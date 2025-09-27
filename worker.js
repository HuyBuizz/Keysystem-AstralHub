// ACC Key API - 3 lockers + Turnstile + lazy-bind + renew + session
// Rewrite: signed &data, idempotent mark, no-store, KV retries, better errors

const CORS = {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "*",
};
const NO_STORE = { "cache-control": "no-store, max-age=0, must-revalidate" };

const json = (o, s = 200, extra = {}) =>
    new Response(JSON.stringify(o), {
        status: s,
        headers: { "content-type": "application/json", ...CORS, ...NO_STORE, ...extra },
    });

const txt = (t, s = 200, extra = {}) =>
    new Response(t, {
        status: s,
        headers: { "content-type": "text/plain; charset=utf-8", ...CORS, ...NO_STORE, ...extra },
    });

const rand = (n) => {
    const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghijkmnpqrstuvwxy";
    const b = new Uint32Array(n);
    crypto.getRandomValues(b);
    let r = "";
    for (let i = 0; i < n; i++) r += a[b[i] % a.length];
    return r;
};

async function kvGetRetry(ns, key, tries = 3) {
    for (let i = 0; i < tries; i++) {
        try { return await ns.get(key); } catch { }
    }
    return null;
}
async function kvPutRetry(ns, key, val, opts, tries = 3) {
    for (let i = 0; i < tries; i++) {
        try { await ns.put(key, val, opts); return true; } catch { }
    }
    return false;
}
function safeJSON(s, fallback = null) { try { return JSON.parse(s); } catch { return fallback; } }

const enc = new TextEncoder();

// ----- HMAC + b64url cho `&data=` -----
function b64urlFromJSON(obj) {
    const s = JSON.stringify(obj);
    return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function jsonFromB64url(s) {
    const raw = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
    const txt = decodeURIComponent(escape(raw));
    return JSON.parse(txt);
}
async function hmacHex(secret, message) {
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
    return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function packData(secret, flow, ttlMs = 15 * 60 * 1000) {
    const exp = Date.now() + ttlMs;
    const toSign = `${flow}.${exp}`;
    const sig = await hmacHex(secret, toSign);
    return b64urlFromJSON({ flow, exp, sig });
}
async function verifyData(secret, data, expectFlow) {
    if (!data) return { ok: false, reason: "NO_DATA" };
    let obj;
    try { obj = jsonFromB64url(data); } catch { return { ok: false, reason: "BAD_DATA" }; }
    const { flow, exp, sig } = obj || {};
    if (!flow || !exp || !sig) return { ok: false, reason: "BAD_DATA" };
    if (expectFlow && flow !== expectFlow) return { ok: false, reason: "FLOW_MISMATCH" };
    if (Date.now() > Number(exp)) return { ok: false, reason: "DATA_EXPIRED" };
    const want = await hmacHex(secret, `${flow}.${exp}`);
    if (want !== sig) return { ok: false, reason: "SIG_INVALID" };
    return { ok: true, flow };
}

export default {
    async fetch(req, env) {
        if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...CORS } });

        const url = new URL(req.url);
        const path = url.pathname;
        const ip = req.headers.get("CF-Connecting-IP") || "0.0.0.0";
        const ua = req.headers.get("User-Agent") || "";

        async function rateLimit(bucket, limit, winSec) {
            const k = `rl:${bucket}:${ip}`;
            const cur = parseInt((await env.RL.get(k)) || "0", 10);
            if (cur >= limit) return false;
            await env.RL.put(k, String(cur + 1), { expirationTtl: winSec });
            return true;
        }
        async function verifyTurnstile(tok) {
            try {
                if (!tok) return false;
                const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
                    method: "POST",
                    headers: { "content-type": "application/x-www-form-urlencoded" },
                    body: new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: tok }),
                });
                const d = await r.json();
                return !!d.success;
            } catch { return false; }
        }

        // ---- health ----
        if (path === "/health") return json({ ok: true });

        // ================== FLOW ==================
        // start -> tạo flow + trả &data ký số để gắn vào link locker
        if (path === "/flow/start" && req.method === "POST") {
            if (!(await rateLimit("flowstart", 60, 3600))) return json({ ok: false, reason: "RATE" }, 429);
            const flow = rand(16);
            const data = { step: 0, ver: 1, createdAt: Date.now(), ip, ua };
            const ok = await kvPutRetry(env.FLOWS, `flow:${flow}`, JSON.stringify(data), { expirationTtl: 3600 });
            if (!ok) return json({ ok: false, reason: "KV_WRITE" }, 503);

            const dataParam = await packData(env.SIGNING_SECRET || "dev-secret", flow, 15 * 60 * 1000);
            return json({ ok: true, flow, step: 0, data: dataParam });
        }

        // ping: refresh TTL (optional)
        if (path === "/flow/ping" && req.method === "POST") {
            const { flow } = await req.json().catch(() => ({}));
            if (!flow) return json({ ok: false, reason: "MISSING" }, 400);
            const s = await kvGetRetry(env.FLOWS, `flow:${flow}`);
            if (!s) return json({ ok: false, reason: "NO_FLOW" }, 404);
            const d = safeJSON(s, null);
            if (!d) return json({ ok: false, reason: "CORRUPT" }, 500);
            d.ver = (d.ver || 1) + 1; d.ip = ip; d.ua = ua;
            const ok = await kvPutRetry(env.FLOWS, `flow:${flow}`, JSON.stringify(d), { expirationTtl: 3600 });
            if (!ok) return json({ ok: false, reason: "KV_WRITE" }, 503);
            return json({ ok: true, step: d.step, ver: d.ver });
        }

        // state
        if (path === "/flow/state" && req.method === "GET") {
            const flow = url.searchParams.get("flow");
            if (!flow) return json({ ok: false, reason: "MISSING" }, 400);
            const s = await kvGetRetry(env.FLOWS, `flow:${flow}`);
            if (!s) return json({ ok: false, reason: "NO_FLOW" }, 404);
            const d = safeJSON(s, null);
            if (!d) return json({ ok: false, reason: "CORRUPT" }, 500);
            d.ver = (d.ver || 1) + 1;
            await kvPutRetry(env.FLOWS, `flow:${flow}`, JSON.stringify(d), { expirationTtl: 3600 });
            return json({ ok: true, step: d.step, ver: d.ver, createdAt: d.createdAt });
        }

        // mark – idempotent + (optional) verify signed data
        if (path === "/flow/mark" && req.method === "POST") {
            const body = await req.json().catch(() => ({}));
            const flow = body.flow;
            const i = parseInt(body.i || "0", 10);
            const dataParam = body.data; // optional
            if (!flow || !(i >= 0)) return json({ ok: false, reason: "MISSING" }, 400);

            // nếu có data => xác thực chặt chẽ
            if (dataParam) {
                const vr = await verifyData(env.SIGNING_SECRET || "dev-secret", dataParam, flow);
                if (!vr.ok) return json({ ok: false, reason: `DATA_${vr.reason}` }, 400);
            }

            const s = await kvGetRetry(env.FLOWS, `flow:${flow}`);
            if (!s) return json({ ok: false, reason: "NO_FLOW" }, 404);

            const d = safeJSON(s, null);
            if (!d) return json({ ok: false, reason: "CORRUPT" }, 500);

            // cập nhật footprint
            if (d.ip !== ip || d.ua !== ua) { d.ip = ip; d.ua = ua; }

            // Idempotent nâng step
            if (i === d.step + 1) {
                d.step = i;
            } else if (i <= d.step) {
                // đã đánh dấu rồi -> OK hiện trạng
            } else {
                return json({ ok: false, reason: "OUT_OF_ORDER", step: d.step }, 409);
            }
            d.ver = (d.ver || 1) + 1;

            const ok = await kvPutRetry(env.FLOWS, `flow:${flow}`, JSON.stringify(d), { expirationTtl: 3600 });
            if (!ok) return json({ ok: false, reason: "KV_WRITE" }, 503);
            return json({ ok: true, step: d.step, ver: d.ver });
        }

        // ================== ISSUE KEY (after C3 + Turnstile) ==================
        if (path === "/issue-by-flow" && req.method === "POST") {
            if (!(await rateLimit("issue", 30, 60))) return json({ ok: false, reason: "RATE" }, 429);
            const { flow, cfTurnstileToken } = await req.json().catch(() => ({}));
            if (!flow) return json({ ok: false, reason: "MISSING" }, 400);

            const s = await kvGetRetry(env.FLOWS, `flow:${flow}`);
            if (!s) return json({ ok: false, reason: "NO_FLOW" }, 404);
            const d = safeJSON(s, null);
            if (!d) return json({ ok: false, reason: "CORRUPT" }, 500);
            if (d.step < 2) return json({ ok: false, reason: "NOT_DONE" }, 400);

            const tsOk = await verifyTurnstile(cfTurnstileToken);
            if (!tsOk) return json({ ok: false, reason: "TURNSTILE" }, 403);

            const key = rand(24);
            const ttl = 24 * 3600;
            const expiresAt = Date.now() + ttl * 1000;

            const w1 = await kvPutRetry(env.KEYS, `key:${key}`, "UNBOUND", { expirationTtl: ttl });
            const w2 = await kvPutRetry(env.KEYS, `meta:${key}`, JSON.stringify({ expiresAt }), { expirationTtl: ttl });
            if (!w1 || !w2) return json({ ok: false, reason: "KV_WRITE" }, 503);

            return json({ ok: true, key, ttlSec: ttl, expiresAt });
        }

        // ================== RENEW ==================
        if (path === "/renew-by-flow" && req.method === "POST") {
            if (!(await rateLimit("renew", 20, 60))) return json({ ok: false, reason: "RATE" }, 429);
            const { flow, cfTurnstileToken, key, hwid } = await req.json().catch(() => ({}));
            if (!flow || !key || !hwid) return json({ ok: false, reason: "MISSING" }, 400);

            const s = await kvGetRetry(env.FLOWS, `flow:${flow}`);
            if (!s) return json({ ok: false, reason: "NO_FLOW" }, 404);
            const d = safeJSON(s, null);
            if (!d) return json({ ok: false, reason: "CORRUPT" }, 500);
            if (d.step < 2) return json({ ok: false, reason: "NOT_DONE" }, 400);

            const tsOk = await verifyTurnstile(cfTurnstileToken);
            if (!tsOk) return json({ ok: false, reason: "TURNSTILE" }, 403);

            const mapped = await kvGetRetry(env.KEYS, `key:${key}`);
            if (!mapped || mapped !== hwid) return json({ ok: false, reason: "MISMATCH_OR_EXPIRED" }, 400);

            const metaStr = await kvGetRetry(env.KEYS, `meta:${key}`);
            if (!metaStr) return json({ ok: false, reason: "MISSING_META" }, 400);
            const meta = safeJSON(metaStr, null);
            if (!meta) return json({ ok: false, reason: "CORRUPT_META" }, 500);

            const add = 24 * 3600;
            const newExpiresAt = Math.max(Date.now(), meta.expiresAt) + add * 1000;
            const newTTL = Math.max(1, Math.floor((newExpiresAt - Date.now()) / 1000));

            const w1 = await kvPutRetry(env.KEYS, `key:${key}`, hwid, { expirationTtl: newTTL });
            const w2 = await kvPutRetry(env.KEYS, `hwid:${hwid}`, key, { expirationTtl: newTTL });
            const w3 = await kvPutRetry(env.KEYS, `meta:${key}`, JSON.stringify({ expiresAt: newExpiresAt }), { expirationTtl: newTTL });
            if (!w1 || !w2 || !w3) return json({ ok: false, reason: "KV_WRITE" }, 503);

            return json({ ok: true, expiresAt: newExpiresAt, ttlSec: newTTL });
        }

        // ================== VERIFY (lazy-bind 1 lần) ==================
        if (path === "/verify" && req.method === "GET") {
            if (!(await rateLimit("verify", 120, 60))) return json({ ok: false, reason: "RATE" }, 429);
            const hwid = url.searchParams.get("hwid");
            const key = url.searchParams.get("key");
            if (!hwid || !key) return json({ ok: false, reason: "MISSING" }, 400);

            let current = await kvGetRetry(env.KEYS, `key:${key}`);
            if (!current) return json({ ok: false, reason: "NOT_FOUND_OR_EXPIRED" });

            const metaStr = await kvGetRetry(env.KEYS, `meta:${key}`);
            if (!metaStr) return json({ ok: false, reason: "NOT_FOUND_OR_EXPIRED" });
            const { expiresAt } = safeJSON(metaStr, { expiresAt: 0 });
            const left = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
            if (left <= 0) return json({ ok: false, reason: "NOT_FOUND_OR_EXPIRED" });

            if (current === "UNBOUND") {
                const w1 = await kvPutRetry(env.KEYS, `key:${key}`, hwid, { expirationTtl: left });
                const w2 = await kvPutRetry(env.KEYS, `hwid:${hwid}`, key, { expirationTtl: left });
                if (!w1 || !w2) return json({ ok: false, reason: "KV_WRITE" }, 503);
            } else if (current !== hwid) {
                return json({ ok: false, reason: "MISMATCH" }, 403);
            }

            const session = rand(32);
            const ok = await kvPutRetry(env.KEYS, `sess:${session}`, hwid, { expirationTtl: 300 });
            if (!ok) return json({ ok: false, reason: "KV_WRITE" }, 503);

            return json({ ok: true, session, expiresIn: left });
        }

        // ================== SCRIPT (via session) ==================
        if (path === "/script" && req.method === "GET") {
            const s = url.searchParams.get("session");
            const hwid = s && (await kvGetRetry(env.KEYS, `sess:${s}`));
            if (!hwid) return txt("forbidden", 403);
            await env.KEYS.delete(`sess:${s}`); // one-shot

            const lua = `-- Astral Hub (verified for HWID: ${hwid})
print("AstralHub verified:", "${hwid}")
-- your real payload here ...
`;
            return txt(lua, 200);
        }

        if (path === "/") return txt("ACC Key API OK");
        return txt("Not found", 404);
    },
};
// EOF