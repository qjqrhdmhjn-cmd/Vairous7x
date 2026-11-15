const COOKIE_NAME = "v7x_admin_session";

function b64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sign(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return b64url(new Uint8Array(signature));
}

function constantTimeEqual(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  let diff = x.length ^ y.length;
  const length = Math.max(x.length, y.length);
  for (let i = 0; i < length; i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

export async function onRequestPost({ request, env }) {
  if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET || env.SESSION_SECRET.length < 32) {
    return Response.json({ error: "إعدادات تسجيل الدخول غير مكتملة على Cloudflare." }, { status: 503 });
  }
  let body;
  try { body = await request.json(); } catch {
    return Response.json({ error: "طلب غير صالح." }, { status: 400 });
  }
  const password = typeof body.password === "string" ? body.password : "";
  if (!constantTimeEqual(password, env.ADMIN_PASSWORD)) {
    return Response.json({ error: "كلمة المرور غير صحيحة." }, { status: 401 });
  }

  const exp = Math.floor(Date.now() / 1000) + 8 * 60 * 60;
  const payload = b64url(new TextEncoder().encode(JSON.stringify({ exp })));
  const token = payload + "." + await sign(payload, env.SESSION_SECRET);
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": COOKIE_NAME + "=" + encodeURIComponent(token) + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800"
    }
  });
}
