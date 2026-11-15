const COOKIE_NAME = "v7x_admin_session";

function b64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromB64url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function sign(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return b64url(new Uint8Array(signature));
}

async function validSession(request, secret) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.split(";").map(v => v.trim()).find(v => v.startsWith(COOKIE_NAME + "="));
  if (!match) return false;
  const token = decodeURIComponent(match.slice(COOKIE_NAME.length + 1));
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const expected = await sign(parts[0], secret);
  if (expected !== parts[1]) return false;
  try {
    const data = JSON.parse(new TextDecoder().decode(fromB64url(parts[0])));
    return Number.isFinite(data.exp) && data.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

export async function onRequest({ request, env, next }) {
  const url = new URL(request.url);
  const protectedPage = url.pathname === "/admin/panel.html" || url.pathname.startsWith("/api/admin/");
  const isLogin = url.pathname === "/api/admin/login";
  if (!protectedPage || isLogin) return next();

  if (!env.SESSION_SECRET) {
    return new Response("Admin authentication is not configured.", {
      status: 503, headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  }
  if (await validSession(request, env.SESSION_SECRET)) return next();

  if (url.pathname.startsWith("/api/")) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  return Response.redirect(new URL("/admin/", request.url), 302);
}
