import crypto from "crypto";

// No database in this app — Discogs is the account store. These cookies just carry the
// (signed, tamper-proof, httpOnly) access token between requests, the way a session table
// would elsewhere. SESSION_SECRET is the only thing keeping a person from forging one.

function getSecret() {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error("SESSION_SECRET is not configured.");
  return secret;
}

export function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(value);
  });
  return out;
}

export function readSignedCookie(req, name) {
  const raw = parseCookies(req)[name];
  if (!raw) return null;
  const dot = raw.lastIndexOf(".");
  if (dot === -1) return null;
  const payload = raw.slice(0, dot);
  const signature = raw.slice(dot + 1);
  let expected;
  try {
    expected = crypto.createHmac("sha256", getSecret()).update(payload).digest("base64url");
  } catch {
    return null;
  }
  // Constant-time compare so a mismatched signature can't leak timing information.
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

export function writeSignedCookie(res, name, data, { maxAge } = {}) {
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
  const signature = crypto.createHmac("sha256", getSecret()).update(payload).digest("base64url");
  const value = `${payload}.${signature}`;
  const attrs = [`${name}=${encodeURIComponent(value)}`, "Path=/", "HttpOnly", "Secure", "SameSite=Lax"];
  if (maxAge != null) attrs.push(`Max-Age=${maxAge}`);
  appendSetCookie(res, attrs.join("; "));
}

export function clearCookie(res, name) {
  appendSetCookie(res, `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
}

// Multiple cookies can be set on one response (e.g. clearing the pending cookie while
// writing the session cookie) — Set-Cookie needs one header value per cookie, not a
// comma-joined string, so this keeps appending rather than overwriting.
function appendSetCookie(res, cookieString) {
  const existing = res.getHeader("Set-Cookie");
  if (!existing) {
    res.setHeader("Set-Cookie", cookieString);
  } else if (Array.isArray(existing)) {
    res.setHeader("Set-Cookie", [...existing, cookieString]);
  } else {
    res.setHeader("Set-Cookie", [existing, cookieString]);
  }
}
