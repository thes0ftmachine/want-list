import crypto from "crypto";

const REQUEST_TOKEN_URL = "https://api.discogs.com/oauth/request_token";
const AUTHORIZE_URL = "https://www.discogs.com/oauth/authorize";
const ACCESS_TOKEN_URL = "https://api.discogs.com/oauth/access_token";
const IDENTITY_URL = "https://api.discogs.com/oauth/identity";
const USER_AGENT = "RandomDiscovery/1.0";

// Discogs uses OAuth 1.0a rather than OAuth 2 — every request needs to be individually
// signed with HMAC-SHA1 rather than just carrying a bearer token. This file is a small,
// dependency-free implementation of just the pieces Discogs' API actually needs.

function percentEncode(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

// Per the OAuth 1.0a spec, the signature covers the HTTP method, the base URL (no query
// string), and every param — both the oauth_* params and any query-string params on the
// URL — normalized and sorted together.
function buildBaseString(method, url, oauthParams) {
  const parsed = new URL(url);
  const allParams = { ...oauthParams };
  parsed.searchParams.forEach((value, key) => {
    allParams[key] = value;
  });
  const encodedParamString = Object.keys(allParams)
    .sort()
    .map((key) => `${percentEncode(key)}=${percentEncode(allParams[key])}`)
    .join("&");
  return `${method.toUpperCase()}&${percentEncode(parsed.origin + parsed.pathname)}&${percentEncode(encodedParamString)}`;
}

function sign(baseString, consumerSecret, tokenSecret = "") {
  const signingKey = `${percentEncode(consumerSecret)}&${percentEncode(tokenSecret)}`;
  return crypto.createHmac("sha1", signingKey).update(baseString).digest("base64");
}

export function buildOAuthHeader({ method, url, consumerKey, consumerSecret, token, tokenSecret, extraOAuthParams = {} }) {
  const oauthParams = {
    oauth_consumer_key: consumerKey,
    oauth_nonce: crypto.randomBytes(16).toString("hex"),
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: String(Math.floor(Date.now() / 1000)),
    oauth_version: "1.0",
    ...(token ? { oauth_token: token } : {}),
    ...extraOAuthParams,
  };
  const baseString = buildBaseString(method, url, oauthParams);
  oauthParams.oauth_signature = sign(baseString, consumerSecret, tokenSecret);
  return (
    "OAuth " +
    Object.keys(oauthParams)
      .sort()
      .map((key) => `${percentEncode(key)}="${percentEncode(oauthParams[key])}"`)
      .join(", ")
  );
}

function parseFormEncoded(text) {
  const out = {};
  new URLSearchParams(text).forEach((value, key) => {
    out[key] = value;
  });
  return out;
}

// Step 1 of 3: ask Discogs for a short-lived request token, tied to our callback URL.
export async function getRequestToken(consumerKey, consumerSecret, callbackUrl) {
  const header = buildOAuthHeader({
    method: "POST",
    url: REQUEST_TOKEN_URL,
    consumerKey,
    consumerSecret,
    extraOAuthParams: { oauth_callback: callbackUrl },
  });
  const res = await fetch(REQUEST_TOKEN_URL, {
    method: "POST",
    headers: { Authorization: header, "User-Agent": USER_AGENT },
  });
  const body = await res.text();
  if (!res.ok) throw new Error("Discogs rejected the login request. Please try again.");
  return parseFormEncoded(body); // { oauth_token, oauth_token_secret, oauth_callback_confirmed }
}

// Step 2 of 3: send the person here to approve access.
export function buildAuthorizeUrl(requestToken) {
  return `${AUTHORIZE_URL}?oauth_token=${encodeURIComponent(requestToken)}`;
}

// Step 3 of 3: exchange the approved request token + verifier for a permanent access token.
export async function getAccessToken({ consumerKey, consumerSecret, token, tokenSecret, verifier }) {
  const header = buildOAuthHeader({
    method: "POST",
    url: ACCESS_TOKEN_URL,
    consumerKey,
    consumerSecret,
    token,
    tokenSecret,
    extraOAuthParams: { oauth_verifier: verifier },
  });
  const res = await fetch(ACCESS_TOKEN_URL, {
    method: "POST",
    headers: { Authorization: header, "User-Agent": USER_AGENT },
  });
  const body = await res.text();
  if (!res.ok) throw new Error("Discogs rejected the access-token exchange.");
  return parseFormEncoded(body); // { oauth_token, oauth_token_secret }
}

// Confirms who we actually just logged in as (Discogs' access-token response doesn't
// include a username, only opaque tokens).
export async function getIdentity({ consumerKey, consumerSecret, token, tokenSecret }) {
  const header = buildOAuthHeader({ method: "GET", url: IDENTITY_URL, consumerKey, consumerSecret, token, tokenSecret });
  const res = await fetch(IDENTITY_URL, { headers: { Authorization: header, "User-Agent": USER_AGENT } });
  if (!res.ok) throw new Error("Couldn't confirm the logged-in Discogs identity.");
  return res.json(); // { id, username, resource_url, consumer_name }
}

// Used by api/discogs.js to sign ordinary authenticated API calls (e.g. fetching the
// logged-in user's own collection) once we already hold their access token.
export function signedRequestHeader({ method, url, consumerKey, consumerSecret, token, tokenSecret }) {
  return buildOAuthHeader({ method, url, consumerKey, consumerSecret, token, tokenSecret });
}
