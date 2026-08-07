import { getAccessToken, getIdentity } from "./_lib/discogsAuth.js";
import { readSignedCookie, writeSignedCookie, clearCookie } from "./_lib/cookies.js";

const SESSION_MAX_AGE = 60 * 60 * 24 * 60; // 60 days — Discogs access tokens don't expire on their own

export default async function handler(req, res) {
  const consumerKey = process.env.DISCOGS_CONSUMER_KEY;
  const consumerSecret = process.env.DISCOGS_CONSUMER_SECRET;
  const { oauth_token: token, oauth_verifier: verifier } = req.query;

  const pending = readSignedCookie(req, "discogs_pending");
  clearCookie(res, "discogs_pending");

  if (!consumerKey || !consumerSecret || !pending || !token || !verifier || pending.token !== token) {
    res.writeHead(302, { Location: "/?login=failed" });
    return res.end();
  }

  try {
    const { oauth_token: accessToken, oauth_token_secret: accessSecret } = await getAccessToken({
      consumerKey,
      consumerSecret,
      token,
      tokenSecret: pending.tokenSecret,
      verifier,
    });
    const identity = await getIdentity({ consumerKey, consumerSecret, token: accessToken, tokenSecret: accessSecret });

    writeSignedCookie(
      res,
      "discogs_session",
      { token: accessToken, tokenSecret: accessSecret, username: identity.username },
      { maxAge: SESSION_MAX_AGE }
    );
    res.writeHead(302, { Location: "/?login=success" });
    res.end();
  } catch (e) {
    res.writeHead(302, { Location: "/?login=failed" });
    res.end();
  }
}
