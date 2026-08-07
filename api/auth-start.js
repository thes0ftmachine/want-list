import { getRequestToken, buildAuthorizeUrl } from "./_lib/discogsAuth.js";
import { writeSignedCookie } from "./_lib/cookies.js";

export default async function handler(req, res) {
  const consumerKey = process.env.DISCOGS_CONSUMER_KEY;
  const consumerSecret = process.env.DISCOGS_CONSUMER_SECRET;
  if (!consumerKey || !consumerSecret) {
    return res.status(500).send("Discogs login isn't configured yet — DISCOGS_CONSUMER_KEY / DISCOGS_CONSUMER_SECRET are missing.");
  }

  const proto = req.headers["x-forwarded-proto"] || "https";
  const callbackUrl = `${proto}://${req.headers.host}/api/auth-callback`;

  try {
    const { oauth_token, oauth_token_secret } = await getRequestToken(consumerKey, consumerSecret, callbackUrl);
    // Short-lived — this only needs to survive the round trip to Discogs and back.
    writeSignedCookie(res, "discogs_pending", { token: oauth_token, tokenSecret: oauth_token_secret }, { maxAge: 600 });
    res.writeHead(302, { Location: buildAuthorizeUrl(oauth_token) });
    res.end();
  } catch (e) {
    res.status(502).send(e.message || "Couldn't start Discogs login. Please try again.");
  }
}
