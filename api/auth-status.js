import { readSignedCookie } from "./_lib/cookies.js";

export default async function handler(req, res) {
  const session = readSignedCookie(req, "discogs_session");
  if (!session) return res.status(200).json({ authenticated: false });
  return res.status(200).json({ authenticated: true, username: session.username });
}
