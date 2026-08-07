import { clearCookie } from "./_lib/cookies.js";

export default async function handler(req, res) {
  clearCookie(res, "discogs_session");
  return res.status(200).json({ ok: true });
}
