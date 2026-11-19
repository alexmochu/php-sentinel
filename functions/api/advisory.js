// GET /api/advisory -> the patch data the checker uses, so the page never hardcodes versions.
import { json } from "../_lib/http.js";
import { ADVISORY } from "../_lib/patch-data.js";

export async function onRequestGet() {
  return json(ADVISORY, 200, { "Cache-Control": "public, max-age=300" });
}
