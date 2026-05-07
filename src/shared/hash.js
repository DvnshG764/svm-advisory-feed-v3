import crypto from "node:crypto";

export async function sha1Hex(input) {
  return crypto.createHash("sha1").update(String(input || ""), "utf8").digest("hex");
}
