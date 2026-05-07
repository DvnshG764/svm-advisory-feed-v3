export function decodeHtml(input) {
  return String(input || "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&#x2F;/g, "/");
}

export function stripHtml(input) {
  return decodeHtml(input || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]*>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function extractCves(text) {
  const matches = String(text || "").match(/CVE-\d{4}-\d{4,7}/g) || [];
  return Array.from(new Set(matches));
}

export function valueOrFallback(value, fallback = "Check Manually") {
  if (value == null || value === "") {
    return fallback;
  }

  return String(value);
}

export function normalizeDateToYyyyMmDd(value) {
  if (!value) {
    return null;
  }

  const raw = String(value).trim();

  const isoMatch = raw.match(/\d{4}-\d{2}-\d{2}/);
  if (isoMatch) {
    return isoMatch[0];
  }

  const d = new Date(raw);
  if (!Number.isNaN(d.getTime())) {
    return d.toISOString().slice(0, 10);
  }

  return raw;
}

export function daysSinceIso(isoString) {
  if (!isoString) {
    return Number.POSITIVE_INFINITY;
  }

  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) {
    return Number.POSITIVE_INFINITY;
  }

  const diffMs = Date.now() - d.getTime();
  return diffMs / (1000 * 60 * 60 * 24);
}
