import { CONFIG } from "../../shared/config.js";
import { fetchTextWithRetry } from "../../shared/fetch.js";
import { sha1Hex } from "../../shared/hash.js";
import { stripHtml } from "../../shared/text.js";

export async function fetchFortinetListPageHtml() {
  const response = await fetchTextWithRetry(
    CONFIG.vendors.fortinet.feedUrl,
    5,
    2000
  );

  if (response.status < 200 || response.status >= 300) {
    throw new Error(`Failed to fetch Fortinet PSIRT list page. HTTP ${response.status}`);
  }

  return response.text;
}

export function extractFortinetFgIdsFromListHtml(html) {
  const text = stripHtml(html);
  const matches = text.match(/FG-IR-\d{2}-\d{3,4}/g) || [];

  return Array.from(new Set(matches)).slice(
    0,
    CONFIG.vendors.fortinet.maxRecordsToCheck
  );
}

export function buildFortinetAdvisoryUrl(fgId) {
  return `https://www.fortiguard.com/psirt/${encodeURIComponent(fgId)}`;
}

export async function buildFortinetFeedFingerprint(fgId) {
  return sha1Hex(
    [
      fgId,
      buildFortinetAdvisoryUrl(fgId)
    ].join("|")
  );
}

export async function buildFortinetAdvisoryCandidates(fgIds) {
  const candidates = [];

  for (const fgId of fgIds) {
    const fingerprint = await buildFortinetFeedFingerprint(fgId);

    candidates.push({
      advisoryId: fgId,
      fingerprint,
      publishedAt: null,
      updatedAt: null
    });
  }

  return candidates;
}
