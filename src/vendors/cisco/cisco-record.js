import { fetchTextWithRetry } from "../../shared/fetch.js";
import { sha1Hex } from "../../shared/hash.js";
import { decodeHtml, extractCves, stripHtml } from "../../shared/text.js";

import {
  advisorySlugFromUrl,
  normalizeCiscoPubDate
} from "./cisco-feed.js";
import {
  buildNvdLink,
  fetchNvdScoreWithCache
} from "./cisco-nvd.js";
import {
  detectCiscoOsList,
  isStandardCiscoOs
} from "./cisco-os.js";

export function extractCiscoCvssBase(html) {
  const raw = decodeHtml(html || "");
  const text = stripHtml(raw);

  const match =
    raw.match(/CVSS[\s\S]{0,400}?Base\s*Score[:\s]*([0-9]+(?:\.[0-9]+)?)/i) ||
    raw.match(/CVSS[\s\S]{0,400}?Base[:\s]*([0-9]+(?:\.[0-9]+)?)/i) ||
    text.match(/CVSS\s*v3\.1\s*Base\s*Score[:\s]*([0-9]+(?:\.[0-9]+)?)/i) ||
    text.match(/CVSS\s*v3\.x\s*Base\s*Score[:\s]*([0-9]+(?:\.[0-9]+)?)/i) ||
    text.match(/CVSS\s*Base\s*Score[:\s]*([0-9]+(?:\.[0-9]+)?)/i) ||
    text.match(/\bBase\s*Score[:\s]*([0-9]+(?:\.[0-9]+)?)/i) ||
    text.match(/\bBase[:\s]*([0-9]+(?:\.[0-9]+)?)/i);

  return match ? Number(match[1]) : null;
}

export function cvssSeverity(score) {
  if (score == null) {
    return null;
  }

  if (score >= 9.0) {
    return "Critical";
  }

  if (score >= 7.0) {
    return "High";
  }

  return null;
}

export function shouldSendCiscoRecord(record) {
  if (!record.cves.length) {
    return false;
  }

  if (record.finalSelectedScore == null) {
    return false;
  }

  if (!record.severity) {
    return false;
  }

  return true;
}

export async function buildCiscoUnifiedRecord(feedItem) {
  const advisorySlug = advisorySlugFromUrl(feedItem.advisoryLink);

  const advisoryPage = await fetchTextWithRetry(feedItem.advisoryLink, 3, 1500);

  if (advisoryPage.status < 200 || advisoryPage.status >= 300) {
    throw new Error(
      `Failed to fetch Cisco advisory page ${advisorySlug}. HTTP ${advisoryPage.status}`
    );
  }

  const advisoryHtml = advisoryPage.text;
  const advisoryText = stripHtml(advisoryHtml);

  const cves = feedItem.cvesFromFeed.length
    ? feedItem.cvesFromFeed
    : extractCves(advisoryText);

  const vendorScore = extractCiscoCvssBase(advisoryHtml);

  let nvdScore = null;
  let nvdScoreSource = "none";

  if (cves.length) {
    const nvdResult = await fetchNvdScoreWithCache(cves[0]);
    nvdScore = nvdResult.score;
    nvdScoreSource = nvdResult.source;
  }

  const finalSelectedScore =
    Math.max(vendorScore || 0, nvdScore || 0) || null;

  const severity = cvssSeverity(finalSelectedScore);

  const affectedOs = detectCiscoOsList(feedItem.title);
  const standardOs = isStandardCiscoOs(affectedOs);

  const publishDate = normalizeCiscoPubDate(feedItem.pubDate);
  const nvdLink = cves.length ? buildNvdLink(cves[0]) : null;

  const fingerprint = await sha1Hex(
    [
      advisorySlug,
      feedItem.title,
      cves.join(","),
      String(vendorScore ?? ""),
      String(nvdScore ?? ""),
      affectedOs.join(","),
      publishDate || ""
    ].join("|")
  );

  return {
    vendor: "Cisco",
    advisorySlug,

    heading: "New Cisco Advisory!",
    severityLine:
      finalSelectedScore != null && severity
        ? `${finalSelectedScore} - ${severity}`
        : "Check Manually",
    subheading: standardOs ? "Check for OS Version" : "Send Email",

    title: feedItem.title,
    affectedOs,
    cves,

    vendorCvssV3Score: vendorScore,
    nvdCvssV3Score: nvdScore,
    nvdScoreSource,
    finalSelectedScore,
    severity,

    standardOs,
    vendorLink: feedItem.advisoryLink,
    nvdLink,
    publishDate,

    fingerprint
  };
}
