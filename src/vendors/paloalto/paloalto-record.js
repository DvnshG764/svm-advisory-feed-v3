import { CONFIG } from "../../shared/config.js";
import { fetchTextWithRetry } from "../../shared/fetch.js";
import { sha1Hex } from "../../shared/hash.js";
import { buildNvdLink, fetchNvdScoreWithCache } from "../../shared/nvd.js";
import { extractCves, stripHtml } from "../../shared/text.js";

import {
  advisorySlugFromPaloAltoUrl,
  normalizePaloAltoPubDate
} from "./paloalto-feed.js";
import {
  extractPaloAltoAffectedOsVersions,
  isStandardPaloAltoOs
} from "./paloalto-os.js";

export function extractPaloAltoCvssBt(pageText) {
  const text = String(pageText || "").replace(/\s+/g, " ").trim();

  let match = text.match(/CVSS-BT:\s*([0-9]+(?:\.[0-9]+)?)/i);
  if (match) {
    return Number(match[1]);
  }

  match = text.match(/CVSS-B:\s*([0-9]+(?:\.[0-9]+)?)/i);
  if (match) {
    return Number(match[1]);
  }

  return null;
}

export function extractPaloAltoCvesFromCveSummaryTable(html) {
  const raw = String(html || "");

  const tableMatch =
    raw.match(/<h[1-6][^>]*>\s*CVE(?:\s+and)?\s+Summary\s*<\/h[1-6]>[\s\S]*?<table[\s\S]*?<\/table>/i) ||
    raw.match(/CVE(?:\s+and)?\s+Summary[\s\S]*?<table[\s\S]*?<\/table>/i);

  if (tableMatch) {
    const fromTable = extractCves(stripHtml(tableMatch[0]));

    if (fromTable.length) {
      return fromTable;
    }
  }

  return extractCves(stripHtml(raw));
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

export function shouldSendPaloAltoRecord(record) {
  if (!record) {
    return false;
  }

  if (!record.cves || !record.cves.length) {
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

export async function buildPaloAltoUnifiedRecord(feedItem) {
  const advisorySlug = advisorySlugFromPaloAltoUrl(feedItem.advisoryLink);

  const advisoryPage = await fetchTextWithRetry(feedItem.advisoryLink, 3, 1500);

  if (advisoryPage.status < 200 || advisoryPage.status >= 300) {
    throw new Error(
      `Failed to fetch Palo Alto advisory page ${advisorySlug}. HTTP ${advisoryPage.status}`
    );
  }

  const advisoryHtml = advisoryPage.text;
  const advisoryText = stripHtml(advisoryHtml);

  let cves = [];

  if (feedItem.leadingId && /^CVE-\d{4}-\d{4,7}$/i.test(feedItem.leadingId)) {
    cves = [feedItem.leadingId.toUpperCase()];
  } else if (feedItem.cvesFromFeed && feedItem.cvesFromFeed.length) {
    cves = feedItem.cvesFromFeed;
  } else {
    cves = extractPaloAltoCvesFromCveSummaryTable(advisoryHtml);
  }

  if (!cves.length) {
    cves = extractCves(advisoryText);
  }

  const vendorScore = extractPaloAltoCvssBt(advisoryText);

  let nvdScore = null;

  if (cves.length) {
    nvdScore = await fetchNvdScoreWithCache(cves[0]);
  }

  const finalSelectedScore =
    Math.max(vendorScore || 0, nvdScore || 0) || null;

  const severity = cvssSeverity(finalSelectedScore);

  const affectedOs = extractPaloAltoAffectedOsVersions(advisoryHtml);
  const standardOs = isStandardPaloAltoOs(affectedOs);

  const publishDate = normalizePaloAltoPubDate(feedItem.pubDate);
  const nvdLink = cves.length ? buildNvdLink(cves[0]) : null;

  const fingerprint = await sha1Hex(
    [
      advisorySlug,
      feedItem.cleanedTitle || "",
      cves.join(","),
      String(vendorScore ?? ""),
      String(nvdScore ?? ""),
      affectedOs.join(","),
      publishDate || ""
    ].join("|")
  );

  return {
    vendor: CONFIG.vendors.paloalto.vendorName,
    advisorySlug,

    heading: `New ${CONFIG.vendors.paloalto.vendorName} Advisory!`,
    severityLine:
      finalSelectedScore != null && severity
        ? `${finalSelectedScore} - ${severity}`
        : "Check Manually",
    subheading: standardOs ? "Check for OS Version" : "Send Email",

    title: feedItem.cleanedTitle,
    affectedOs,
    cves,

    vendorCvssV3Score: vendorScore,
    nvdCvssV3Score: nvdScore,
    finalSelectedScore,
    severity,

    standardOs,
    vendorLink: feedItem.advisoryLink,
    nvdLink,
    publishDate,

    leadingId: feedItem.leadingId || null,
    fingerprint
  };
}
