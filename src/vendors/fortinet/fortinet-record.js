import { CONFIG } from "../../shared/config.js";
import { fetchTextWithRetry } from "../../shared/fetch.js";
import { sha1Hex } from "../../shared/hash.js";
import { buildNvdLink, fetchNvdScoreWithCache } from "../../shared/nvd.js";
import { extractCves, stripHtml } from "../../shared/text.js";

import { buildFortinetAdvisoryUrl } from "./fortinet-feed.js";

const STANDARD_OS_PATTERNS = [
  /^FortiOS\b/i
];

export function extractFortinetTitle(html, fgId) {
  const raw = String(html || "");

  const h1Match = raw.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i);
  if (h1Match) {
    return stripHtml(h1Match[1]).replace(/\|.*$/, "").trim();
  }

  const titleMatch = raw.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (titleMatch) {
    return stripHtml(titleMatch[1]).replace(/\|.*$/, "").trim();
  }

  return fgId;
}

export function extractFortinetVendorCvss(text) {
  const match = String(text || "").match(/CVSSv3\s*Score[:\s]*([0-9]+(?:\.[0-9]+)?)/i);
  return match ? Number(match[1]) : null;
}

export function extractFortinetAffectedOsVersions(html) {
  const raw = String(html || "");

  const tableMatch = raw.match(
    /<table[^>]*>[\s\S]*?<thead>[\s\S]*?(Version|Affected)[\s\S]*?<\/thead>[\s\S]*?<tbody>[\s\S]*?<\/tbody>[\s\S]*?<\/table>/i
  );

  if (!tableMatch) {
    return ["Check Manually"];
  }

  const rows = tableMatch[0].match(/<tr[\s\S]*?<\/tr>/gi) || [];
  const out = [];

  for (const row of rows) {
    const tds = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)];

    if (tds.length < 2) {
      continue;
    }

    const versionText = stripHtml(tds[0][1]);
    const statusText = stripHtml(tds[1][1]);

    if (!versionText) {
      continue;
    }

    if (/not affected/i.test(statusText)) {
      continue;
    }

    if (!out.includes(versionText)) {
      out.push(versionText);
    }
  }

  return out.length ? out : ["Check Manually"];
}

export function isStandardFortinetOs(osList) {
  return osList.some((os) =>
    STANDARD_OS_PATTERNS.some((pattern) => pattern.test(os))
  );
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

export function shouldSendFortinetRecord(record) {
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

export async function buildFortinetUnifiedRecord(fgId) {
  const advisoryLink = buildFortinetAdvisoryUrl(fgId);

  const advisoryPage = await fetchTextWithRetry(advisoryLink, 5, 1500);

  if (advisoryPage.status < 200 || advisoryPage.status >= 300) {
    throw new Error(
      `Failed to fetch Fortinet advisory page ${fgId}. HTTP ${advisoryPage.status}`
    );
  }

  const advisoryHtml = advisoryPage.text;
  const advisoryText = stripHtml(advisoryHtml);

  const cves = extractCves(advisoryText);
  const vendorScore = extractFortinetVendorCvss(advisoryText);

  let nvdScore = null;

  if (cves.length) {
    nvdScore = await fetchNvdScoreWithCache(cves[0]);
  }

  const finalSelectedScore =
    Math.max(vendorScore || 0, nvdScore || 0) || null;

  const severity = cvssSeverity(finalSelectedScore);

  const affectedOs = extractFortinetAffectedOsVersions(advisoryHtml);
  const standardOs = isStandardFortinetOs(affectedOs);

  const nvdLink = cves.length ? buildNvdLink(cves[0]) : null;

  const title = extractFortinetTitle(advisoryHtml, fgId);

  const fingerprint = await sha1Hex(
    [
      fgId,
      title || "",
      cves.join(","),
      String(vendorScore ?? ""),
      String(nvdScore ?? ""),
      affectedOs.join(",")
    ].join("|")
  );

  return {
    vendor: CONFIG.vendors.fortinet.vendorName,
    fgId,
    advisorySlug: fgId,

    heading: `New ${CONFIG.vendors.fortinet.vendorName} Advisory!`,
    severityLine:
      finalSelectedScore != null && severity
        ? `${finalSelectedScore} - ${severity}`
        : "Check Manually",
    subheading: standardOs ? "Check for OS Version" : "Send Email",

    title,
    affectedOs,
    cves,

    vendorCvssV3Score: vendorScore,
    nvdCvssV3Score: nvdScore,
    finalSelectedScore,
    severity,

    standardOs,
    vendorLink: advisoryLink,
    nvdLink,
    publishDate: null,

    fingerprint
  };
}
