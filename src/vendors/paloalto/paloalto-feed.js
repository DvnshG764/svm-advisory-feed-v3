import { XMLParser } from "fast-xml-parser";

import { CONFIG } from "../../shared/config.js";
import { fetchTextWithRetry } from "../../shared/fetch.js";
import { sha1Hex } from "../../shared/hash.js";
import {
  extractCves,
  normalizeDateToYyyyMmDd,
  stripHtml
} from "../../shared/text.js";

function arrayify(input) {
  if (input == null) {
    return [];
  }

  return Array.isArray(input) ? input : [input];
}

export async function fetchPaloAltoFeedXml() {
  const response = await fetchTextWithRetry(
    CONFIG.vendors.paloalto.feedUrl,
    3,
    1500
  );

  if (response.status < 200 || response.status >= 300) {
    throw new Error(`Failed to fetch Palo Alto RSS feed. HTTP ${response.status}`);
  }

  return response.text;
}

export function advisorySlugFromPaloAltoUrl(url) {
  const cleaned = String(url || "").split("?")[0].replace(/\/+$/, "");
  const match = cleaned.match(/\/([^/]+)$/);
  return match ? match[1] : cleaned;
}

export function normalizePaloAltoPubDate(pubDate) {
  return normalizeDateToYyyyMmDd(pubDate);
}

/*
 * Extracts the leading identifier only for:
 * - CVE extraction when the title starts with a CVE
 * - title cleanup
 *
 * This value is NOT used for severity/filtering decisions.
 */
export function extractPaloAltoLeadingId(rawTitle) {
  if (!rawTitle) {
    return null;
  }

  const match = String(rawTitle).match(
    /^\s*((?:PAN-SA-\d{4}-\d{4})|(?:CVE-\d{4}-\d{4,7}))\b/i
  );

  return match ? match[1].trim() : null;
}

/*
 * Cleans Palo Alto title by removing:
 * 1. leading CVE/PAN-SA identifier
 * 2. trailing "(Severity: ...)" suffix
 *
 * The severity text is deliberately NOT returned or used anywhere.
 */
export function normalizePaloAltoTitle(rawTitle) {
  if (!rawTitle) {
    return null;
  }

  let title = String(rawTitle).trim();

  title = title.replace(
    /^\s*(?:PAN-SA-\d{4}-\d{4}|CVE-\d{4}-\d{4,7})\s*/i,
    ""
  );

  title = title.replace(
    /\s*\(\s*Severity:\s*[^)]+\s*\)\s*$/i,
    ""
  );

  return title.trim();
}

function getPaloAltoAdvisoryLink(feedLink, guid) {
  if (guid && /^https?:\/\//i.test(guid)) {
    return guid;
  }

  if (feedLink && /^https?:\/\//i.test(feedLink)) {
    return feedLink;
  }

  return guid || feedLink;
}

function readTextNode(value) {
  if (value == null) {
    return "";
  }

  if (typeof value === "string") {
    return value;
  }

  if (typeof value === "number") {
    return String(value);
  }

  if (typeof value === "object" && value["#text"] != null) {
    return String(value["#text"]);
  }

  return String(value || "");
}

export function extractPaloAltoFeedItems(xmlText) {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@_",
    textNodeName: "#text",
    trimValues: true,
    processEntities: false
  });

  const parsed = parser.parse(xmlText);

  let rawItems = [];

  if (parsed?.rss?.channel?.item) {
    rawItems = arrayify(parsed.rss.channel.item);
  } else if (parsed?.feed?.entry) {
    rawItems = arrayify(parsed.feed.entry);
  }

  const out = [];

  for (
    const item of rawItems
  ) {
    if (out.length >= CONFIG.vendors.paloalto.maxRecordsToCheck) {
      break;
    }

    const rawTitle = readTextNode(item?.title).trim();

    const link =
      typeof item?.link === "string"
        ? item.link
        : item?.link?.href || item?.link?.["@_href"] || readTextNode(item?.link);

    const guid = readTextNode(item?.guid).trim();

    const description = readTextNode(
      item?.description || item?.summary || ""
    ).trim();

    const pubDate =
      readTextNode(
        item?.pubDate ||
          item?.published ||
          item?.updated ||
          ""
      ).trim() || null;

    if (!rawTitle) {
      continue;
    }

    const advisoryLink = getPaloAltoAdvisoryLink(link, guid);

    if (!advisoryLink) {
      continue;
    }

    const leadingId = extractPaloAltoLeadingId(rawTitle);
    const cleanedTitle = normalizePaloAltoTitle(rawTitle);

    let cvesFromFeed = [];

    if (leadingId && /^CVE-\d{4}-\d{4,7}$/i.test(leadingId)) {
      cvesFromFeed = [leadingId.toUpperCase()];
    } else {
      const combined = stripHtml(`${description} ${rawTitle}`);
      cvesFromFeed = extractCves(combined);
    }

    out.push({
      rawTitle,
      cleanedTitle,
      leadingId,
      advisoryLink,
      link,
      guid,
      description: description || "",
      pubDate,
      cvesFromFeed
    });
  }

  return out;
}

export async function buildPaloAltoFeedFingerprint(item) {
  return sha1Hex(
    [
      item.rawTitle || "",
      item.cleanedTitle || "",
      item.advisoryLink || "",
      item.pubDate || "",
      item.cvesFromFeed.join(",")
    ].join("|")
  );
}

export async function buildPaloAltoAdvisoryCandidates(feedItems) {
  const candidates = [];

  for (const item of feedItems) {
    const advisoryId = advisorySlugFromPaloAltoUrl(item.advisoryLink);
    const fingerprint = await buildPaloAltoFeedFingerprint(item);
    const normalizedDate = normalizePaloAltoPubDate(item.pubDate);

    candidates.push({
      advisoryId,
      fingerprint,
      publishedAt: normalizedDate,
      updatedAt: normalizedDate
    });
  }

  return candidates;
}
