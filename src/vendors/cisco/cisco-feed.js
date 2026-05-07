import { XMLParser } from "fast-xml-parser";

import { CONFIG } from "../../shared/config.js";
import { fetchTextWithRetry } from "../../shared/fetch.js";
import { sha1Hex } from "../../shared/hash.js";
import { extractCves, normalizeDateToYyyyMmDd, stripHtml } from "../../shared/text.js";

function arrayify(input) {
  if (input == null) {
    return [];
  }

  return Array.isArray(input) ? input : [input];
}

export async function fetchCiscoFeedXml() {
  const response = await fetchTextWithRetry(CONFIG.vendors.cisco.feedUrl, 3, 1500);

  if (response.status < 200 || response.status >= 300) {
    throw new Error(`Failed to fetch Cisco RSS feed. HTTP ${response.status}`);
  }

  return response.text;
}

export function advisorySlugFromUrl(url) {
  const cleaned = String(url || "").split("?")[0].replace(/\/+$/, "");
  const match = cleaned.match(/\/([^/]+)$/);
  return match ? match[1] : cleaned;
}

export function normalizeCiscoPubDate(pubDate) {
  return normalizeDateToYyyyMmDd(pubDate);
}

export function extractCiscoFeedItems(xmlText) {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@_",
    textNodeName: "#text",
    trimValues: true
  });

  const parsed = parser.parse(xmlText);

  let rawItems = [];

  if (parsed?.rss?.channel?.item) {
    rawItems = arrayify(parsed.rss.channel.item);
  } else if (parsed?.feed?.entry) {
    rawItems = arrayify(parsed.feed.entry);
  }

  const out = [];

  for (const item of rawItems.slice(0, CONFIG.vendors.cisco.maxRecordsToCheck)) {
    const title = String(item?.title?.["#text"] || item?.title || "").trim();

    const linkRaw =
      typeof item?.link === "string"
        ? item.link
        : item?.link?.href || item?.link?.["@_href"] || "";

    const guid = String(item?.guid?.["#text"] || item?.guid || "").trim();

    const description = String(
      item?.description?.["#text"] ||
        item?.description ||
        item?.summary?.["#text"] ||
        item?.summary ||
        ""
    ).trim();

    const pubDate =
      String(
        item?.pubDate?.["#text"] ||
          item?.pubDate ||
          item?.published?.["#text"] ||
          item?.published ||
          item?.updated?.["#text"] ||
          item?.updated ||
          ""
      ).trim() || null;

    if (!title) {
      continue;
    }

    const advisoryLink =
      /^https?:\/\//i.test(guid)
        ? guid
        : /^https?:\/\//i.test(linkRaw)
          ? linkRaw
          : guid || linkRaw;

    if (!advisoryLink) {
      continue;
    }

    const combined = stripHtml(`${description} ${title}`);
    const cvesFromFeed = extractCves(combined);

    out.push({
      title,
      advisoryLink,
      pubDate,
      cvesFromFeed
    });
  }

  return out;
}

export async function buildCiscoFeedFingerprint(item) {
  return sha1Hex(
    [
      item.title,
      item.advisoryLink,
      item.pubDate || "",
      item.cvesFromFeed.join(",")
    ].join("|")
  );
}

export async function buildCiscoAdvisoryCandidates(feedItems) {
  const candidates = [];

  for (const item of feedItems) {
    const advisoryId = advisorySlugFromUrl(item.advisoryLink);
    const fingerprint = await buildCiscoFeedFingerprint(item);
    const normalizedDate = normalizeCiscoPubDate(item.pubDate);

    candidates.push({
      advisoryId,
      fingerprint,
      publishedAt: normalizedDate,
      updatedAt: normalizedDate
    });
  }

  return candidates;
}
