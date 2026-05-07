import { CONFIG } from "../../shared/config.js";
import { fetchJsonWithRetry, sleepMs } from "../../shared/fetch.js";
import { logInfo, logWarn } from "../../shared/logger.js";

const nvdMemoryCache = new Map();

export function buildNvdApiUrl(cve) {
  return CONFIG.nvd.apiBaseUrl + encodeURIComponent(cve);
}

export function buildNvdLink(cve) {
  return cve ? `https://nvd.nist.gov/vuln/detail/${cve}` : null;
}

function pickPreferredCvss(metricArray) {
  if (!Array.isArray(metricArray)) {
    return null;
  }

  const nistMetric = metricArray.find((metric) => {
    const source = metric?.source ? String(metric.source).toLowerCase() : "";
    return source.includes("nist") && metric?.cvssData?.baseScore != null;
  });

  if (nistMetric) {
    return Number(nistMetric.cvssData.baseScore);
  }

  const firstMetric = metricArray.find(
    (metric) => metric?.cvssData?.baseScore != null
  );

  return firstMetric ? Number(firstMetric.cvssData.baseScore) : null;
}

export function extractNvdPreferredScore(json) {
  const metrics = json?.vulnerabilities?.[0]?.cve?.metrics;

  if (!metrics) {
    return null;
  }

  const v31Score = pickPreferredCvss(metrics.cvssMetricV31);
  if (v31Score != null) {
    return v31Score;
  }

  const v30Score = pickPreferredCvss(metrics.cvssMetricV30);
  if (v30Score != null) {
    return v30Score;
  }

  const v40Score = pickPreferredCvss(metrics.cvssMetricV40);
  if (v40Score != null) {
    return v40Score;
  }

  return null;
}

export function extractNvdPreferredScoreSource(json) {
  const metrics = json?.vulnerabilities?.[0]?.cve?.metrics;

  if (!metrics) {
    return "none";
  }

  if (pickPreferredCvss(metrics.cvssMetricV31) != null) {
    return "CVSS v3.1";
  }

  if (pickPreferredCvss(metrics.cvssMetricV30) != null) {
    return "CVSS v3.0";
  }

  if (pickPreferredCvss(metrics.cvssMetricV40) != null) {
    return "CVSS v4.0";
  }

  return "none";
}

export async function fetchNvdScoreWithCache(cve) {
  if (!cve) {
    return {
      score: null,
      source: "none"
    };
  }

  const cached = nvdMemoryCache.get(cve);

  if (cached) {
    return cached;
  }

  const url = buildNvdApiUrl(cve);

  logInfo("Fetching NVD score", {
    cve
  });

  const response = await fetchJsonWithRetry(url, 3, 1500);

  if (response.status < 200 || response.status >= 300 || !response.json) {
    logWarn("NVD fetch failed or returned non-OK response", {
      cve,
      status: response.status
    });

    return {
      score: null,
      source: "none"
    };
  }

  const score = extractNvdPreferredScore(response.json);
  const source = extractNvdPreferredScoreSource(response.json);

  const result = {
    score,
    source
  };

  nvdMemoryCache.set(cve, result);

  await sleepMs(CONFIG.nvd.delayMsNoKey);

  return result;
}
