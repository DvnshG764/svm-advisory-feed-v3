import { stripHtml } from "../../shared/text.js";

const STANDARD_OS_PATTERNS = [
  /^PAN-OS\b/i
];

export function isStandardPaloAltoOs(osList) {
  return osList.some((os) =>
    STANDARD_OS_PATTERNS.some((pattern) => pattern.test(os))
  );
}

export function extractPaloAltoAffectedOsVersions(html) {
  const raw = String(html || "");

  const tableMatch =
    raw.match(/<h[1-6][^>]*>\s*Product Status\s*<\/h[1-6]>[\s\S]*?<table[\s\S]*?<\/table>/i) ||
    raw.match(/Product Status[\s\S]*?<table[\s\S]*?<\/table>/i);

  if (!tableMatch) {
    return ["Check Manually"];
  }

  const rows = tableMatch[0].match(/<tr[\s\S]*?<\/tr>/gi) || [];
  const out = [];

  for (const row of rows) {
    if (/<th/i.test(row)) {
      continue;
    }

    const tds = row.match(/<td[^>]*>[\s\S]*?<\/td>/gi) || [];

    if (tds.length < 2) {
      continue;
    }

    const versionText = stripHtml(tds[0]);
    const affectedText = stripHtml(tds[1]);

    if (!versionText) {
      continue;
    }

    if (/^none$/i.test(affectedText)) {
      continue;
    }

    if (!out.includes(versionText)) {
      out.push(versionText);
    }
  }

  return out.length ? out : ["Check Manually"];
}
