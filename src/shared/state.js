import fs from "node:fs/promises";
import path from "node:path";

import { CONFIG } from "./config.js";
import { daysSinceIso } from "./text.js";
import { logInfo, logWarn } from "./logger.js";

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

export async function loadJson(filePath, fallbackValue) {
  if (!(await fileExists(filePath))) {
    return structuredClone(fallbackValue);
  }

  const raw = await fs.readFile(filePath, "utf8");

  if (!raw.trim()) {
    return structuredClone(fallbackValue);
  }

  return JSON.parse(raw);
}

export async function saveJson(filePath, value) {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });

  const formatted = `${JSON.stringify(value, null, 2)}\n`;
  await fs.writeFile(filePath, formatted, "utf8");
}

export function getDefaultVendorTopRecords() {
  return {
    cisco: {
      vendor: "cisco",
      advisoryId: null,
      fingerprint: null,
      publishedAt: null,
      updatedAt: null,
      processedAt: null
    },
    paloalto: {
      vendor: "paloalto",
      advisoryId: null,
      fingerprint: null,
      publishedAt: null,
      updatedAt: null,
      processedAt: null
    },
    fortinet: {
      vendor: "fortinet",
      advisoryId: null,
      fingerprint: null,
      publishedAt: null,
      updatedAt: null,
      processedAt: null
    }
  };
}

export function getDefaultRunControl() {
  return {
    lastRun: {
      cisco: null,
      paloalto: null,
      fortinet: null
    },
    intervalMinutes: {
      cisco: 10,
      paloalto: 30,
      fortinet: 30
    },
    runCounters: {
      cisco: 0,
      paloalto: 0,
      fortinet: 0
    },
    forceFullScanEveryRuns: {
      cisco: 6,
      paloalto: 4,
      fortinet: 4
    }
  };
}

export function getDefaultProcessedState() {
  return {
    items: {}
  };
}

export async function loadVendorTopRecords() {
  const state = await loadJson(CONFIG.paths.vendorTopRecords, getDefaultVendorTopRecords());

  const defaults = getDefaultVendorTopRecords();

  return {
    ...defaults,
    ...state,
    cisco: {
      ...defaults.cisco,
      ...(state.cisco || {})
    },
    paloalto: {
      ...defaults.paloalto,
      ...(state.paloalto || {})
    },
    fortinet: {
      ...defaults.fortinet,
      ...(state.fortinet || {})
    }
  };
}

export async function saveVendorTopRecords(state) {
  await saveJson(CONFIG.paths.vendorTopRecords, state);
}

export async function loadRunControl() {
  const state = await loadJson(CONFIG.paths.runControl, getDefaultRunControl());

  const defaults = getDefaultRunControl();

  return {
    ...defaults,
    ...state,
    lastRun: {
      ...defaults.lastRun,
      ...(state.lastRun || {})
    },
    intervalMinutes: {
      ...defaults.intervalMinutes,
      ...(state.intervalMinutes || {})
    },
    runCounters: {
      ...defaults.runCounters,
      ...(state.runCounters || {})
    },
    forceFullScanEveryRuns: {
      ...defaults.forceFullScanEveryRuns,
      ...(state.forceFullScanEveryRuns || {})
    }
  };
}

export async function saveRunControl(state) {
  await saveJson(CONFIG.paths.runControl, state);
}

export async function loadProcessedState(filePath) {
  const state = await loadJson(filePath, getDefaultProcessedState());

  return {
    items: state.items || {}
  };
}

export async function saveProcessedState(filePath, state) {
  await saveJson(filePath, {
    items: state.items || {}
  });
}

export function pruneProcessedState(processedState, retentionDays = CONFIG.processedRetentionDays) {
  const items = processedState.items || {};
  let deleted = 0;

  for (const [key, meta] of Object.entries(items)) {
    if (daysSinceIso(meta?.processedAt) > retentionDays) {
      delete items[key];
      deleted++;
    }
  }

  if (deleted > 0) {
    logInfo("Pruned old processed advisory records", {
      deleted,
      retentionDays
    });
  }

  return {
    items
  };
}

export function isProcessed(processedState, advisorySlug) {
  if (!advisorySlug) {
    return false;
  }

  return Boolean(processedState.items?.[advisorySlug]);
}

export function markProcessed(processedState, record) {
  if (!record?.advisorySlug) {
    logWarn("Cannot mark processed because advisorySlug is missing");
    return processedState;
  }

  const next = {
    items: {
      ...(processedState.items || {})
    }
  };

  next.items[record.advisorySlug] = {
    advisorySlug: record.advisorySlug,
    processedAt: new Date().toISOString(),
    cves: record.cves || [],
    finalSelectedScore: record.finalSelectedScore ?? null
  };

  return next;
}

export function shouldRunVendor(runControl, vendorKey, now = new Date()) {
  const lastRunRaw = runControl.lastRun?.[vendorKey];
  const intervalMinutes = Number(runControl.intervalMinutes?.[vendorKey] || 0);

  if (!intervalMinutes) {
    return true;
  }

  if (!lastRunRaw) {
    return true;
  }

  const lastRun = new Date(lastRunRaw);
  if (Number.isNaN(lastRun.getTime())) {
    return true;
  }

  const diffMinutes = (now.getTime() - lastRun.getTime()) / (1000 * 60);

  return diffMinutes >= intervalMinutes;
}

export function updateRunControlAfterVendorRun(runControl, vendorKey, now = new Date()) {
  const next = structuredClone(runControl);

  next.lastRun[vendorKey] = now.toISOString();
  next.runCounters[vendorKey] = Number(next.runCounters?.[vendorKey] || 0) + 1;

  return next;
}

export function shouldForceFullScan(runControl, vendorKey) {
  const counter = Number(runControl.runCounters?.[vendorKey] || 0);
  const everyRuns = Number(runControl.forceFullScanEveryRuns?.[vendorKey] || 0);

  if (!everyRuns) {
    return false;
  }

  const nextRunNumber = counter + 1;

  return nextRunNumber % everyRuns === 0;
}

export function commitTopRecord(vendorTopRecords, vendorKey, topCandidate) {
  const next = structuredClone(vendorTopRecords);

  next[vendorKey] = {
    vendor: vendorKey,
    advisoryId: topCandidate?.advisoryId || null,
    fingerprint: topCandidate?.fingerprint || null,
    publishedAt: topCandidate?.publishedAt || null,
    updatedAt: topCandidate?.updatedAt || null,
    processedAt: new Date().toISOString()
  };

  return next;
}
