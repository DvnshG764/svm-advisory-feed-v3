import { CONFIG } from "../../shared/config.js";
import { logError, logInfo, logWarn } from "../../shared/logger.js";
import { sendTeamsPayload } from "../../shared/teams.js";
import {
  commitTopRecord,
  isProcessed,
  loadProcessedState,
  loadVendorTopRecords,
  markProcessed,
  pruneProcessedState,
  saveProcessedState,
  saveVendorTopRecords
} from "../../shared/state.js";

import {
  buildPaloAltoAdvisoryCandidates,
  extractPaloAltoFeedItems,
  fetchPaloAltoFeedXml
} from "./paloalto-feed.js";
import {
  buildPaloAltoUnifiedRecord,
  shouldSendPaloAltoRecord
} from "./paloalto-record.js";
import { scanOrderedCandidates } from "./paloalto-scan.js";
import { buildPaloAltoDispatchEnvelope } from "./paloalto-card.js";

export async function runPaloAltoPipeline({
  dryRun = false,
  forceFullScan = false
} = {}) {
  const vendorKey = CONFIG.vendors.paloalto.vendorKey;
  const maxScan = CONFIG.vendors.paloalto.maxRecordsToCheck;

  const summary = {
    vendor: "Palo Alto",
    checked: 0,
    scanned: 0,
    queued: 0,
    sent: 0,
    alreadyProcessed: 0,
    skippedNoCves: 0,
    skippedBelowThreshold: 0,
    fetchFailed: 0,
    dryRunReady: 0,
    errors: 0,
    stopReason: null,
    forceFullScan,
    messages: []
  };

  logInfo("Starting Palo Alto pipeline", {
    dryRun,
    forceFullScan,
    maxScan
  });

  const vendorTopRecords = await loadVendorTopRecords();

  let processedState = await loadProcessedState(
    CONFIG.vendors.paloalto.processedStatePath
  );

  processedState = pruneProcessedState(
    processedState,
    CONFIG.processedRetentionDays
  );

  const feedXml = await fetchPaloAltoFeedXml();
  const feedItems = extractPaloAltoFeedItems(feedXml).slice(0, maxScan);
  const candidates = await buildPaloAltoAdvisoryCandidates(feedItems);

  summary.checked = feedItems.length;

  const storedTopRecord = vendorTopRecords[vendorKey];

  const scanResult = scanOrderedCandidates({
    vendor: vendorKey,
    candidates,
    maxScan,
    storedTopRecord,
    forceFullScan
  });

  summary.scanned = scanResult.scannedCount;
  summary.stopReason = scanResult.stopReason;

  logInfo("Palo Alto scan result", {
    stopReason: scanResult.stopReason,
    scannedCount: scanResult.scannedCount,
    toProcessCount: scanResult.toProcess.length,
    forceFullScan,
    decisions: scanResult.decisions
  });

  for (const decision of scanResult.toProcess) {
    const feedItem = feedItems[decision.index];

    if (!feedItem) {
      logWarn("Palo Alto feed item missing for scan decision", {
        decision
      });
      summary.errors++;
      continue;
    }

    let record;

    try {
      record = await buildPaloAltoUnifiedRecord(feedItem);
    } catch (err) {
      logError("Failed to build Palo Alto unified record", err);
      summary.fetchFailed++;
      continue;
    }

    if (isProcessed(processedState, record.advisorySlug)) {
      logInfo("Skipping already processed Palo Alto advisory", {
        advisorySlug: record.advisorySlug,
        title: record.title
      });
      summary.alreadyProcessed++;
      continue;
    }

    if (!record.cves.length) {
      logInfo("Skipping Palo Alto advisory with no CVEs", {
        advisorySlug: record.advisorySlug,
        title: record.title
      });
      summary.skippedNoCves++;
      continue;
    }

    if (!shouldSendPaloAltoRecord(record)) {
      logInfo("Skipping Palo Alto advisory below threshold or missing score", {
        advisorySlug: record.advisorySlug,
        title: record.title,
        finalSelectedScore: record.finalSelectedScore,
        severity: record.severity
      });
      summary.skippedBelowThreshold++;
      continue;
    }

    const envelope = buildPaloAltoDispatchEnvelope(record);

    summary.messages.push({
      advisorySlug: envelope.advisorySlug,
      dedupKey: envelope.dedupKey,
      severity: envelope.severity,
      finalSelectedScore: envelope.finalSelectedScore,
      title: envelope.title,
      affectedOs: envelope.affectedOs,
      cves: envelope.cves,
      standardOs: envelope.standardOs,
      vendorLink: envelope.vendorLink,
      nvdLink: envelope.nvdLink
    });

    if (dryRun) {
      logInfo("Dry run ready for Palo Alto Teams payload", {
        advisorySlug: envelope.advisorySlug,
        title: envelope.title,
        affectedOs: envelope.affectedOs,
        severity: envelope.severity,
        finalSelectedScore: envelope.finalSelectedScore,
        standardOs: envelope.standardOs
      });

      summary.dryRunReady++;
      continue;
    }

    try {
      await sendTeamsPayload(envelope.teamsPayload);

      processedState = markProcessed(processedState, record);

      summary.queued++;
      summary.sent++;

      logInfo("Sent Palo Alto advisory to Teams", {
        advisorySlug: record.advisorySlug,
        title: record.title,
        affectedOs: record.affectedOs,
        severity: record.severity,
        finalSelectedScore: record.finalSelectedScore,
        standardOs: record.standardOs
      });
    } catch (err) {
      logError("Failed to send Palo Alto advisory to Teams", err);
      summary.errors++;
    }
  }

  if (!dryRun) {
    await saveProcessedState(
      CONFIG.vendors.paloalto.processedStatePath,
      processedState
    );

    if (candidates.length) {
      const nextVendorTopRecords = commitTopRecord(
        vendorTopRecords,
        vendorKey,
        candidates[0]
      );

      await saveVendorTopRecords(nextVendorTopRecords);

      logInfo("Committed Palo Alto top record", {
        advisoryId: candidates[0].advisoryId,
        fingerprint: candidates[0].fingerprint
      });
    }
  }

  logInfo("Palo Alto pipeline completed", summary);

  return summary;
}
