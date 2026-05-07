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
  buildCiscoAdvisoryCandidates,
  extractCiscoFeedItems,
  fetchCiscoFeedXml
} from "./cisco-feed.js";
import {
  buildCiscoUnifiedRecord,
  shouldSendCiscoRecord
} from "./cisco-record.js";
import { scanOrderedCandidates } from "./cisco-scan.js";
import { buildCiscoDispatchEnvelope } from "./cisco-card.js";

export async function runCiscoPipeline({
  dryRun = false,
  forceFullScan = false
} = {}) {
  const vendorKey = CONFIG.vendors.cisco.vendorKey;
  const maxScan = CONFIG.vendors.cisco.maxRecordsToCheck;

  const summary = {
    vendor: "Cisco",
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

  logInfo("Starting Cisco pipeline", {
    dryRun,
    forceFullScan,
    maxScan
  });

  const vendorTopRecords = await loadVendorTopRecords();

  let processedState = await loadProcessedState(
    CONFIG.vendors.cisco.processedStatePath
  );

  processedState = pruneProcessedState(
    processedState,
    CONFIG.processedRetentionDays
  );

  const feedXml = await fetchCiscoFeedXml();
  const feedItems = extractCiscoFeedItems(feedXml).slice(0, maxScan);
  const candidates = await buildCiscoAdvisoryCandidates(feedItems);

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

  logInfo("Cisco scan result", {
    stopReason: scanResult.stopReason,
    scannedCount: scanResult.scannedCount,
    toProcessCount: scanResult.toProcess.length,
    forceFullScan,
    decisions: scanResult.decisions
  });

  for (const decision of scanResult.toProcess) {
    const feedItem = feedItems[decision.index];

    if (!feedItem) {
      logWarn("Cisco feed item missing for scan decision", {
        decision
      });
      summary.errors++;
      continue;
    }

    let record;

    try {
      record = await buildCiscoUnifiedRecord(feedItem);
    } catch (err) {
      logError("Failed to build Cisco unified record", err);
      summary.fetchFailed++;
      continue;
    }

    if (isProcessed(processedState, record.advisorySlug)) {
      logInfo("Skipping already processed Cisco advisory", {
        advisorySlug: record.advisorySlug,
        title: record.title
      });
      summary.alreadyProcessed++;
      continue;
    }

    if (!record.cves.length) {
      logInfo("Skipping Cisco advisory with no CVEs", {
        advisorySlug: record.advisorySlug,
        title: record.title
      });
      summary.skippedNoCves++;
      continue;
    }

    if (!shouldSendCiscoRecord(record)) {
      logInfo("Skipping Cisco advisory below threshold or missing score", {
        advisorySlug: record.advisorySlug,
        title: record.title,
        finalSelectedScore: record.finalSelectedScore,
        severity: record.severity
      });
      summary.skippedBelowThreshold++;
      continue;
    }

    const envelope = buildCiscoDispatchEnvelope(record);

    summary.messages.push({
      advisorySlug: envelope.advisorySlug,
      dedupKey: envelope.dedupKey,
      severity: envelope.severity,
      finalSelectedScore: envelope.finalSelectedScore,
      title: envelope.title,
      cves: envelope.cves,
      standardOs: envelope.standardOs,
      vendorLink: envelope.vendorLink,
      nvdLink: envelope.nvdLink
    });

    if (dryRun) {
      logInfo("Dry run ready for Cisco Teams payload", {
        advisorySlug: envelope.advisorySlug,
        title: envelope.title,
        severity: envelope.severity,
        finalSelectedScore: envelope.finalSelectedScore
      });

      summary.dryRunReady++;
      continue;
    }

    try {
      await sendTeamsPayload(envelope.teamsPayload);

      processedState = markProcessed(processedState, record);

      summary.queued++;
      summary.sent++;

      logInfo("Sent Cisco advisory to Teams", {
        advisorySlug: record.advisorySlug,
        title: record.title,
        severity: record.severity,
        finalSelectedScore: record.finalSelectedScore
      });
    } catch (err) {
      logError("Failed to send Cisco advisory to Teams", err);
      summary.errors++;
    }
  }

  if (!dryRun) {
    await saveProcessedState(
      CONFIG.vendors.cisco.processedStatePath,
      processedState
    );

    if (candidates.length) {
      const nextVendorTopRecords = commitTopRecord(
        vendorTopRecords,
        vendorKey,
        candidates[0]
      );

      await saveVendorTopRecords(nextVendorTopRecords);

      logInfo("Committed Cisco top record", {
        advisoryId: candidates[0].advisoryId,
        fingerprint: candidates[0].fingerprint
      });
    }
  }

  logInfo("Cisco pipeline completed", summary);

  return summary;
}
