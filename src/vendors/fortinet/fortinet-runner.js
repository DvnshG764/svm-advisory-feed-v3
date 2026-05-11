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
  buildFortinetAdvisoryCandidates,
  extractFortinetFgIdsFromListHtml,
  fetchFortinetListPageHtml
} from "./fortinet-feed.js";
import {
  buildFortinetUnifiedRecord,
  shouldSendFortinetRecord
} from "./fortinet-record.js";
import { scanOrderedCandidates } from "./fortinet-scan.js";
import { buildFortinetDispatchEnvelope } from "./fortinet-card.js";

export async function runFortinetPipeline({
  dryRun = false,
  forceFullScan = false
} = {}) {
  const vendorKey = CONFIG.vendors.fortinet.vendorKey;
  const maxScan = CONFIG.vendors.fortinet.maxRecordsToCheck;

  const summary = {
    vendor: "Fortinet",
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


  let hadFetchFailure = false;
  
  logInfo("Starting Fortinet pipeline", {
    dryRun,
    forceFullScan,
    maxScan
  });

  const vendorTopRecords = await loadVendorTopRecords();

  let processedState = await loadProcessedState(
    CONFIG.vendors.fortinet.processedStatePath
  );

  processedState = pruneProcessedState(
    processedState,
    CONFIG.processedRetentionDays
  );

  const listHtml = await fetchFortinetListPageHtml();
  const fgIds = extractFortinetFgIdsFromListHtml(listHtml).slice(0, maxScan);
  const candidates = await buildFortinetAdvisoryCandidates(fgIds);

  summary.checked = fgIds.length;

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

  logInfo("Fortinet scan result", {
    stopReason: scanResult.stopReason,
    scannedCount: scanResult.scannedCount,
    toProcessCount: scanResult.toProcess.length,
    forceFullScan,
    decisions: scanResult.decisions
  });

  for (const decision of scanResult.toProcess) {
    const fgId = fgIds[decision.index];

    if (!fgId) {
      logWarn("Fortinet FG-IR ID missing for scan decision", {
        decision
      });
      summary.errors++;
      continue;
    }


    if (isProcessed(processedState, fgId)) {
      logInfo("Skipping already processed Fortinet advisory", {
        advisorySlug: fgId
      });
    
      summary.alreadyProcessed++;
      continue;
    }
    
    let record;

    try {
      record = await buildFortinetUnifiedRecord(fgId);
    } catch (err) {
      logError("Failed to build Fortinet unified record", err);
      summary.fetchFailed++;
      hadFetchFailure = true;
      continue;
    }

    if (isProcessed(processedState, record.advisorySlug)) {
      logInfo("Skipping already processed Fortinet advisory", {
        advisorySlug: record.advisorySlug,
        title: record.title
      });
      summary.alreadyProcessed++;
      continue;
    }

    if (!record.cves.length) {
      logInfo("Skipping Fortinet advisory with no CVEs", {
        advisorySlug: record.advisorySlug,
        title: record.title
      });
      summary.skippedNoCves++;
      continue;
    }

    if (!shouldSendFortinetRecord(record)) {
      logInfo("Skipping Fortinet advisory below threshold or missing score", {
        advisorySlug: record.advisorySlug,
        title: record.title,
        finalSelectedScore: record.finalSelectedScore,
        severity: record.severity
      });
      summary.skippedBelowThreshold++;
      continue;
    }

    const envelope = buildFortinetDispatchEnvelope(record);

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
      logInfo("Dry run ready for Fortinet Teams payload", {
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

      logInfo("Sent Fortinet advisory to Teams", {
        advisorySlug: record.advisorySlug,
        title: record.title,
        affectedOs: record.affectedOs,
        severity: record.severity,
        finalSelectedScore: record.finalSelectedScore,
        standardOs: record.standardOs
      });
    } catch (err) {
      logError("Failed to send Fortinet advisory to Teams", err);
      summary.errors++;
    }
  }

  if (!dryRun) {
  await saveProcessedState(
    CONFIG.vendors.fortinet.processedStatePath,
    processedState
  );

  if (candidates.length && !hadFetchFailure) {
    const nextVendorTopRecords = commitTopRecord(
      vendorTopRecords,
      vendorKey,
      candidates[0]
    );

    await saveVendorTopRecords(nextVendorTopRecords);

    logInfo("Committed Fortinet top record", {
      advisoryId: candidates[0].advisoryId,
      fingerprint: candidates[0].fingerprint
    });
  } else if (hadFetchFailure) {
    logWarn("Skipped Fortinet top-record commit because one or more advisory fetches failed", {
      topCandidate: candidates[0] || null,
      fetchFailed: summary.fetchFailed
    });
  }
}

  logInfo("Fortinet pipeline completed", summary);

  return summary;
}
