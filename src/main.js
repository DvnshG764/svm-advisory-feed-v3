import { logError, logInfo, logWarn } from "./shared/logger.js";
import {
  loadRunControl,
  saveRunControl,
  shouldForceFullScan,
  shouldRunVendor,
  updateRunControlAfterVendorRun
} from "./shared/state.js";

import { runCiscoPipeline } from "./vendors/cisco/cisco-runner.js";

function parseBoolean(value, defaultValue = false) {
  if (value == null || value === "") {
    return defaultValue;
  }

  const normalized = String(value).trim().toLowerCase();

  if (["true", "1", "yes", "y"].includes(normalized)) {
    return true;
  }

  if (["false", "0", "no", "n"].includes(normalized)) {
    return false;
  }

  return defaultValue;
}

function getOnlyVendor() {
  return String(process.env.ONLY_VENDOR || "all").trim().toLowerCase();
}

function isManualWorkflowRun() {
  return String(process.env.GITHUB_EVENT_NAME || "").trim() === "workflow_dispatch";
}

function shouldIncludeVendor(onlyVendor, vendorKey) {
  return onlyVendor === "all" || onlyVendor === vendorKey;
}

async function run() {
  const startedAt = new Date();

  const dryRun = parseBoolean(process.env.DRY_RUN, false);
  const onlyVendor = getOnlyVendor();
  const manualRun = isManualWorkflowRun();

  logInfo("SVM Advisory Feed V3 started", {
    startedAt: startedAt.toISOString(),
    dryRun,
    onlyVendor,
    manualRun,
    githubEventName: process.env.GITHUB_EVENT_NAME || null
  });

  let runControl = await loadRunControl();

  const overallSummary = {
    startedAt: startedAt.toISOString(),
    completedAt: null,
    dryRun,
    onlyVendor,
    manualRun,
    vendors: {},
    skipped: {},
    errors: 0
  };

  if (shouldIncludeVendor(onlyVendor, "cisco")) {
    try {
      const vendorKey = "cisco";

      /*
       * Cisco requirement:
       * The GitHub workflow runs every 10 minutes, and Cisco should run on every scheduled trigger.
       *
       * For manual runs, we also allow Cisco to run immediately for testing.
       *
       * For Palo Alto/Fortinet later, we will use shouldRunVendor() to enforce 30-minute intervals.
       */
      const shouldRunCisco = true;

      if (!shouldRunCisco) {
        logInfo("Skipping Cisco because interval has not elapsed");
        overallSummary.skipped.cisco = "INTERVAL_NOT_ELAPSED";
      } else {
        const forceFullScan = shouldForceFullScan(runControl, vendorKey);

        const ciscoSummary = await runCiscoPipeline({
          dryRun,
          forceFullScan
        });

        overallSummary.vendors.cisco = ciscoSummary;

        if (!dryRun) {
          runControl = updateRunControlAfterVendorRun(
            runControl,
            vendorKey,
            new Date()
          );
        }
      }
    } catch (err) {
      logError("Cisco pipeline failed", err);
      overallSummary.errors++;
    }
  } else {
    logInfo("Cisco not selected by ONLY_VENDOR", {
      onlyVendor
    });
    overallSummary.skipped.cisco = "NOT_SELECTED";
  }

  /*
   * Placeholders for later phases:
   * Palo Alto and Fortinet will use:
   *
   * if (shouldRunVendor(runControl, "paloalto")) { ... }
   * if (shouldRunVendor(runControl, "fortinet")) { ... }
   *
   * This allows one workflow every 10 minutes while Palo/Fortinet run every 30 minutes.
   */
  if (shouldIncludeVendor(onlyVendor, "paloalto")) {
    if (!shouldRunVendor(runControl, "paloalto", new Date()) && !manualRun) {
      overallSummary.skipped.paloalto = "INTERVAL_NOT_ELAPSED";
    } else {
      overallSummary.skipped.paloalto = "NOT_IMPLEMENTED_YET";
      logWarn("Palo Alto pipeline is not implemented yet");
    }
  }

  if (shouldIncludeVendor(onlyVendor, "fortinet")) {
    if (!shouldRunVendor(runControl, "fortinet", new Date()) && !manualRun) {
      overallSummary.skipped.fortinet = "INTERVAL_NOT_ELAPSED";
    } else {
      overallSummary.skipped.fortinet = "NOT_IMPLEMENTED_YET";
      logWarn("Fortinet pipeline is not implemented yet");
    }
  }

  if (!dryRun) {
    await saveRunControl(runControl);
  }

  overallSummary.completedAt = new Date().toISOString();

  logInfo("SVM Advisory Feed V3 completed", overallSummary);

  if (overallSummary.errors > 0) {
    process.exitCode = 1;
  }
}

run().catch((err) => {
  logError("Fatal error in SVM Advisory Feed V3", err);
  process.exitCode = 1;
});
