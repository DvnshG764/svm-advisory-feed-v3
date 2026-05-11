import { logError, logInfo, logWarn } from "./shared/logger.js";
import {
  loadRunControl,
  saveRunControl,
  shouldForceFullScan,
  shouldRunVendor,
  updateRunControlAfterVendorRun
} from "./shared/state.js";

import { runCiscoPipeline } from "./vendors/cisco/cisco-runner.js";
import { runPaloAltoPipeline } from "./vendors/paloalto/paloalto-runner.js";
import { runFortinetPipeline } from "./vendors/fortinet/fortinet-runner.js";

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

async function runCisco({
  dryRun,
  runControl,
  overallSummary
}) {
  const vendorKey = "cisco";

  /*
   * Cisco requirement:
   * Cisco runs every external cron trigger.
   *
   * Current cron-job.org interval = 15 minutes.
   * Therefore Cisco currently runs every 15 minutes.
   */
  const forceFullScan = shouldForceFullScan(runControl, vendorKey);

  const ciscoSummary = await runCiscoPipeline({
    dryRun,
    forceFullScan
  });

  overallSummary.vendors.cisco = ciscoSummary;

  if (!dryRun) {
    return updateRunControlAfterVendorRun(
      runControl,
      vendorKey,
      new Date()
    );
  }

  return runControl;
}
//-------------------------

async function runFortinet({
  dryRun,
  runControl,
  overallSummary,
  manualRun,
  onlyVendor
}) {
  const vendorKey = "fortinet";

  const vendorSpecificManualRun = manualRun && onlyVendor === vendorKey;

  const shouldRunFortinet =
    vendorSpecificManualRun || shouldRunVendor(runControl, vendorKey, new Date());

  if (!shouldRunFortinet) {
    logInfo("Skipping Fortinet because interval has not elapsed", {
      vendorKey,
      intervalMinutes: runControl.intervalMinutes?.[vendorKey],
      lastRun: runControl.lastRun?.[vendorKey] || null
    });

    overallSummary.skipped.fortinet = "INTERVAL_NOT_ELAPSED";
    return runControl;
  }

  const forceFullScan = shouldForceFullScan(runControl, vendorKey);

  const fortinetSummary = await runFortinetPipeline({
    dryRun,
    forceFullScan
  });

  overallSummary.vendors.fortinet = fortinetSummary;

  if (!dryRun) {
    return updateRunControlAfterVendorRun(
      runControl,
      vendorKey,
      new Date()
    );
  }

  return runControl;
}
//------------------------

async function runPaloAlto({
  dryRun,
  runControl,
  overallSummary,
  manualRun,
  onlyVendor
}) {
  const vendorKey = "paloalto";

  /*
   * Palo Alto requirement:
   * Palo Alto should run every 30 minutes.
   *
   * Since cron-job.org triggers every 15 minutes, Palo Alto will run roughly
   * every second GitHub Actions run.
   *
   * Manual vendor-specific runs should execute immediately for testing.
   */
  const vendorSpecificManualRun = manualRun && onlyVendor === vendorKey;

  const shouldRunPaloAlto =
    vendorSpecificManualRun || shouldRunVendor(runControl, vendorKey, new Date());

  if (!shouldRunPaloAlto) {
    logInfo("Skipping Palo Alto because interval has not elapsed", {
      vendorKey,
      intervalMinutes: runControl.intervalMinutes?.[vendorKey],
      lastRun: runControl.lastRun?.[vendorKey] || null
    });

    overallSummary.skipped.paloalto = "INTERVAL_NOT_ELAPSED";
    return runControl;
  }

  const forceFullScan = shouldForceFullScan(runControl, vendorKey);

  const paloAltoSummary = await runPaloAltoPipeline({
    dryRun,
    forceFullScan
  });

  overallSummary.vendors.paloalto = paloAltoSummary;

  if (!dryRun) {
    return updateRunControlAfterVendorRun(
      runControl,
      vendorKey,
      new Date()
    );
  }

  return runControl;
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
      runControl = await runCisco({
        dryRun,
        runControl,
        overallSummary
      });
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

  if (shouldIncludeVendor(onlyVendor, "paloalto")) {
    try {
      runControl = await runPaloAlto({
        dryRun,
        runControl,
        overallSummary,
        manualRun,
        onlyVendor
      });
    } catch (err) {
      logError("Palo Alto pipeline failed", err);
      overallSummary.errors++;
    }
  } else {
    logInfo("Palo Alto not selected by ONLY_VENDOR", {
      onlyVendor
    });
    overallSummary.skipped.paloalto = "NOT_SELECTED";
  }

  if (shouldIncludeVendor(onlyVendor, "fortinet")) {
    try {
      runControl = await runFortinet({
        dryRun,
        runControl,
        overallSummary,
        manualRun,
        onlyVendor
      });
    } catch (err) {
      logError("Fortinet pipeline failed", err);
      overallSummary.errors++;
    }
  } else {
    logInfo("Fortinet not selected by ONLY_VENDOR", {
      onlyVendor
    });
    overallSummary.skipped.fortinet = "NOT_SELECTED";
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
