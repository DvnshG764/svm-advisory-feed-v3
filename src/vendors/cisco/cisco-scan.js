export function compareIncomingTopRecord(stored, advisoryId, fingerprint) {
stored.advisoryId === advisoryId && stored.fingerprint !== fingerprint) {  if (!stored?.advisoryId || !stored?.fingerprint) {
    return "UPDATED";
  }

  return "NEW";
}

export function scanOrderedCandidates({
  vendor,
  candidates,
  maxScan,
  storedTopRecord,
  forceFullScan = false
}) {
  const bounded = candidates.slice(0, maxScan);
  const decisions = [];
  const toProcess = [];

  for (let i = 0; i < bounded.length; i++) {
    const item = bounded[i];

    const status = compareIncomingTopRecord(
      storedTopRecord,
      item.advisoryId,
      item.fingerprint
    );

    const decision = {
      index: i,
      advisoryId: item.advisoryId,
      status
    };

    decisions.push(decision);

    if (status === "KNOWN" && !forceFullScan) {
      return {
        vendor,
        maxScan,
        scannedCount: decisions.length,
        stopReason: "KNOWN_FOUND",
        stopIndex: i,
        forceFullScan,
        toProcess,
        decisions
      };
    }

    if (status === "NEW" || status === "UPDATED" || forceFullScan) {
      toProcess.push(decision);
    }
  }

  if (forceFullScan) {
    return {
      vendor,
      maxScan,
      scannedCount: decisions.length,
      stopReason: "FORCED_FULL_SCAN_COMPLETED",
      stopIndex: null,
      forceFullScan,
      toProcess,
      decisions
    };
  }

  if (bounded.length === maxScan && candidates.length > maxScan) {
    return {
      vendor,
      maxScan,
      scannedCount: decisions.length,
      stopReason: "MAX_REACHED",
      stopIndex: null,
      forceFullScan,
      toProcess,
      decisions
    };
  }

  return {
    vendor,
    maxScan,
    scannedCount: decisions.length,
    stopReason: "END_OF_LIST",
    stopIndex: null,
    forceFullScan,
    toProcess,
    decisions
  };
}

    return "NEW";
  }

  if (stored.advisoryId === advisoryId && stored.fingerprint === fingerprint) {
    return "KNOWN";
  }

