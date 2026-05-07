function timestamp() {
  return new Date().toISOString();
}

export function logInfo(message, data = null) {
  if (data == null) {
    console.log(`[INFO] ${timestamp()} ${message}`);
    return;
  }

  console.log(`[INFO] ${timestamp()} ${message}`, JSON.stringify(data, null, 2));
}

export function logWarn(message, data = null) {
  if (data == null) {
    console.warn(`[WARN] ${timestamp()} ${message}`);
    return;
  }

  console.warn(`[WARN] ${timestamp()} ${message}`, JSON.stringify(data, null, 2));
}

export function logError(message, error = null) {
  if (error == null) {
    console.error(`[ERROR] ${timestamp()} ${message}`);
    return;
  }

  const safeError = {
    name: error?.name,
    message: error?.message,
    stack: error?.stack
  };

  console.error(`[ERROR] ${timestamp()} ${message}`, JSON.stringify(safeError, null, 2));
}
