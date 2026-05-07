import { logWarn } from "./logger.js";

export function sleepMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function fetchTextWithRetry(url, maxAttempts = 3, baseWaitMs = 1500) {
  let lastStatus = 0;
  let lastText = "";
  let lastError = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const response = await fetch(url, {
        headers: {
          Accept: "*/*",
          "User-Agent": "Mozilla/5.0 svm-advisory-feed-v3"
        }
      });

      lastStatus = response.status;
      lastText = await response.text();

      if (response.ok) {
        return {
          status: lastStatus,
          text: lastText
        };
      }

      logWarn("Fetch returned non-OK status", {
        url,
        attempt,
        status: lastStatus
      });
    } catch (err) {
      lastError = err;

      logWarn("Fetch attempt failed", {
        url,
        attempt,
        error: err?.message || String(err)
      });
    }

    if (attempt < maxAttempts) {
      await sleepMs(baseWaitMs * attempt);
    }
  }

  if (lastStatus) {
    return {
      status: lastStatus,
      text: lastText
    };
  }

  throw lastError || new Error(`Fetch failed for URL: ${url}`);
}

export async function fetchJsonWithRetry(url, maxAttempts = 3, baseWaitMs = 1500) {
  const result = await fetchTextWithRetry(url, maxAttempts, baseWaitMs);

  if (result.status < 200 || result.status >= 300) {
    return {
      status: result.status,
      json: null,
      text: result.text
    };
  }

  return {
    status: result.status,
    json: JSON.parse(result.text),
    text: result.text
  };
}
