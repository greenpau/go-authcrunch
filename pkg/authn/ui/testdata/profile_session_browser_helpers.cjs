// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.

// Retry read-only observations across document replacement, never login actions.
async function waitFor(fn, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if (await fn()) return;
    } catch (error) {
      if (!/Execution context was destroyed|Cannot find context|Inspected target navigated or closed/.test(error.message)) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("profile recovery did not reach the expected page");
}

module.exports = { waitFor };
