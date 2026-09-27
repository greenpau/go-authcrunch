// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const test = require("node:test");
const assert = require("node:assert/strict");
const { waitFor } = require("./profile_session_browser_helpers.cjs");

test("profile navigation waits for the expected page", { timeout: 1000 }, async () => {
  let observations = 0;
  await waitFor(() => ++observations === 2);
  assert.equal(observations, 2);
});

for (const message of [
  "Execution context was destroyed.",
  "Cannot find context with specified id",
  "Inspected target navigated or closed",
]) {
  test(`profile navigation recovers from ${message}`, { timeout: 1000 }, async () => {
    let observations = 0;
    await waitFor(async () => {
      if (++observations === 1) throw new Error(message);
      return observations === 3;
    });
    assert.equal(observations, 3, "a navigation error must not count as the expected page");
  });
}

for (const message of ["browser command timed out", "browser evaluation failed", "Session with given id not found."]) {
  test(`profile navigation preserves ${message}`, async () => {
    const failure = new Error(message);
    let observations = 0;
    await assert.rejects(waitFor(async () => {
      observations++;
      throw failure;
    }), (error) => error === failure);
    assert.equal(observations, 1, "unrelated errors must fail immediately");
  });
}

for (const navigating of [false, true]) {
  test(`profile navigation keeps its deadline with navigating=${navigating}`, { timeout: 1000 }, async () => {
    await assert.rejects(waitFor(async () => {
      if (navigating) throw new Error("Inspected target navigated or closed");
      return false;
    }, 40), /profile recovery did not reach the expected page/);
  });
}
