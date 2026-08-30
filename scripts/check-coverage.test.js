"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const { evaluateCoverage } = require("./check-coverage.js");

test("accepts coverage only when both line and branch thresholds are met", () => {
  const report = {
    type: "llvm.coverage.json.export",
    version: "2.0.1",
    data: [{ totals: {
      lines: { count: 100, covered: 90, percent: 90 },
      branches: { count: 200, covered: 170, percent: 85 },
    } }],
  };
  assert.deepEqual(evaluateCoverage(report, 90, 85), { lines: 90, branches: 85 });
  assert.throws(() => evaluateCoverage(report, 90.01, 85), /line coverage/);
  assert.throws(() => evaluateCoverage(report, 90, 85.01), /branch coverage/);
});

test("rejects missing, non-finite, or zero-denominator branch reports", () => {
  assert.throws(() => evaluateCoverage({}, 90, 85), /unsupported LLVM coverage/);
  assert.throws(() => evaluateCoverage({ data: [{ totals: {
    lines: { count: 1, covered: 1, percent: 100 },
    branches: { count: 0, covered: 0, percent: 100 },
  } }] }, 90, 85), /branch coverage data/);
});
