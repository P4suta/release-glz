"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const { verifyWorkflow } = require("./verify-workflows.js");
const { rejectExpressionInterpolation } = require("./de-shell.js");

const safe = `name: Safe
on: push
permissions: {}
jobs:
  test:
    timeout-minutes: 10
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@${"a".repeat(40)}
        with:
          persist-credentials: false
      - env:
          VALUE: \${{ github.ref_name }}
        run: printf '%s\\n' "$VALUE"
`;

test("workflow verifier accepts immutable actions and least-privilege jobs", () => {
  assert.doesNotThrow(() => verifyWorkflow("safe.yml", safe));
  assert.doesNotThrow(() => rejectExpressionInterpolation("safe.yml", safe));
});

test("workflow verifier rejects mutable actions, implicit timeouts, and persistent checkout credentials", () => {
  assert.throws(() => verifyWorkflow("mutable.yml", safe.replace(`${"a".repeat(40)}`, "v7")), /full commit SHA/);
  assert.throws(() => verifyWorkflow("timeout.yml", safe.replace("    timeout-minutes: 10\n", "")), /timeout-minutes/);
  assert.throws(() => verifyWorkflow("credentials.yml", safe.replace("persist-credentials: false", "persist-credentials: true")), /credentials/);
});

test("de-shell rejects expression interpolation inside command text", () => {
  const unsafe = safe.replace("printf '%s\\n' \"$VALUE\"", "echo \${{ github.event.pull_request.title }}");
  assert.throws(() => rejectExpressionInterpolation("unsafe.yml", unsafe), /expression.*run/i);
});
