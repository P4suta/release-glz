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

test("workflow verifier rejects a POSIX variable in an implicit shell on a varying runner", () => {
  const matrixJob = (step) => `name: Distribute
on: push
permissions: {}
jobs:
  build:
    timeout-minutes: 10
    permissions:
      contents: read
    runs-on: \${{ matrix.runner }}
    steps:
      - uses: actions/checkout@${"a".repeat(40)}
        with:
          persist-credentials: false
${step}`;

  // PowerShell is the default shell on a Windows runner and leaves `$TARGET`
  // empty, so an implicit shell here builds nothing instead of failing.
  const implicit = matrixJob(`      - env:
          TARGET: \${{ matrix.target }}
        run: cargo build --target "$TARGET"
`);
  assert.throws(() => verifyWorkflow("distribute.yml", implicit), /must set shell/);

  const explicit = matrixJob(`      - shell: bash
        env:
          TARGET: \${{ matrix.target }}
        run: cargo build --target "$TARGET"
`);
  assert.doesNotThrow(() => verifyWorkflow("distribute.yml", explicit));

  // A step that expands no POSIX variable reads the same under either shell.
  const noVariable = matrixJob(`      - run: cargo test --locked
`);
  assert.doesNotThrow(() => verifyWorkflow("distribute.yml", noVariable));

  // A runner fixed to one operating system has a known default shell.
  const fixedRunner = explicit.replace("runs-on: \${{ matrix.runner }}", "runs-on: ubuntu-24.04");
  assert.doesNotThrow(() =>
    verifyWorkflow("distribute.yml", fixedRunner.replace("        shell: bash\n", "")),
  );
});

test("de-shell rejects expression interpolation inside command text", () => {
  const unsafe = safe.replace("printf '%s\\n' \"$VALUE\"", "echo \${{ github.event.pull_request.title }}");
  assert.throws(() => rejectExpressionInterpolation("unsafe.yml", unsafe), /expression.*run/i);
});

test("both workflow validators reject quoted mapping keys before regex inspection", () => {
  for (const key of ["uses", "run", "permissions", "pull_request_target"]) {
    const quoted = key === "pull_request_target"
      ? `"pull_request_target":\n${safe}`
      : safe.replace(new RegExp(`^(\\s*(?:-\\s*)?)${key}:`, "m"), `$1"${key}":`);
    assert.throws(() => verifyWorkflow(`${key}.yml`, quoted), /quoted.*key/i, key);
    assert.throws(() => rejectExpressionInterpolation(`${key}.yml`, quoted), /quoted.*key/i, key);
  }
});
