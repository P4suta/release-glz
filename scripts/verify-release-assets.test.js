"use strict";

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const script = path.join(__dirname, "verify-release-assets.js");
const { validateInventory } = require("./verify-release-assets.js");

test("accepts only unique existing assets drawn from the expected inventory", () => {
  const expected = ["release-glz.tar.gz", "SHA256SUMS"];
  assert.doesNotThrow(() => validateInventory(expected, {
    assets: [{ name: "release-glz.tar.gz" }],
  }));
  assert.throws(
    () => validateInventory(expected, { assets: [{ name: "stale.bin" }] }),
    /unsealed asset `stale\.bin`/,
  );
  assert.throws(
    () => validateInventory(expected, {
      assets: [{ name: "SHA256SUMS" }, { name: "SHA256SUMS" }],
    }),
    /duplicate asset `SHA256SUMS`/,
  );
  assert.throws(() => validateInventory(expected, {}), /assets array/);
});

test("CLI derives the expected flat regular-file inventory from dist", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-assets-"));
  fs.writeFileSync(path.join(root, "release-glz.tar.gz"), "archive");
  fs.writeFileSync(path.join(root, "SHA256SUMS"), "sum");

  const run = (body) => childProcess.spawnSync(
    process.execPath,
    [script, "--artifacts", root],
    { encoding: "utf8", input: JSON.stringify(body) },
  );
  assert.equal(run({ assets: [{ name: "SHA256SUMS" }] }).status, 0);
  const unexpected = run({ assets: [{ name: "old-release.zip" }] });
  assert.equal(unexpected.status, 1);
  assert.match(unexpected.stderr, /unsealed asset/);

  fs.mkdirSync(path.join(root, "nested"));
  const nonFlat = run({ assets: [] });
  assert.equal(nonFlat.status, 1);
  assert.match(nonFlat.stderr, /bounded regular files/);
});
