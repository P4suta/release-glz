"use strict";

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const script = path.join(__dirname, "verify-release-assets.js");
const { validateInventory } = require("./verify-release-assets.js");

const digest = (contents) => `sha256:${crypto.createHash("sha256").update(contents).digest("hex")}`;

test("accepts only unique existing assets drawn from the expected inventory", () => {
  const archive = digest("archive");
  const sums = digest("sum");
  const expected = new Map([
    ["release-glz.tar.gz", archive],
    ["SHA256SUMS", sums],
  ]);
  assert.doesNotThrow(() =>
    validateInventory(expected, {
      assets: [{ name: "release-glz.tar.gz", digest: archive }],
    }),
  );
  assert.throws(
    () => validateInventory(expected, { assets: [{ name: "stale.bin" }] }),
    /unsealed asset `stale\.bin`/,
  );
  assert.throws(
    () =>
      validateInventory(expected, {
        assets: [
          { name: "SHA256SUMS", digest: sums },
          { name: "SHA256SUMS", digest: sums },
        ],
      }),
    /duplicate asset `SHA256SUMS`/,
  );
  assert.throws(() => validateInventory(expected, {}), /assets array/);
  assert.doesNotThrow(() =>
    validateInventory(
      expected,
      {
        assets: [
          { name: "release-glz.tar.gz", digest: archive },
          { name: "SHA256SUMS", digest: sums },
        ],
      },
      true,
    ),
  );
  assert.throws(
    () =>
      validateInventory(
        expected,
        {
          assets: [{ name: "release-glz.tar.gz", digest: archive }],
        },
        true,
      ),
    /complete sealed inventory/,
  );
});

test("requires every existing asset to carry the digest of its local file", () => {
  const expected = new Map([["release-glz.tar.gz", digest("archive")]]);
  assert.throws(
    () => validateInventory(expected, { assets: [{ name: "release-glz.tar.gz" }] }),
    /`release-glz\.tar\.gz` has digest none, not sha256:/,
  );
  assert.throws(
    () =>
      validateInventory(expected, {
        assets: [{ name: "release-glz.tar.gz", digest: digest("replaced") }],
      }),
    /`release-glz\.tar\.gz` has digest sha256:[0-9a-f]{64}, not sha256:/,
  );
  assert.throws(
    () => validateInventory(new Map([["release-glz.tar.gz", "sha256:short"]]), { assets: [] }),
    /unsafe name or digest/,
  );
});

test("CLI derives the expected flat regular-file inventory and digests from dist", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-assets-"));
  fs.writeFileSync(path.join(root, "release-glz.tar.gz"), "archive");
  fs.writeFileSync(path.join(root, "SHA256SUMS"), "sum");
  const archive = { name: "release-glz.tar.gz", digest: digest("archive") };
  const sums = { name: "SHA256SUMS", digest: digest("sum") };

  const run = (body, ...flags) =>
    childProcess.spawnSync(process.execPath, [script, "--artifacts", root, ...flags], {
      encoding: "utf8",
      input: JSON.stringify(body),
    });
  assert.equal(run({ assets: [sums] }).status, 0);
  const incomplete = run({ assets: [sums] }, "--complete");
  assert.equal(incomplete.status, 1);
  assert.match(incomplete.stderr, /complete sealed inventory/);
  const complete = run({ assets: [sums, archive] }, "--complete");
  assert.equal(complete.status, 0, complete.stderr);
  const replaced = run(
    { assets: [sums, { ...archive, digest: digest("replaced") }] },
    "--complete",
  );
  assert.equal(replaced.status, 1);
  assert.match(replaced.stderr, /`release-glz\.tar\.gz` has digest/);
  const unexpected = run({ assets: [{ name: "old-release.zip" }] });
  assert.equal(unexpected.status, 1);
  assert.match(unexpected.stderr, /unsealed asset/);

  fs.mkdirSync(path.join(root, "nested"));
  const nonFlat = run({ assets: [] });
  assert.equal(nonFlat.status, 1);
  assert.match(nonFlat.stderr, /bounded regular files/);
});
