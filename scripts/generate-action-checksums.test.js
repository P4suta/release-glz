"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const targets = [
  ["x86_64-unknown-linux-musl", "tar.gz"],
  ["aarch64-unknown-linux-musl", "tar.gz"],
  ["x86_64-apple-darwin", "tar.gz"],
  ["aarch64-apple-darwin", "tar.gz"],
  ["x86_64-pc-windows-msvc", "zip"],
  ["aarch64-pc-windows-msvc", "zip"],
];

test("generates and checks the complete action checksum manifest", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-action-sums-"));
  const dist = path.join(root, "dist");
  const manifest = path.join(root, "checksums.json");
  fs.mkdirSync(dist);
  for (const [target, extension] of targets) {
    fs.writeFileSync(path.join(dist, `release-glz-${target}.${extension}`), target);
  }

  const generated = run(["--artifacts", dist, "--version", "v1.0.0", "--out", manifest]);
  assert.equal(generated.status, 0, generated.stderr);
  const parsed = JSON.parse(fs.readFileSync(manifest, "utf8"));
  assert.equal(parsed.schema, "release-glz-action-checksums/v1");
  assert.equal(parsed.version, "v1.0.0");
  assert.equal(Object.keys(parsed.artifacts).length, 6);

  const checked = run(["--artifacts", dist, "--version", "v1.0.0", "--check", manifest]);
  assert.equal(checked.status, 0, checked.stderr);
  fs.appendFileSync(path.join(dist, "release-glz-x86_64-unknown-linux-musl.tar.gz"), "changed");
  const mismatch = run(["--artifacts", dist, "--version", "v1.0.0", "--check", manifest]);
  assert.notEqual(mismatch.status, 0);
  assert.match(mismatch.stderr, /does not match/);
});

function run(args) {
  const result = spawnSync(process.execPath, [
    path.join(__dirname, "generate-action-checksums.js"),
    ...args,
  ], { encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}
