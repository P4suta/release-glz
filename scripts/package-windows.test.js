"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const { createStoredZip } = require("./package-windows.js");

test("packages a single executable into byte-for-byte deterministic ZIP archives", (context) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-zip-"));
  context.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const binary = path.join(root, "input.exe");
  const left = path.join(root, "left.zip");
  const right = path.join(root, "right.zip");
  fs.writeFileSync(binary, Buffer.from("MZ deterministic fixture\n"));

  createStoredZip(binary, left);
  fs.utimesSync(binary, new Date(), new Date());
  createStoredZip(binary, right);

  const leftBytes = fs.readFileSync(left);
  assert.deepEqual(leftBytes, fs.readFileSync(right));
  assert.equal(leftBytes.readUInt32LE(0), 0x04034b50);
  assert.equal(leftBytes.readUInt32LE(leftBytes.length - 22), 0x06054b50);
  assert.match(leftBytes.toString("latin1"), /release-glz\.exe/);
  assert.equal(
    crypto.createHash("sha256").update(leftBytes).digest("hex"),
    crypto.createHash("sha256").update(fs.readFileSync(right)).digest("hex"),
  );
});

test("CLI refuses symlink, empty, oversized, and existing output paths", (context) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-zip-invalid-"));
  context.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const binary = path.join(root, "release-glz.exe");
  const empty = path.join(root, "empty.exe");
  const oversized = path.join(root, "oversized.exe");
  const link = path.join(root, "link.exe");
  const output = path.join(root, "release.zip");
  fs.writeFileSync(binary, "binary");
  fs.writeFileSync(empty, "");
  fs.closeSync(fs.openSync(oversized, "w"));
  fs.truncateSync(oversized, 128 * 1024 * 1024 + 1);
  if (process.platform !== "win32") fs.symlinkSync(binary, link);
  fs.writeFileSync(output, "occupied");

  if (process.platform !== "win32") {
    const linked = run(["--binary", link, "--out", path.join(root, "linked.zip")]);
    assert.notEqual(linked.status, 0);
    assert.match(linked.stderr, /bounded regular executable/);
  }

  const emptyResult = run(["--binary", empty, "--out", path.join(root, "empty.zip")]);
  assert.notEqual(emptyResult.status, 0);
  assert.match(emptyResult.stderr, /bounded regular executable/);

  const oversizedResult = run([
    "--binary", oversized,
    "--out", path.join(root, "oversized.zip"),
  ]);
  assert.notEqual(oversizedResult.status, 0);
  assert.match(oversizedResult.stderr, /bounded regular executable/);

  const occupied = run(["--binary", binary, "--out", output]);
  assert.notEqual(occupied.status, 0);
  assert.match(occupied.stderr, /already exists/);
});

function run(args) {
  const result = spawnSync(process.execPath, [path.join(__dirname, "package-windows.js"), ...args], {
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}
