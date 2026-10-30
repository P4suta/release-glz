// @ts-check
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const zlib = require("node:zlib");

const { createTarGz } = require("./package-unix.js");
const { extract, inventoryTarGz } = require("../action/index.js");

const BLOCK_BYTES = 512;
const RECORD_BYTES = 20 * BLOCK_BYTES;
// Larger than one stored deflate block holds, and not a whole number of tar blocks.
const MULTI_BLOCK_BYTES = 3 * 65535 + 1234;

/**
 * @param {import("node:test").TestContext} context
 * @param {string} prefix
 * @returns {string}
 */
function temporaryRoot(context, prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  context.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

/**
 * @param {number} length
 * @returns {Buffer}
 */
function fixture(length) {
  return Buffer.from(Array.from({ length }, (_, index) => (index * 31 + 7) % 251));
}

/**
 * @param {Buffer} header
 * @param {number} start
 * @param {number} length
 * @returns {string}
 */
function field(header, start, length) {
  return header.subarray(start, start + length).toString("latin1");
}

test("packages the same binary into the same bytes whatever its mode and time", (context) => {
  const root = temporaryRoot(context, "release-glz-tar-");
  const binary = path.join(root, "input");
  const left = path.join(root, "left.tar.gz");
  const right = path.join(root, "right.tar.gz");
  fs.writeFileSync(binary, fixture(MULTI_BLOCK_BYTES), { mode: 0o755 });

  createTarGz(binary, left);
  fs.chmodSync(binary, 0o644);
  fs.utimesSync(binary, new Date(Date.UTC(2001, 0, 1)), new Date(Date.UTC(2001, 0, 1)));
  createTarGz(binary, right);

  assert.deepEqual(fs.readFileSync(left), fs.readFileSync(right));
});

test("pins the archive bytes, so every host writes the same archive", (context) => {
  const root = temporaryRoot(context, "release-glz-tar-pinned-");
  const binary = path.join(root, "input");
  const archive = path.join(root, "release.tar.gz");
  fs.writeFileSync(binary, Buffer.from("\x7fELF deterministic fixture\n", "latin1"));

  createTarGz(binary, archive);

  assert.equal(
    crypto.createHash("sha256").update(fs.readFileSync(archive)).digest("hex"),
    "26200f3d631742bef78e4e20459047584a5be42a39cf01482c7473c9446c22f4",
  );
});

test("writes one ustar entry with a fixed mode, owner, group, and time", (context) => {
  const root = temporaryRoot(context, "release-glz-tar-header-");
  const binary = path.join(root, "input");
  const archive = path.join(root, "release.tar.gz");
  const contents = fixture(MULTI_BLOCK_BYTES);
  fs.writeFileSync(binary, contents, { mode: 0o600 });

  createTarGz(binary, archive);

  const compressed = fs.readFileSync(archive);
  // Deflate, no flags, no time, no compression level, and Unix, whatever host wrote it.
  assert.equal(compressed.subarray(0, 10).toString("hex"), "1f8b0800000000000003");
  const tar = zlib.gunzipSync(compressed);
  assert.equal(tar.length % RECORD_BYTES, 0);
  const header = tar.subarray(0, BLOCK_BYTES);
  assert.equal(field(header, 0, 100), `release-glz${"\0".repeat(89)}`);
  assert.equal(field(header, 100, 8), "0000755\0");
  assert.equal(field(header, 108, 8), "0000000\0");
  assert.equal(field(header, 116, 8), "0000000\0");
  assert.equal(field(header, 124, 12), `${contents.length.toString(8).padStart(11, "0")}\0`);
  assert.equal(field(header, 136, 12), "00000000000\0");
  assert.equal(field(header, 156, 1), "0");
  assert.equal(field(header, 157, 100), "\0".repeat(100));
  assert.equal(field(header, 257, 8), "ustar\x0000");
  assert.equal(field(header, 265, 64), "\0".repeat(64));
  assert.equal(field(header, 329, 16), "0000000\0".repeat(2));
  assert.equal(field(header, 345, 167), "\0".repeat(167));
  const sum = [...header].reduce(
    (total, byte, index) => total + (index >= 148 && index < 156 ? 0x20 : byte),
    0,
  );
  assert.equal(field(header, 148, 8), `${sum.toString(8).padStart(6, "0")}\0 `);
  assert.deepEqual(tar.subarray(BLOCK_BYTES, BLOCK_BYTES + contents.length), contents);
  assert.ok(tar.subarray(BLOCK_BYTES + contents.length).every((byte) => byte === 0));
});

test("the Action's tar reader accepts the archive and extracts the binary", {
  skip: process.platform === "win32" && "the Action extracts a Unix archive only on Unix hosts",
}, async (context) => {
  const root = temporaryRoot(context, "release-glz-tar-extract-");
  const binary = path.join(root, "input");
  const archive = path.join(root, "release.tar.gz");
  const destination = path.join(root, "extracted");
  const contents = fixture(MULTI_BLOCK_BYTES);
  fs.writeFileSync(binary, contents, { mode: 0o600 });
  createTarGz(binary, archive);

  assert.deepEqual(await inventoryTarGz(archive), [
    { path: "release-glz", kind: "file", size: contents.length },
  ]);
  await extract(archive, "tar.gz", destination);

  assert.deepEqual(fs.readdirSync(destination), ["release-glz"]);
  const extracted = path.join(destination, "release-glz");
  assert.deepEqual(fs.readFileSync(extracted), contents);
  // The Action extracts with --no-same-permissions, so the umask applies to the archived mode.
  const probe = path.join(root, "umask-probe");
  fs.writeFileSync(probe, "", { mode: 0o777 });
  const permitted = fs.statSync(probe).mode & 0o777;
  assert.equal(fs.statSync(extracted).mode & 0o777, 0o755 & permitted);
});

test("CLI refuses symlink, empty, oversized, existing, and identical paths", (context) => {
  const root = temporaryRoot(context, "release-glz-tar-invalid-");
  const binary = path.join(root, "release-glz");
  const empty = path.join(root, "empty");
  const oversized = path.join(root, "oversized");
  const link = path.join(root, "link");
  const output = path.join(root, "release.tar.gz");
  fs.writeFileSync(binary, "binary");
  fs.writeFileSync(empty, "");
  fs.closeSync(fs.openSync(oversized, "w"));
  fs.truncateSync(oversized, 128 * 1024 * 1024 + 1);
  if (process.platform !== "win32") fs.symlinkSync(binary, link);
  fs.writeFileSync(output, "occupied");

  if (process.platform !== "win32") {
    const linked = run(["--binary", link, "--out", path.join(root, "linked.tar.gz")]);
    assert.notEqual(linked.status, 0);
    assert.match(linked.stderr, /bounded regular executable/);
  }

  const emptyResult = run(["--binary", empty, "--out", path.join(root, "empty.tar.gz")]);
  assert.notEqual(emptyResult.status, 0);
  assert.match(emptyResult.stderr, /bounded regular executable/);

  const oversizedResult = run(["--binary", oversized, "--out", path.join(root, "big.tar.gz")]);
  assert.notEqual(oversizedResult.status, 0);
  assert.match(oversizedResult.stderr, /bounded regular executable/);

  const occupied = run(["--binary", binary, "--out", output]);
  assert.notEqual(occupied.status, 0);
  assert.match(occupied.stderr, /already exists/);
  assert.equal(fs.readFileSync(output, "utf8"), "occupied");

  const same = run(["--binary", binary, "--out", binary]);
  assert.notEqual(same.status, 0);
  assert.match(same.stderr, /different paths/);

  const usage = run(["--binary", binary]);
  assert.notEqual(usage.status, 0);
  assert.match(usage.stderr, /usage: --binary FILE --out FILE/);
});

test("CLI writes the archive it names", (context) => {
  const root = temporaryRoot(context, "release-glz-tar-cli-");
  const binary = path.join(root, "release-glz");
  const output = path.join(root, "release.tar.gz");
  fs.writeFileSync(binary, "binary");

  const result = run(["--binary", binary, "--out", output]);

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  const tar = zlib.gunzipSync(fs.readFileSync(output));
  assert.equal(tar.subarray(BLOCK_BYTES, BLOCK_BYTES + 6).toString("latin1"), "binary");
});

/**
 * @param {string[]} args
 * @returns {{status: number | null, stdout: string, stderr: string}}
 */
function run(args) {
  const result = spawnSync(process.execPath, [path.join(__dirname, "package-unix.js"), ...args], {
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}
