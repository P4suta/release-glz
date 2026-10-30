#!/usr/bin/env node
// @ts-check
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const KIB = 1024;
const MIB = 1024 * KIB;

const MAX_RELEASE_JSON_BYTES = 4 * MIB;
const MAX_ASSET_COUNT = 1024;

// Characters a Release asset name may use.
const MAX_ASSET_NAME_LEN = 256;

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * @param {unknown} name
 * @returns {name is string}
 */
function safeAssetName(name) {
  return (
    typeof name === "string" &&
    name.length > 0 &&
    name.length <= MAX_ASSET_NAME_LEN &&
    name !== "." &&
    name !== ".." &&
    !/[\\/\0\r\n]/.test(name)
  );
}

// The form GitHub reports in a Release asset's `digest`.
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;

/**
 * @param {string} file
 * @returns {string}
 */
function sha256Digest(file) {
  return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex")}`;
}

/**
 * Refuse a GitHub Release whose assets aren't a subset of the sealed inventory with the same digests, or all of it when `requireComplete` is set.
 * @param {Map<string, string>} expected
 * @param {unknown} release
 * @param {boolean} [requireComplete]
 * @returns {void}
 */
function validateInventory(expected, release, requireComplete = false) {
  if (!(expected instanceof Map) || expected.size === 0 || expected.size > MAX_ASSET_COUNT) {
    throw new Error("expected release inventory is empty or excessive");
  }
  for (const [name, digest] of expected) {
    if (!safeAssetName(name) || !SHA256_DIGEST.test(digest)) {
      throw new Error("expected release inventory has an unsafe name or digest");
    }
  }
  /** @type {unknown} */
  const assets = isRecord(release) ? release.assets : undefined;
  if (!Array.isArray(assets) || assets.length > MAX_ASSET_COUNT) {
    throw new Error("GitHub Release response has no bounded assets array");
  }
  /** @type {Set<string>} */
  const existing = new Set();
  for (const asset of /** @type {unknown[]} */ (assets)) {
    const name = isRecord(asset) ? asset.name : undefined;
    if (!isRecord(asset) || !safeAssetName(name)) {
      throw new Error("GitHub Release contains an unsafe asset name");
    }
    if (existing.has(name)) {
      throw new Error(`GitHub Release contains duplicate asset \`${name}\``);
    }
    if (!expected.has(name)) {
      throw new Error(`GitHub Release contains unsealed asset \`${name}\``);
    }
    if (asset.digest !== expected.get(name)) {
      throw new Error(
        `GitHub Release asset \`${name}\` has digest ${asset.digest ?? "none"}, not ${expected.get(name)}`,
      );
    }
    existing.add(name);
  }
  if (requireComplete && existing.size !== expected.size) {
    throw new Error("GitHub Release does not contain the complete sealed inventory");
  }
}

/**
 * The digest of every file in `directory`, keyed by file name.
 * @param {string} directory
 * @returns {Map<string, string>}
 */
function expectedInventory(directory) {
  const metadata = fs.lstatSync(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("artifact inventory must be a real directory");
  }
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  if (
    entries.length === 0 ||
    entries.length > MAX_ASSET_COUNT ||
    entries.some((entry) => !entry.isFile())
  ) {
    throw new Error("artifact inventory must contain only bounded regular files");
  }
  return new Map(
    entries
      .map((entry) => entry.name)
      .sort()
      .map((name) => [name, sha256Digest(path.join(directory, name))]),
  );
}

/**
 * @param {NodeJS.ReadableStream} stream
 * @returns {Promise<string>}
 */
function readBoundedStdin(stream = process.stdin) {
  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */
    const chunks = [];
    let size = 0;
    let settled = false;
    stream.on("data", (/** @type {Buffer} */ chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > MAX_RELEASE_JSON_BYTES) {
        settled = true;
        stream.pause();
        reject(new Error("GitHub Release response exceeds the 4 MiB limit"));
        return;
      }
      chunks.push(chunk);
    });
    stream.on("end", () => {
      if (!settled) resolve(Buffer.concat(chunks).toString("utf8"));
    });
    stream.on("error", (/** @type {Error} */ error) => {
      if (!settled) reject(error);
    });
  });
}

/**
 * @param {string[]} argv
 * @returns {string}
 */
function artifactsArgument(argv) {
  const [flag, directory, complete] = argv;
  if (
    (argv.length !== 2 && argv.length !== 3) ||
    flag !== "--artifacts" ||
    !directory ||
    (argv.length === 3 && complete !== "--complete")
  ) {
    throw new Error("usage: verify-release-assets.js --artifacts DIR [--complete]");
  }
  return directory;
}

/**
 * @param {string[]} argv
 * @returns {Promise<void>}
 */
async function main(argv = process.argv.slice(2)) {
  const directory = artifactsArgument(argv);
  const source = await readBoundedStdin();
  /** @type {unknown} */
  let release;
  try {
    release = JSON.parse(source);
  } catch {
    throw new Error("GitHub Release response is not valid JSON");
  }
  validateInventory(
    expectedInventory(path.resolve(directory)),
    release,
    argv.includes("--complete"),
  );
}

if (require.main === module) {
  main().catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`release asset inventory verification failed: ${message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  artifactsArgument,
  expectedInventory,
  readBoundedStdin,
  safeAssetName,
  validateInventory,
};
