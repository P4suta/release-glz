#!/usr/bin/env node
// @ts-check
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const KIB = 1024;
const MIB = 1024 * KIB;

// Size one release archive may reach before it is refused.
const MAX_ARCHIVE_BYTES = 256 * MIB;

const archives = [
  "release-glz-x86_64-unknown-linux-musl.tar.gz",
  "release-glz-aarch64-unknown-linux-musl.tar.gz",
  "release-glz-x86_64-apple-darwin.tar.gz",
  "release-glz-aarch64-apple-darwin.tar.gz",
  "release-glz-x86_64-pc-windows-msvc.zip",
  "release-glz-aarch64-pc-windows-msvc.zip",
];

const USAGE = "usage: --artifacts DIR --version vX.Y.Z (--out FILE | --check FILE)";

/**
 * @typedef {object} ChecksumOptions
 * @property {string} artifacts Directory that holds the six release archives.
 * @property {string} version Stable `vX.Y.Z` tag the manifest names.
 * @property {{mode: "out" | "check", file: string}} manifest Whether to write the manifest or compare it with a checked-in one.
 */

/**
 * @param {string} message
 * @returns {void}
 */
function fail(message) {
  process.stderr.write(`generate-action-checksums: ${message}\n`);
  process.exitCode = 1;
}

/**
 * @param {string[]} argv
 * @returns {ChecksumOptions}
 */
function argumentsFrom(argv) {
  /** @type {Record<string, string>} */
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index] ?? "";
    const value = argv[index + 1];
    if (!["--artifacts", "--version", "--out", "--check"].includes(option) || !value) {
      throw new Error(USAGE);
    }
    if (Object.hasOwn(values, option)) throw new Error(`duplicate option ${option}`);
    values[option] = value;
  }
  const artifacts = values["--artifacts"];
  const version = values["--version"];
  const out = values["--out"];
  const check = values["--check"];
  if (!artifacts || !version || Boolean(out) === Boolean(check)) {
    throw new Error(USAGE);
  }
  if (!/^v\d+\.\d+\.\d+$/.test(version)) {
    throw new Error("version must be a stable vX.Y.Z tag");
  }
  if (check) return { artifacts, version, manifest: { mode: "check", file: check } };
  if (out) return { artifacts, version, manifest: { mode: "out", file: out } };
  throw new Error(USAGE);
}

/**
 * @param {string} file
 * @returns {string}
 */
function digestRegularFile(file) {
  const metadata = fs.lstatSync(file);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size === 0 ||
    metadata.size > MAX_ARCHIVE_BYTES
  ) {
    throw new Error(`${path.basename(file)} is not a bounded regular release archive`);
  }
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

/**
 * @param {string} directory
 * @param {string} version
 * @returns {string}
 */
function render(directory, version) {
  /** @type {Record<string, string>} */
  const artifacts = {};
  for (const archive of archives) {
    artifacts[archive] = digestRegularFile(path.join(directory, archive));
  }
  return `${JSON.stringify(
    {
      schema: "release-glz-action-checksums/v1",
      version,
      artifacts,
    },
    null,
    2,
  )}\n`;
}

/**
 * @param {string} destination
 * @param {string} contents
 * @returns {void}
 */
function writeAtomically(destination, contents) {
  const parent = path.dirname(destination);
  fs.mkdirSync(parent, { recursive: true });
  const temporary = path.join(parent, `.${path.basename(destination)}.${process.pid}.tmp`);
  fs.writeFileSync(temporary, contents, { flag: "wx", mode: 0o600 });
  try {
    fs.renameSync(temporary, destination);
  } catch (error) {
    try {
      fs.unlinkSync(temporary);
    } catch {}
    throw error;
  }
}

/**
 * @param {string[]} argv
 * @returns {void}
 */
function main(argv = process.argv.slice(2)) {
  const options = argumentsFrom(argv);
  const rendered = render(options.artifacts, options.version);
  if (options.manifest.mode === "check") {
    const actual = fs.readFileSync(options.manifest.file, "utf8");
    if (actual !== rendered)
      throw new Error("checked-in Action checksum manifest does not match release archives");
    return;
  }
  writeAtomically(options.manifest.file, rendered);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}

module.exports = { argumentsFrom, render };
