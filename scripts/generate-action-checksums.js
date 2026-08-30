#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const archives = [
  "release-glz-x86_64-unknown-linux-musl.tar.gz",
  "release-glz-aarch64-unknown-linux-musl.tar.gz",
  "release-glz-x86_64-apple-darwin.tar.gz",
  "release-glz-aarch64-apple-darwin.tar.gz",
  "release-glz-x86_64-pc-windows-msvc.zip",
  "release-glz-aarch64-pc-windows-msvc.zip",
];

function fail(message) {
  process.stderr.write(`generate-action-checksums: ${message}\n`);
  process.exitCode = 1;
}

function argumentsFrom(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    const value = argv[index + 1];
    if (!["--artifacts", "--version", "--out", "--check"].includes(option) || !value) {
      throw new Error("usage: --artifacts DIR --version vX.Y.Z (--out FILE | --check FILE)");
    }
    if (Object.hasOwn(values, option)) throw new Error(`duplicate option ${option}`);
    values[option] = value;
  }
  if (!values["--artifacts"] || !values["--version"] ||
      Boolean(values["--out"]) === Boolean(values["--check"])) {
    throw new Error("usage: --artifacts DIR --version vX.Y.Z (--out FILE | --check FILE)");
  }
  if (!/^v\d+\.\d+\.\d+$/.test(values["--version"])) {
    throw new Error("version must be a stable vX.Y.Z tag");
  }
  return values;
}

function digestRegularFile(file) {
  const metadata = fs.lstatSync(file);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0 || metadata.size > 256 * 1024 * 1024) {
    throw new Error(`${path.basename(file)} is not a bounded regular release archive`);
  }
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function render(directory, version) {
  const artifacts = {};
  for (const archive of archives) {
    artifacts[archive] = digestRegularFile(path.join(directory, archive));
  }
  return `${JSON.stringify({
    schema: "release-glz-action-checksums/v1",
    version,
    artifacts,
  }, null, 2)}\n`;
}

function writeAtomically(destination, contents) {
  const parent = path.dirname(destination);
  fs.mkdirSync(parent, { recursive: true });
  const temporary = path.join(parent, `.${path.basename(destination)}.${process.pid}.tmp`);
  fs.writeFileSync(temporary, contents, { flag: "wx", mode: 0o600 });
  try {
    fs.renameSync(temporary, destination);
  } catch (error) {
    try { fs.unlinkSync(temporary); } catch {}
    throw error;
  }
}

function main(argv = process.argv.slice(2)) {
  const options = argumentsFrom(argv);
  const rendered = render(options["--artifacts"], options["--version"]);
  if (options["--check"]) {
    const actual = fs.readFileSync(options["--check"], "utf8");
    if (actual !== rendered) throw new Error("checked-in Action checksum manifest does not match release archives");
    return;
  }
  writeAtomically(options["--out"], rendered);
}

if (require.main === module) {
  try { main(); } catch (error) { fail(error.message); }
}

module.exports = { argumentsFrom, render };
