#!/usr/bin/env node
// @ts-check
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ARCHIVES = Object.freeze([
  "release-glz-x86_64-unknown-linux-musl.tar.gz",
  "release-glz-aarch64-unknown-linux-musl.tar.gz",
  "release-glz-x86_64-apple-darwin.tar.gz",
  "release-glz-aarch64-apple-darwin.tar.gz",
  "release-glz-x86_64-pc-windows-msvc.zip",
  "release-glz-aarch64-pc-windows-msvc.zip",
]);
const KIB = 1024;
const MIB = 1024 * KIB;

const GIT_OBJECT_HEX = /^[a-f0-9]{40}$/;

// A positive decimal run id, bounded to what a 64-bit counter can produce.
const RUN_ID = /^[1-9]\d{0,19}$/;

const MAX_ARCHIVE_BYTES = 256 * MIB;

/**
 * The workflow run that built the archives.
 * @typedef {object} BuildIdentity
 * @property {string} repository The `owner/name` slug.
 * @property {string} source Full commit SHA the tag names.
 * @property {string} version Stable `vX.Y.Z` tag.
 * @property {string} runId GitHub Actions run ID.
 */

/** @typedef {BuildIdentity & {artifacts: string}} ProvenanceOptions */

/**
 * @param {string[]} argv
 * @returns {ProvenanceOptions}
 */
function argumentsFrom(argv) {
  const allowed = new Set(["--artifacts", "--repository", "--source", "--version", "--run-id"]);
  if (argv.length % 2 !== 0) throw new Error("every option requires one value");
  /** @type {Record<string, string>} */
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index] ?? "";
    const value = argv[index + 1];
    if (!allowed.has(option) || typeof value !== "string" || value.length === 0) {
      throw new Error("unsupported or empty option");
    }
    if (Object.hasOwn(values, option)) throw new Error(`duplicate option ${option}`);
    values[option] = value;
  }
  const {
    "--artifacts": artifacts,
    "--repository": repository,
    "--source": source,
    "--version": version,
    "--run-id": runId,
  } = values;
  if (
    artifacts === undefined ||
    repository === undefined ||
    source === undefined ||
    version === undefined ||
    runId === undefined
  ) {
    throw new Error("artifacts, repository, source, version, and run-id are required");
  }
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    throw new Error("repository must be an owner/name pair");
  }
  if (!GIT_OBJECT_HEX.test(source)) {
    throw new Error("source must be a lowercase full commit SHA");
  }
  if (!/^v\d+\.\d+\.\d+$/.test(version)) {
    throw new Error("version must be a stable vX.Y.Z tag");
  }
  if (!RUN_ID.test(runId)) {
    throw new Error("run-id must be a positive decimal GitHub Actions run ID");
  }
  const metadata = fs.lstatSync(artifacts);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("artifacts must be a real directory");
  }
  return { artifacts, repository, source, version, runId };
}

/**
 * @param {string} file
 * @returns {string}
 */
function digestRegularArchive(file) {
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
 * The SLSA provenance statement for one archive.
 * @param {BuildIdentity & {archive: string, digest: string}} subject
 * @returns {object}
 */
function statementFor({ archive, digest, repository, source, version, runId }) {
  const workflow = `https://github.com/${repository}/.github/workflows/distribute.yml@refs/tags/${version}`;
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: archive, digest: { sha256: digest } }],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://github.com/P4suta/release-glz/distribution/v1",
        externalParameters: {
          repository: `https://github.com/${repository}`,
          ref: `refs/tags/${version}`,
          workflow,
        },
        internalParameters: {},
        resolvedDependencies: [
          {
            uri: `git+https://github.com/${repository}@refs/tags/${version}`,
            digest: { gitCommit: source },
          },
        ],
      },
      runDetails: {
        builder: { id: workflow },
        metadata: {
          invocationId: `https://github.com/${repository}/actions/runs/${runId}`,
        },
      },
    },
  };
}

/**
 * @param {string} directory
 * @param {BuildIdentity} identity
 * @returns {void}
 */
function generate(directory, identity) {
  const rendered = new Map();
  for (const archive of ARCHIVES) {
    const digest = digestRegularArchive(path.join(directory, archive));
    const statement = statementFor({ archive, digest, ...identity });
    rendered.set(`${archive}.intoto.jsonl`, `${JSON.stringify(statement)}\n`);
  }
  for (const [name, contents] of rendered) {
    fs.writeFileSync(path.join(directory, name), contents, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
  }
}

/**
 * @param {string[]} argv
 * @returns {void}
 */
function main(argv = process.argv.slice(2)) {
  const { artifacts, ...identity } = argumentsFrom(argv);
  generate(artifacts, identity);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`provenance generation failed: ${message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { ARCHIVES, argumentsFrom, generate, statementFor };
