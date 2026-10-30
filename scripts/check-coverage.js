#!/usr/bin/env node
// @ts-check
"use strict";

const fs = require("node:fs");

const MAX_REPORT_BYTES = 512 * 1024 * 1024;

/** @typedef {{"--report": string, "--lines": number, "--branches": number}} CoverageOptions */

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * The covered percentage of one total in an LLVM coverage report.
 * @param {unknown} totals
 * @param {"lines" | "branches"} name
 * @returns {number}
 */
function metric(totals, name) {
  const value = isRecord(totals) ? totals[name] : undefined;
  const count = isRecord(value) ? value.count : undefined;
  const covered = isRecord(value) ? value.covered : undefined;
  const label = name === "branches" ? "branch" : "line";
  if (
    typeof count !== "number" ||
    typeof covered !== "number" ||
    !Number.isSafeInteger(count) ||
    !Number.isSafeInteger(covered) ||
    count <= 0 ||
    covered < 0 ||
    covered > count
  ) {
    throw new Error(`${label} coverage data is missing or invalid`);
  }
  return (covered * 100) / count;
}

/**
 * @param {unknown} report
 * @param {number} minimumLines
 * @param {number} minimumBranches
 * @returns {{lines: number, branches: number}}
 */
function evaluateCoverage(report, minimumLines, minimumBranches) {
  const data = isRecord(report) ? report.data : undefined;
  /** @type {unknown} */
  const onlyExport = Array.isArray(data) && data.length === 1 ? data[0] : undefined;
  const totals = isRecord(onlyExport) ? onlyExport.totals : undefined;
  if (!totals) throw new Error("unsupported LLVM coverage report shape");
  const lines = metric(totals, "lines");
  const branches = metric(totals, "branches");
  if (lines + Number.EPSILON < minimumLines) {
    throw new Error(`line coverage ${lines.toFixed(2)}% is below ${minimumLines}%`);
  }
  if (branches + Number.EPSILON < minimumBranches) {
    throw new Error(`branch coverage ${branches.toFixed(2)}% is below ${minimumBranches}%`);
  }
  return { lines, branches };
}

/**
 * @param {string[]} argv
 * @returns {CoverageOptions}
 */
function argumentsFrom(argv) {
  /** @type {Record<string, string | undefined>} */
  const values = { "--report": "coverage.json" };
  if (argv.length % 2 !== 0) throw new Error("each coverage option requires one value");
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index] ?? "";
    if (!["--report", "--lines", "--branches"].includes(option)) {
      throw new Error("usage: [--report FILE] --lines PERCENT --branches PERCENT");
    }
    if (option !== "--report" && Object.hasOwn(values, option)) {
      throw new Error(`duplicate option ${option}`);
    }
    values[option] = argv[index + 1];
  }
  /**
   * @param {"--lines" | "--branches"} option
   * @returns {number}
   */
  const threshold = (option) => {
    const value = Number(values[option]);
    if (!Number.isFinite(value) || value < 0 || value > 100) {
      throw new Error(`${option.slice(2)} threshold must be between 0 and 100`);
    }
    return value;
  };
  return {
    "--report": values["--report"] ?? "coverage.json",
    "--lines": threshold("--lines"),
    "--branches": threshold("--branches"),
  };
}

/**
 * @param {string[]} argv
 * @returns {void}
 */
function main(argv = process.argv.slice(2)) {
  const options = argumentsFrom(argv);
  const metadata = fs.lstatSync(options["--report"]);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size === 0 ||
    metadata.size > MAX_REPORT_BYTES
  ) {
    throw new Error("coverage report must be a bounded regular file");
  }
  const report = JSON.parse(fs.readFileSync(options["--report"], "utf8"));
  const result = evaluateCoverage(report, options["--lines"], options["--branches"]);
  process.stdout.write(
    `line coverage ${result.lines.toFixed(2)}%, branch coverage ${result.branches.toFixed(2)}%\n`,
  );
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`coverage gate failed: ${message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { argumentsFrom, evaluateCoverage, main };
