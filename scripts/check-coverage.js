#!/usr/bin/env node
"use strict";

const fs = require("node:fs");

const MAX_REPORT_BYTES = 512 * 1024 * 1024;

function metric(totals, name) {
  const value = totals?.[name];
  const label = name === "branches" ? "branch" : "line";
  if (!value || !Number.isSafeInteger(value.count) || !Number.isSafeInteger(value.covered) ||
      value.count <= 0 || value.covered < 0 || value.covered > value.count) {
    throw new Error(`${label} coverage data is missing or invalid`);
  }
  return (value.covered * 100) / value.count;
}

function evaluateCoverage(report, minimumLines, minimumBranches) {
  const totals = report?.data?.length === 1 ? report.data[0]?.totals : undefined;
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

function argumentsFrom(argv) {
  const values = { "--report": "coverage.json" };
  if (argv.length % 2 !== 0) throw new Error("each coverage option requires one value");
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    if (!["--report", "--lines", "--branches"].includes(option)) {
      throw new Error("usage: [--report FILE] --lines PERCENT --branches PERCENT");
    }
    if (option !== "--report" && Object.hasOwn(values, option)) {
      throw new Error(`duplicate option ${option}`);
    }
    values[option] = argv[index + 1];
  }
  for (const option of ["--lines", "--branches"]) {
    const threshold = Number(values[option]);
    if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
      throw new Error(`${option.slice(2)} threshold must be between 0 and 100`);
    }
    values[option] = threshold;
  }
  return values;
}

function main(argv = process.argv.slice(2)) {
  const options = argumentsFrom(argv);
  const metadata = fs.lstatSync(options["--report"]);
  if (!metadata.isFile() || metadata.isSymbolicLink() ||
      metadata.size === 0 || metadata.size > MAX_REPORT_BYTES) {
    throw new Error("coverage report must be a bounded regular file");
  }
  const report = JSON.parse(fs.readFileSync(options["--report"], "utf8"));
  const result = evaluateCoverage(report, options["--lines"], options["--branches"]);
  process.stdout.write(`line coverage ${result.lines.toFixed(2)}%, branch coverage ${result.branches.toFixed(2)}%\n`);
}

if (require.main === module) {
  try { main(); } catch (error) {
    process.stderr.write(`coverage gate failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { argumentsFrom, evaluateCoverage, main };
