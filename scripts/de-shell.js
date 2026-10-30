#!/usr/bin/env node
// @ts-check
"use strict";

const fs = require("node:fs");
const { rejectQuotedMappingKeys, workflowFiles } = require("./verify-workflows.js");

/**
 * @param {string} line
 * @returns {number}
 */
function indentation(line) {
  return line.length - line.trimStart().length;
}

/**
 * @param {string} filename
 * @param {string} source
 * @returns {void}
 */
function rejectExpressionInterpolation(filename, source) {
  rejectQuotedMappingKeys(filename, source);
  const lines = source.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const match = (lines[index] ?? "").match(/^(\s*)(?:-\s*)?run:\s*(.*)$/);
    if (!match) continue;
    const [, leading = "", value = ""] = match;
    const indent = leading.length;
    if (value.includes("${{")) {
      throw new Error(`${filename}: expression interpolation is forbidden in run commands`);
    }
    if (!/^[|>][-+]?\s*(?:#.*)?$/.test(value)) continue;
    for (index += 1; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      if (line.trim() && indentation(line) <= indent) {
        index -= 1;
        break;
      }
      if (line.includes("${{")) {
        throw new Error(`${filename}: expression interpolation is forbidden in run blocks`);
      }
    }
  }
}

/**
 * @param {string[]} argv
 * @returns {void}
 */
function main(argv = process.argv.slice(2)) {
  for (const file of workflowFiles(argv)) {
    rejectExpressionInterpolation(file, fs.readFileSync(file, "utf8"));
  }
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`de-shell verification failed: ${message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, rejectExpressionInterpolation };
