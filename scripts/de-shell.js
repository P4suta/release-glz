#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const { rejectQuotedMappingKeys, workflowFiles } = require("./verify-workflows.js");

function indentation(line) {
  return line.length - line.trimStart().length;
}

function rejectExpressionInterpolation(filename, source) {
  rejectQuotedMappingKeys(filename, source);
  const lines = source.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(/^(\s*)(?:-\s*)?run:\s*(.*)$/);
    if (!match) continue;
    const indent = match[1].length;
    const value = match[2];
    if (value.includes("${{")) {
      throw new Error(`${filename}: expression interpolation is forbidden in run commands`);
    }
    if (!/^[|>][-+]?\s*(?:#.*)?$/.test(value)) continue;
    for (index += 1; index < lines.length; index += 1) {
      if (lines[index].trim() && indentation(lines[index]) <= indent) {
        index -= 1;
        break;
      }
      if (lines[index].includes("${{")) {
        throw new Error(`${filename}: expression interpolation is forbidden in run blocks`);
      }
    }
  }
}

function main(argv = process.argv.slice(2)) {
  for (const file of workflowFiles(argv)) {
    rejectExpressionInterpolation(file, fs.readFileSync(file, "utf8"));
  }
}

if (require.main === module) {
  try { main(); } catch (error) {
    process.stderr.write(`de-shell verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, rejectExpressionInterpolation };
