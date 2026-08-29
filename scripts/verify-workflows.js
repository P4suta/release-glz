#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const MAX_WORKFLOW_BYTES = 1024 * 1024;

function indentation(line) {
  return line.length - line.trimStart().length;
}

function jobBlocks(source) {
  const lines = source.split(/\r?\n/);
  const jobsIndex = lines.findIndex((line) => /^jobs:\s*(?:#.*)?$/.test(line));
  if (jobsIndex < 0) throw new Error("workflow has no jobs mapping");
  const blocks = [];
  for (let index = jobsIndex + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    const indent = indentation(line);
    if (indent === 0) break;
    const match = line.match(/^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$/);
    if (!match) continue;
    let end = index + 1;
    while (end < lines.length && (!lines[end].trim() || indentation(lines[end]) > 2)) end += 1;
    blocks.push({ name: match[1], source: lines.slice(index, end).join("\n") });
    index = end - 1;
  }
  if (blocks.length === 0) throw new Error("workflow has no statically named jobs");
  return blocks;
}

function rejectQuotedMappingKeys(filename, source) {
  if (/^\s*(?:-\s*)?(?:"(?:[^"\\]|\\.)*"|'[^']*')\s*:/m.test(source)) {
    throw new Error(`${filename}: quoted YAML mapping keys are forbidden by the security verifier`);
  }
}

function verifyWorkflow(filename, source) {
  if (typeof source !== "string" || Buffer.byteLength(source) > MAX_WORKFLOW_BYTES) {
    throw new Error(`${filename}: workflow exceeds its size limit`);
  }
  rejectQuotedMappingKeys(filename, source);
  if (/^\s*pull_request_target\s*:/m.test(source)) {
    throw new Error(`${filename}: pull_request_target is forbidden`);
  }
  if (!/^permissions:\s*\{\}\s*(?:#.*)?$/m.test(source)) {
    throw new Error(`${filename}: top-level permissions must be empty`);
  }
  if (/permissions:\s*write-all/.test(source)) {
    throw new Error(`${filename}: write-all permissions are forbidden`);
  }

  const uses = [...source.matchAll(/^\s*(?:-\s*)?uses:\s*([^\s#]+).*$/gm)];
  for (const match of uses) {
    const reference = match[1];
    if (reference.startsWith("./")) continue;
    if (reference.startsWith("docker://")) {
      if (!/@sha256:[a-f0-9]{64}$/.test(reference)) {
        throw new Error(`${filename}: container action must use a sha256 digest`);
      }
      continue;
    }
    const separator = reference.lastIndexOf("@");
    if (separator < 1 || !/^[a-f0-9]{40}$/i.test(reference.slice(separator + 1))) {
      throw new Error(`${filename}: every external action must use a full commit SHA`);
    }
  }

  const lines = source.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    if (!/uses:\s*actions\/checkout@/i.test(lines[index])) continue;
    const stepIndent = indentation(lines[index]);
    let end = index + 1;
    while (end < lines.length &&
      (!/^\s*-\s+/.test(lines[end]) || indentation(lines[end]) > stepIndent)) end += 1;
    const step = lines.slice(index, end).join("\n");
    if (!/^\s*persist-credentials:\s*false\s*(?:#.*)?$/m.test(step)) {
      throw new Error(`${filename}: checkout must disable persistent credentials`);
    }
  }

  for (const job of jobBlocks(source)) {
    if (!/^\s+timeout-minutes:\s*[1-9]\d*\s*(?:#.*)?$/m.test(job.source)) {
      throw new Error(`${filename}: job ${job.name} must set timeout-minutes`);
    }
    if (!/^\s+permissions:\s*(?:\{\}\s*)?(?:#.*)?$/m.test(job.source)) {
      throw new Error(`${filename}: job ${job.name} must declare permissions`);
    }
  }
}

function workflowFiles(inputs) {
  const files = [];
  for (const input of inputs) {
    const metadata = fs.lstatSync(input);
    if (metadata.isSymbolicLink()) throw new Error(`${input}: symlinks are forbidden`);
    if (metadata.isDirectory()) {
      for (const name of fs.readdirSync(input).sort()) {
        if (/\.ya?ml$/.test(name)) files.push(path.join(input, name));
      }
    } else if (metadata.isFile()) {
      files.push(input);
    } else {
      throw new Error(`${input}: not a regular file or directory`);
    }
  }
  if (files.length === 0) throw new Error("no workflow files were selected");
  return files;
}

function main(argv = process.argv.slice(2)) {
  for (const file of workflowFiles(argv)) {
    const metadata = fs.lstatSync(file);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_WORKFLOW_BYTES) {
      throw new Error(`${file}: not a bounded regular workflow`);
    }
    verifyWorkflow(file, fs.readFileSync(file, "utf8"));
  }
}

if (require.main === module) {
  try { main(); } catch (error) {
    process.stderr.write(`workflow verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { jobBlocks, main, rejectQuotedMappingKeys, verifyWorkflow, workflowFiles };
