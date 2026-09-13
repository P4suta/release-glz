#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const KIB = 1024;
const MIB = 1024 * KIB;

const MAX_WORKFLOW_BYTES = MIB;

// A container action pinned by image digest.
const CONTAINER_DIGEST = /@sha256:[a-f0-9]{64}$/;

// A git object id, in either case, as an action reference may carry it.
const GIT_OBJECT_HEX = /^[a-f0-9]{40}$/i;

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
      if (!CONTAINER_DIGEST.test(reference)) {
        throw new Error(`${filename}: container action must use a sha256 digest`);
      }
      continue;
    }
    const separator = reference.lastIndexOf("@");
    if (separator < 1 || !GIT_OBJECT_HEX.test(reference.slice(separator + 1))) {
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
    requireExplicitShell(filename, job);
  }
}

// Reject a `run` step that expands a POSIX variable while leaving its shell to
// the runner, when the runner is not fixed to one operating system. PowerShell
// is the default on Windows and does not expand `$NAME`, so such a step reads
// an empty value there instead of failing loudly.
function requireExplicitShell(filename, job) {
  const runsOn = job.source.match(/^\s+runs-on:\s*(.+?)\s*(?:#.*)?$/m);
  if (!runsOn) return;
  const varies = runsOn[1].includes("${{") || /windows/i.test(runsOn[1]);
  if (!varies) return;

  const lines = job.source.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    if (!/^\s+run:\s*\S/.test(lines[index]) && !/^\s+run:\s*[|>]/.test(lines[index])) continue;
    let start = index;
    while (start > 0 && !/^\s*-\s+\S/.test(lines[start])) start -= 1;
    const stepIndent = indentation(lines[start]);
    let end = start + 1;
    while (end < lines.length &&
      (!/^\s*-\s+\S/.test(lines[end]) || indentation(lines[end]) > stepIndent)) end += 1;
    const step = lines.slice(start, end).join("\n");
    const posix = step.replace(/\$\{\{[^}]*\}\}/g, "");
    if (!/\$[A-Za-z_{]/.test(posix)) {
      index = end - 1;
      continue;
    }
    if (!/^\s+(?:-\s+)?shell:\s*\S/m.test(step)) {
      throw new Error(
        `${filename}: job ${job.name} expands a POSIX variable on a runner that varies, so its run step must set shell`,
      );
    }
    index = end - 1;
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

module.exports = {
  jobBlocks,
  main,
  rejectQuotedMappingKeys,
  requireExplicitShell,
  verifyWorkflow,
  workflowFiles,
};
