"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const zlib = require("node:zlib");
const { spawn } = require("node:child_process");

const SUPPORTED_COMMANDS = new Set([
  "plan",
  "release-pr",
  "rehearse",
  "verify",
  "release",
  "status",
  "doctor",
]);
const DOWNLOAD_LIMIT = 256 * 1024 * 1024;
const PROCESS_OUTPUT_LIMIT = 8 * 1024 * 1024;
const PROCESS_TIMEOUT_MS = 30 * 60 * 1000;
const SUPPORTED_ARCHIVES = Object.freeze([
  "release-glz-x86_64-unknown-linux-musl.tar.gz",
  "release-glz-aarch64-unknown-linux-musl.tar.gz",
  "release-glz-x86_64-apple-darwin.tar.gz",
  "release-glz-aarch64-apple-darwin.tar.gz",
  "release-glz-x86_64-pc-windows-msvc.zip",
  "release-glz-aarch64-pc-windows-msvc.zip",
]);

function targetFor(platform = process.platform, arch = process.arch) {
  const targets = {
    "linux:x64": ["x86_64-unknown-linux-musl", "tar.gz"],
    "linux:arm64": ["aarch64-unknown-linux-musl", "tar.gz"],
    "darwin:x64": ["x86_64-apple-darwin", "tar.gz"],
    "darwin:arm64": ["aarch64-apple-darwin", "tar.gz"],
    "win32:x64": ["x86_64-pc-windows-msvc", "zip"],
    "win32:arm64": ["aarch64-pc-windows-msvc", "zip"],
  };
  const target = targets[`${platform}:${arch}`];
  if (!target) throw new Error(`release-glz does not publish binaries for ${platform}/${arch}`);
  return target;
}

function normalizedVersion(input, actionRef, bundledVersion = require("./package.json").version) {
  const pattern = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
  const exactRef = pattern.test(actionRef || "") ? actionRef : "";
  const value = input || exactRef || bundledVersion;
  if (!pattern.test(value)) {
    throw new Error(
      `Cannot derive an immutable release-glz version from action ref ${JSON.stringify(value)}; set the version input`,
    );
  }
  return value.startsWith("v") ? value : `v${value}`;
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function expectedChecksum(checksums, filename) {
  for (const line of checksums.split(/\r?\n/)) {
    const match = line.trim().match(/^([a-fA-F0-9]{64})\s+\*?(.+)$/);
    if (match && match[2] === filename) return match[1].toLowerCase();
  }
  throw new Error(`SHA256SUMS does not contain ${filename}`);
}

function verifyChecksum(file, expected) {
  if (!/^[a-fA-F0-9]{64}$/.test(expected || "")) {
    throw new Error("Expected checksum must be a full SHA-256 digest");
  }
  const actual = sha256(file);
  const actualBytes = Buffer.from(actual, "hex");
  const expectedBytes = Buffer.from(expected, "hex");
  if (!crypto.timingSafeEqual(actualBytes, expectedBytes)) {
    throw new Error(`Checksum mismatch for ${path.basename(file)}: expected ${expected}, got ${actual}`);
  }
}

function bundledChecksum(source, version, filename) {
  if (typeof source !== "string" || Buffer.byteLength(source) > 64 * 1024) {
    throw new Error("Bundled checksum manifest exceeds its size limit");
  }
  let manifest;
  try { manifest = JSON.parse(source); } catch (error) {
    throw new Error(`Bundled checksum manifest is invalid JSON: ${error.message}`);
  }
  const keys = manifest && typeof manifest === "object" && !Array.isArray(manifest)
    ? Object.keys(manifest).sort()
    : [];
  if (keys.join(",") !== "artifacts,schema,version" ||
      manifest.schema !== "release-glz-action-checksums/v1") {
    throw new Error("Bundled checksum manifest has an unsupported schema");
  }
  if (manifest.version !== version) {
    throw new Error(`Bundled checksum manifest version ${manifest.version} does not match ${version}`);
  }
  if (!manifest.artifacts || typeof manifest.artifacts !== "object" || Array.isArray(manifest.artifacts)) {
    throw new Error("Bundled checksum manifest artifacts are invalid");
  }
  const names = Object.keys(manifest.artifacts).sort();
  const expectedNames = [...SUPPORTED_ARCHIVES].sort();
  if (names.length !== expectedNames.length || names.some((name, index) => name !== expectedNames[index])) {
    throw new Error("Bundled checksum manifest must cover every supported platform exactly once");
  }
  for (const [name, digest] of Object.entries(manifest.artifacts)) {
    if (!/^[a-f0-9]{64}$/.test(digest) || /^0{64}$/.test(digest)) {
      throw new Error(`Bundled checksum for ${name} is not a lowercase SHA-256 digest`);
    }
  }
  if (!SUPPORTED_ARCHIVES.includes(filename)) {
    throw new Error(`Archive ${filename} is not a supported release-glz platform`);
  }
  return manifest.artifacts[filename];
}

function verifyProvenance(file, expectedDigest, filename, archiveDigest) {
  const metadata = fs.lstatSync(file);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 1024 * 1024) {
    throw new Error("Provenance must be a regular file no larger than 1 MiB");
  }
  verifyChecksum(file, expectedDigest);
  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/).filter((line) => line.trim());
  if (lines.length !== 1) throw new Error("Provenance must contain exactly one JSON statement");
  let statement;
  try { statement = JSON.parse(lines[0]); } catch (error) {
    throw new Error(`Provenance is invalid JSON: ${error.message}`);
  }
  if (statement._type !== "https://in-toto.io/Statement/v1" ||
      statement.predicateType !== "https://slsa.dev/provenance/v1" ||
      !statement.predicate || typeof statement.predicate !== "object" ||
      !Array.isArray(statement.subject) || statement.subject.length !== 1 ||
      statement.subject[0]?.name !== filename ||
      statement.subject[0]?.digest?.sha256 !== archiveDigest) {
    throw new Error("Provenance subject does not bind the selected release archive");
  }
}

function isLoopback(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

function download(url, destination, options = {}) {
  const maxBytes = options.maxBytes ?? DOWNLOAD_LIMIT;
  const timeoutMs = options.timeoutMs ?? 60_000;
  const allowHttpLoopback = options.allowHttpLoopback === true;
  const redirects = options.redirects ?? 0;
  const initialOrigin = options.initialOrigin ?? new URL(url).origin;
  if (redirects > 8) return Promise.reject(new Error(`Too many redirects downloading ${url}`));

  const parsed = new URL(url);
  if (parsed.username || parsed.password) {
    return Promise.reject(new Error("Download URLs must not contain credentials"));
  }
  if (parsed.protocol !== "https:" && !(allowHttpLoopback && parsed.protocol === "http:" && isLoopback(parsed.hostname))) {
    return Promise.reject(new Error(`Download URL must use HTTPS: ${url}`));
  }
  if (parsed.origin !== initialOrigin) {
    return Promise.reject(new Error(`Refusing cross-origin redirect to ${parsed.origin}`));
  }
  const transport = parsed.protocol === "https:" ? https : http;

  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      try { fs.unlinkSync(destination); } catch (unlinkError) {
        if (unlinkError.code !== "ENOENT") error.message += `; cleanup failed: ${unlinkError.message}`;
      }
      reject(error);
    };
    const request = transport.get(parsed, {
      headers: { "user-agent": "release-glz-action" },
      timeout: timeoutMs,
    }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        const next = new URL(response.headers.location, parsed);
        if (next.origin !== initialOrigin) {
          fail(new Error(`Refusing cross-origin redirect from ${parsed.origin} to ${next.origin}`));
          return;
        }
        settled = true;
        download(next.toString(), destination, {
          maxBytes,
          timeoutMs,
          allowHttpLoopback,
          redirects: redirects + 1,
          initialOrigin,
        }).then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        fail(new Error(`Download failed with HTTP ${response.statusCode}: ${url}`));
        return;
      }
      const declared = Number(response.headers["content-length"] || 0);
      if (declared > maxBytes) {
        response.resume();
        fail(new Error(`Download exceeds the ${maxBytes} byte limit: ${url}`));
        return;
      }
      let received = 0;
      const output = fs.createWriteStream(destination, { flags: "wx", mode: 0o600 });
      output.on("error", fail);
      response.on("data", (chunk) => {
        received += chunk.length;
        if (received > maxBytes) {
          response.destroy(new Error(`Download exceeds the ${maxBytes} byte limit: ${url}`));
        }
      });
      response.on("error", fail);
      response.pipe(output);
      output.on("finish", () => {
        output.close((error) => {
          if (error) return fail(error);
          if (!settled) {
            settled = true;
            resolve();
          }
        });
      });
    });
    request.on("timeout", () => request.destroy(new Error(`Download timed out: ${url}`)));
    request.on("error", fail);
  });
}

function validateArchiveInventory(entries, limits = {}) {
  const maxEntries = limits.maxEntries ?? 32;
  const maxBytes = limits.maxBytes ?? DOWNLOAD_LIMIT;
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > maxEntries) {
    throw new Error(`Archive inventory exceeds the ${maxEntries} entry limit or is empty`);
  }
  const seen = new Set();
  let total = 0;
  for (const entry of entries) {
    const name = String(entry.path || "").replace(/\\/g, "/");
    const segments = name.split("/");
    if (
      !name || name.startsWith("/") || /^[A-Za-z]:\//.test(name) ||
      segments.some((segment) => segment === ".." || segment === "." || segment === "")
    ) {
      throw new Error(`Archive contains unsafe path ${JSON.stringify(name)}`);
    }
    if (!new Set(["file", "directory"]).has(entry.kind)) {
      throw new Error(`Archive contains unsupported ${entry.kind || "unknown"} entry ${name}`);
    }
    if (seen.has(name)) throw new Error(`Archive contains duplicate entry ${name}`);
    seen.add(name);
    const size = Number(entry.size);
    if (!Number.isSafeInteger(size) || size < 0) throw new Error(`Archive has invalid size for ${name}`);
    total += size;
    if (total > maxBytes) throw new Error(`Archive expands beyond the ${maxBytes} byte limit`);
  }
  return entries;
}

function terminateProcess(child, force = false) {
  if (!child || child.exitCode !== null) return;
  const signal = force ? "SIGKILL" : "SIGTERM";
  if (process.platform !== "win32" && child.pid) {
    try { process.kill(-child.pid, signal); } catch { child.kill(signal); }
  } else if (force && child.pid) {
    try {
      spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
        shell: false,
        windowsHide: true,
        stdio: "ignore",
      });
    } catch {
      child.kill();
    }
  } else {
    child.kill();
  }
}

function runProcess(executable, args, options = {}) {
  const timeoutMs = options.timeoutMs ?? PROCESS_TIMEOUT_MS;
  const terminateGraceMs = options.terminateGraceMs ?? 5_000;
  const maxOutputBytes = options.maxOutputBytes ?? PROCESS_OUTPUT_LIMIT;
  const child = spawn(executable, args, {
    cwd: options.cwd,
    env: options.env,
    shell: false,
    windowsHide: true,
    detached: process.platform !== "win32",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return new Promise((resolve, reject) => {
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let failure;
    let forceTimer;
    const stop = (error) => {
      if (failure) return;
      failure = error;
      terminateProcess(child, false);
      forceTimer = setTimeout(() => terminateProcess(child, true), terminateGraceMs);
    };
    const collect = (name, current, chunk) => {
      if (current.length + chunk.length > maxOutputBytes) {
        stop(new Error(`${name} exceeded the subprocess output limit`));
        return current;
      }
      return Buffer.concat([current, chunk]);
    };
    child.stdout.on("data", (chunk) => { stdout = collect("stdout", stdout, chunk); });
    child.stderr.on("data", (chunk) => {
      stderr = collect("stderr", stderr, chunk);
      if (options.streamStderr !== false) process.stderr.write(chunk);
    });
    child.on("error", stop);
    const timer = setTimeout(() => stop(new Error(`Subprocess timed out after ${timeoutMs}ms`)), timeoutMs);
    const abort = () => stop(new Error("Subprocess cancelled"));
    if (options.signal) {
      if (options.signal.aborted) abort();
      else options.signal.addEventListener("abort", abort, { once: true });
    }
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      clearTimeout(forceTimer);
      if (options.signal) options.signal.removeEventListener("abort", abort);
      if (failure) return reject(failure);
      if (code !== 0) {
        const error = new Error(`release-glz exited with status ${code ?? signal}`);
        error.exitCode = Number.isInteger(code) ? code : 1;
        error.stderr = stderr.toString("utf8");
        return reject(error);
      }
      resolve({ stdout: stdout.toString("utf8"), stderr: stderr.toString("utf8"), code });
    });
  });
}

function tarString(field) {
  const end = field.indexOf(0);
  const bytes = end === -1 ? field : field.subarray(0, end);
  const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (!value || /[\0\r\n]/.test(value)) throw new Error("Tar header contains an invalid path");
  return value;
}

function tarOctal(field, description) {
  if (field[0] & 0x80) throw new Error(`Tar ${description} uses unsupported base-256 encoding`);
  const value = field.toString("ascii").replace(/\0.*$/, "").trim();
  if (!value || !/^[0-7]+$/.test(value)) throw new Error(`Tar ${description} is not valid octal`);
  const parsed = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(parsed)) throw new Error(`Tar ${description} exceeds the safe integer range`);
  return parsed;
}

function parseTarHeader(header) {
  const expectedChecksum = tarOctal(header.subarray(148, 156), "checksum");
  let actualChecksum = 0;
  for (let index = 0; index < header.length; index += 1) {
    actualChecksum += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  if (actualChecksum !== expectedChecksum) throw new Error("Tar header checksum mismatch");
  const name = tarString(header.subarray(0, 100));
  const prefixBytes = header.subarray(345, 500);
  const prefix = prefixBytes.every((byte) => byte === 0) ? "" : tarString(prefixBytes);
  const entryPath = `${prefix ? `${prefix}/` : ""}${name}`.replace(/\/+$/, "");
  const type = header[156];
  let kind;
  if (type === 0 || type === 0x30) kind = "file";
  else if (type === 0x35) kind = "directory";
  else kind = "unsupported";
  const size = tarOctal(header.subarray(124, 136), "entry size");
  if (kind === "directory" && size !== 0) throw new Error(`Tar directory ${entryPath} has content`);
  return { path: entryPath, kind, size };
}

async function inventoryTarGz(archive, limits = {}) {
  const maxEntries = limits.maxEntries ?? 32;
  const maxBytes = limits.maxBytes ?? DOWNLOAD_LIMIT;
  const maxStreamBytes = maxBytes + (maxEntries * 1024) + 1024;
  const input = fs.createReadStream(archive);
  const gunzip = zlib.createGunzip();
  input.pipe(gunzip);
  const entries = [];
  let buffer = Buffer.alloc(0);
  let contentRemaining = 0;
  let paddingRemaining = 0;
  let zeroBlocks = 0;
  let ended = false;
  let streamBytes = 0;
  try {
    for await (const chunk of gunzip) {
      streamBytes += chunk.length;
      if (streamBytes > maxStreamBytes) throw new Error("Tar stream exceeds its bounded expansion size");
      buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
      while (buffer.length > 0) {
        if (ended) {
          if (buffer.some((byte) => byte !== 0)) throw new Error("Tar contains data after its end marker");
          buffer = Buffer.alloc(0);
          break;
        }
        if (contentRemaining > 0) {
          const consumed = Math.min(contentRemaining, buffer.length);
          buffer = buffer.subarray(consumed);
          contentRemaining -= consumed;
          continue;
        }
        if (paddingRemaining > 0) {
          const consumed = Math.min(paddingRemaining, buffer.length);
          buffer = buffer.subarray(consumed);
          paddingRemaining -= consumed;
          continue;
        }
        if (buffer.length < 512) break;
        const header = buffer.subarray(0, 512);
        buffer = buffer.subarray(512);
        if (header.every((byte) => byte === 0)) {
          zeroBlocks += 1;
          if (zeroBlocks === 2) ended = true;
          continue;
        }
        if (zeroBlocks !== 0) throw new Error("Tar has an incomplete end marker");
        const entry = parseTarHeader(header);
        entries.push(entry);
        validateArchiveInventory(entries, { maxEntries, maxBytes });
        contentRemaining = entry.size;
        paddingRemaining = (512 - (entry.size % 512)) % 512;
      }
    }
  } catch (error) {
    input.destroy();
    gunzip.destroy();
    throw error;
  }
  if (!ended || contentRemaining !== 0 || paddingRemaining !== 0 || buffer.length !== 0) {
    throw new Error("Tar archive is truncated or has no end marker");
  }
  return validateArchiveInventory(entries, { maxEntries, maxBytes });
}

function zipEntryKind(entryPath, externalAttributes) {
  const attributes = Number(externalAttributes) >>> 0;
  const unixType = (attributes >>> 16) & 0o170000;
  const reparsePoint = (attributes & 0x400) !== 0;
  if (reparsePoint) return "unsupported";
  if (unixType !== 0 && unixType !== 0o100000 && unixType !== 0o040000) {
    return "unsupported";
  }
  if (unixType === 0o040000 || entryPath.endsWith("/")) return "directory";
  return "file";
}

async function extract(archive, extension, destination) {
  fs.mkdirSync(destination, { recursive: false, mode: 0o700 });
  if (extension === "zip") {
    const inventoryScript = [
      "$a=[IO.Compression.ZipFile]::OpenRead($args[0]);",
      "try {$a.Entries | ForEach-Object { Write-Output ($_.FullName+'`t'+$_.Length+'`t'+$_.ExternalAttributes) }} finally {$a.Dispose()}",
    ].join(" ");
    const inventory = await runProcess("powershell", ["-NoProfile", "-NonInteractive", "-Command", inventoryScript, archive]);
    const entries = inventory.stdout.split(/\r?\n/).filter(Boolean).map((line) => {
      const [entryPath, size, externalAttributes] = line.split("\t");
      return {
        path: entryPath.replace(/\/$/, ""),
        kind: zipEntryKind(entryPath, externalAttributes),
        size: Number(size),
      };
    });
    validateArchiveInventory(entries);
    await runProcess("powershell", [
      "-NoProfile", "-NonInteractive", "-Command",
      "[IO.Compression.ZipFile]::ExtractToDirectory($args[0],$args[1],$false)", archive, destination,
    ]);
  } else {
    await inventoryTarGz(archive);
    await runProcess("tar", ["--extract", "--gzip", "--file", archive, "--directory", destination, "--no-same-owner", "--no-same-permissions"]);
  }
}

function setOutput(name, value, outputFile = process.env.GITHUB_OUTPUT) {
  if (!outputFile) return;
  const delimiter = `release_glz_${crypto.randomBytes(12).toString("hex")}`;
  fs.appendFileSync(outputFile, `${name}<<${delimiter}\n${value ?? ""}\n${delimiter}\n`, { encoding: "utf8" });
}

function buildCommandArgs(command, environment = process.env) {
  if (!SUPPORTED_COMMANDS.has(command)) {
    throw new Error(`command is required and must be one of: ${[...SUPPORTED_COMMANDS].join(", ")}`);
  }
  const args = [
    "--manifest-path", environment["INPUT_MANIFEST-PATH"] || "gleam.toml",
    "--output", "json",
  ];
  if ((environment["INPUT_DRY-RUN"] || "false").toLowerCase() === "true") args.push("--dry-run");
  args.push(command);
  const candidate = environment.INPUT_CANDIDATE;
  if (command === "rehearse") {
    const sourceRef = environment["INPUT_SOURCE-REF"];
    if (!/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/.test(sourceRef || "")) {
      throw new Error("rehearse requires source-ref to be a full lowercase commit SHA");
    }
    if (!candidate) throw new Error("rehearse requires the candidate output directory input");
    args.push("--ref", sourceRef, "--out", candidate);
  } else if (["verify", "release"].includes(command)) {
    if (!candidate) throw new Error(`${command} requires the candidate input`);
    args.push("--candidate", candidate);
    if (command === "verify" && (environment.INPUT_ONLINE || "false").toLowerCase() === "true") {
      args.push("--online");
    }
  } else if (command === "release-pr" && candidate) {
    args.push("--candidate", candidate);
  } else if (command === "status") {
    if (candidate) args.push("--candidate", candidate);
    if ((environment.INPUT_ONLINE || "false").toLowerCase() === "true") args.push("--online");
  }
  return args;
}

function parseCommandEnvelope(stdout) {
  let value;
  try { value = JSON.parse(stdout.trim()); } catch (error) {
    throw new Error(`release-glz returned invalid JSON: ${error.message}`);
  }
  if (
    !value || value.schema !== "command/v2" || typeof value.ok !== "boolean" ||
    typeof value.command !== "string" || !Array.isArray(value.diagnostics) ||
    !Array.isArray(value.next_actions)
  ) {
    throw new Error("release-glz output is not command/v2");
  }
  return value;
}

function resultOutputs(envelope) {
  const result = envelope.result || {};
  const candidate = result.candidate || {};
  return {
    state: result.state || candidate.state || "",
    "release-required": String(Boolean(result.release_required)),
    version: result.version || candidate.version || "",
    "intent-digest": result.intent_digest || candidate.intent_digest || "",
    "candidate-digest": result.candidate_digest || candidate.candidate_digest || "",
    "pr-url": result.pr_url || "",
    "hex-url": result.hex_url || "",
    "github-release-url": result.github_release_url || "",
    "next-action": envelope.next_actions[0]?.command || "",
  };
}

async function acquireBinary(environment = process.env) {
  if (environment.RELEASE_GLZ_BINARY) {
    return { binary: environment.RELEASE_GLZ_BINARY, cleanup: () => {} };
  }
  const [target, extension] = targetFor();
  const inputVersion = environment.INPUT_VERSION || "";
  const version = normalizedVersion(inputVersion, environment.GITHUB_ACTION_REF);
  if (inputVersion && (!environment["INPUT_BINARY-CHECKSUM"] || !environment.INPUT_PROVENANCE)) {
    throw new Error("An explicit version override requires binary-checksum and provenance inputs");
  }
  const repository = environment.GITHUB_ACTION_REPOSITORY || "P4suta/release-glz";
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    throw new Error("GITHUB_ACTION_REPOSITORY is unsafe");
  }
  const filename = `release-glz-${target}.${extension}`;
  const base = `https://github.com/${repository}/releases/download/${version}`;
  const temporary = fs.mkdtempSync(path.join(environment.RUNNER_TEMP || os.tmpdir(), "release-glz-action-"));
  const cleanup = () => fs.rmSync(temporary, { recursive: true, force: true });
  try {
    const archive = path.join(temporary, filename);
    let expected = environment["INPUT_BINARY-CHECKSUM"] || "";
    if (inputVersion) {
      const provenanceExpected = environment.INPUT_PROVENANCE;
      if (!/^[a-f0-9]{64}$/.test(expected) || !/^[a-f0-9]{64}$/.test(provenanceExpected)) {
        throw new Error("Explicit override checksum and provenance must be lowercase SHA-256 digests");
      }
      const provenance = path.join(temporary, `${filename}.intoto.jsonl`);
      await Promise.all([
        download(`${base}/${filename}`, archive),
        download(`${base}/${filename}.intoto.jsonl`, provenance, { maxBytes: 1024 * 1024 }),
      ]);
      verifyChecksum(archive, expected);
      verifyProvenance(provenance, provenanceExpected, filename, expected);
    } else {
      expected = bundledChecksum(
        fs.readFileSync(path.join(__dirname, "checksums.json"), "utf8"),
        version,
        filename,
      );
      await download(`${base}/${filename}`, archive);
      verifyChecksum(archive, expected);
    }
    const destination = path.join(temporary, "bin");
    await extract(archive, extension, destination);
    const binaryName = process.platform === "win32" ? "release-glz.exe" : "release-glz";
    const binary = path.join(destination, binaryName);
    const metadata = fs.lstatSync(binary);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`Archive did not contain a regular ${binaryName}`);
    }
    fs.chmodSync(binary, 0o755);
    return { binary, cleanup };
  } catch (error) {
    cleanup();
    throw error;
  }
}

async function main(environment = process.env) {
  const command = environment.INPUT_COMMAND;
  const args = buildCommandArgs(command, environment);
  const acquired = await acquireBinary(environment);
  const controller = new AbortController();
  const cancel = () => controller.abort();
  process.once("SIGINT", cancel);
  process.once("SIGTERM", cancel);
  try {
    const childEnvironment = { ...environment };
    if (environment["INPUT_GITHUB-TOKEN"]) childEnvironment.GITHUB_TOKEN = environment["INPUT_GITHUB-TOKEN"];
    const timeoutSeconds = Number(environment["INPUT_TIMEOUT-SECONDS"] || 1800);
    if (!Number.isSafeInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 3600) {
      throw new Error("timeout-seconds must be between 1 and 3600");
    }
    const result = await runProcess(acquired.binary, args, {
      env: childEnvironment,
      timeoutMs: timeoutSeconds * 1000,
      maxOutputBytes: PROCESS_OUTPUT_LIMIT,
      signal: controller.signal,
    });
    const envelope = parseCommandEnvelope(result.stdout);
    for (const [name, value] of Object.entries(resultOutputs(envelope))) {
      setOutput(name, value, environment.GITHUB_OUTPUT);
    }
    process.stdout.write(`${JSON.stringify(envelope)}\n`);
    return envelope;
  } finally {
    process.removeListener("SIGINT", cancel);
    process.removeListener("SIGTERM", cancel);
    acquired.cleanup();
  }
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`release-glz action failed: ${error.message}\n`);
    process.exitCode = error.exitCode || 1;
  });
}

module.exports = {
  acquireBinary,
  buildCommandArgs,
  bundledChecksum,
  download,
  expectedChecksum,
  inventoryTarGz,
  main,
  normalizedVersion,
  parseCommandEnvelope,
  resultOutputs,
  runProcess,
  setOutput,
  sha256,
  targetFor,
  validateArchiveInventory,
  verifyChecksum,
  verifyProvenance,
  zipEntryKind,
};
