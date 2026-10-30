// @ts-check
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
// Byte-size units, so a limit reads as a count rather than a product of 1024s.
const KIB = 1024;
const MIB = 1024 * KIB;
const SECOND_MS = 1000;
const MINUTE_MS = 60 * SECOND_MS;

const DOWNLOAD_LIMIT = 256 * MIB;
const PROCESS_OUTPUT_LIMIT = 8 * MIB;
const PROCESS_TIMEOUT_MS = 30 * MINUTE_MS;

/// The hexadecimal form of a SHA-256 digest, lowercase as every manifest records it, and in either case where a third party wrote it.
const SHA256_HEX = /^[a-f0-9]{64}$/;
const SHA256_HEX_ANY_CASE = /^[a-fA-F0-9]{64}$/;

/// A digest of nothing but zeroes, which is what the checksum manifest carries until a release fills it in.
const SHA256_HEX_ZEROED = /^0{64}$/;

/// A git object id: the SHA-1 form git writes today, or the SHA-256 form a migrated repository writes.
const GIT_OBJECT_HEX = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/;

/// Size the checksum manifest and a `SHA256SUMS` file may reach.
const CHECKSUM_MANIFEST_LIMIT = MIB;
const CHECKSUM_LIST_LIMIT = 64 * KIB;

/// Entries an archive this Action unpacks may contain.
const ARCHIVE_ENTRY_LIMIT = 32;

/// Milliseconds a download connection may stay silent before it is abandoned.
const DOWNLOAD_TIMEOUT_MS = 60 * SECOND_MS;

/// Milliseconds one download may take in total, across its redirects, however steadily the server sends.
const DOWNLOAD_TOTAL_TIMEOUT_MS = 10 * MINUTE_MS;

/// Milliseconds a terminated child is given to exit before it is killed.
const TERMINATE_GRACE_MS = 5 * SECOND_MS;

/// Random bytes in the token that resumes workflow commands, which output from release-glz can't guess.
const WORKFLOW_COMMAND_TOKEN_BYTES = 16;

/// Bounds on the `timeout-seconds` input, matching the manifest's hook bounds.
const MIN_TIMEOUT_SECONDS = 1;
const MAX_TIMEOUT_SECONDS = 3600;
const DEFAULT_TIMEOUT_SECONDS = 1800;

/// HTTP status codes this client distinguishes.
const HTTP_OK = 200;
const HTTP_REDIRECT_MIN = 300;
const HTTP_REDIRECT_MAX = 400;

/// POSIX ustar header layout, in bytes.
const TAR_BLOCK_BYTES = 512;
const TAR_NAME_END = 100;
const TAR_SIZE_START = 124;
const TAR_SIZE_END = 136;
const TAR_CHECKSUM_START = 148;
const TAR_CHECKSUM_END = 156;
const TAR_TYPE_OFFSET = 156;
const TAR_PREFIX_START = 345;
const TAR_PREFIX_END = 500;
const TAR_CHECKSUM_BLANK = 0x20;
const TAR_BASE256_FLAG = 0x80;
const TAR_TYPE_FILE_ALTERNATE = 0x30;
const TAR_TYPE_DIRECTORY = 0x35;
const OCTAL_RADIX = 8;
const SUPPORTED_ARCHIVES = Object.freeze([
  "release-glz-x86_64-unknown-linux-musl.tar.gz",
  "release-glz-aarch64-unknown-linux-musl.tar.gz",
  "release-glz-x86_64-apple-darwin.tar.gz",
  "release-glz-aarch64-apple-darwin.tar.gz",
  "release-glz-x86_64-pc-windows-msvc.zip",
  "release-glz-aarch64-pc-windows-msvc.zip",
]);

/** @typedef {"tar.gz" | "zip"} ArchiveExtension */

/**
 * Where the Action writes text or relayed bytes, such as `process.stdout`.
 * @typedef {{write(chunk: string | Uint8Array): unknown}} OutputSink
 */

/**
 * The release target and archive format for a runner platform.
 * @param {string} platform
 * @param {string} arch
 * @returns {[string, ArchiveExtension]}
 */
function targetFor(platform = process.platform, arch = process.arch) {
  /** @type {Record<string, [string, ArchiveExtension]>} */
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

/**
 * The `vX.Y.Z` release to install: the input, an exact Action ref, or the bundled version.
 * @param {string | undefined} input
 * @param {string | undefined} actionRef
 * @param {string} bundledVersion
 * @returns {string}
 */
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

/**
 * @param {string} file
 * @returns {string}
 */
function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

/**
 * The lowercase digest that a `SHA256SUMS` listing records for `filename`.
 * @param {string} checksums
 * @param {string} filename
 * @returns {string}
 */
function expectedChecksum(checksums, filename) {
  for (const line of checksums.split(/\r?\n/)) {
    const [, digest, name] = line.trim().match(/^([a-fA-F0-9]{64})\s+\*?(.+)$/) ?? [];
    if (digest !== undefined && name === filename) return digest.toLowerCase();
  }
  throw new Error(`SHA256SUMS does not contain ${filename}`);
}

/**
 * @param {string} file
 * @param {string | undefined} expected
 * @returns {void}
 */
function verifyChecksum(file, expected) {
  const digest = expected || "";
  if (!SHA256_HEX_ANY_CASE.test(digest)) {
    throw new Error("Expected checksum must be a full SHA-256 digest");
  }
  const actual = sha256(file);
  const actualBytes = Buffer.from(actual, "hex");
  const expectedBytes = Buffer.from(digest, "hex");
  if (!crypto.timingSafeEqual(actualBytes, expectedBytes)) {
    throw new Error(
      `Checksum mismatch for ${path.basename(file)}: expected ${digest}, got ${actual}`,
    );
  }
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * @param {unknown} error
 * @returns {string}
 */
function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

/**
 * The digest that the bundled checksum manifest records for one archive of `version`.
 * @param {unknown} source
 * @param {string} version
 * @param {string} filename
 * @returns {string}
 */
function bundledChecksum(source, version, filename) {
  if (typeof source !== "string" || Buffer.byteLength(source) > CHECKSUM_LIST_LIMIT) {
    throw new Error("Bundled checksum manifest exceeds its size limit");
  }
  /** @type {unknown} */
  let manifest;
  try {
    manifest = JSON.parse(source);
  } catch (error) {
    throw new Error(`Bundled checksum manifest is invalid JSON: ${errorMessage(error)}`);
  }
  if (
    !isRecord(manifest) ||
    Object.keys(manifest).sort().join(",") !== "artifacts,schema,version" ||
    manifest.schema !== "release-glz-action-checksums/v1"
  ) {
    throw new Error("Bundled checksum manifest has an unsupported schema");
  }
  if (manifest.version !== version) {
    throw new Error(
      `Bundled checksum manifest version ${manifest.version} does not match ${version}`,
    );
  }
  const artifacts = manifest.artifacts;
  if (!isRecord(artifacts)) {
    throw new Error("Bundled checksum manifest artifacts are invalid");
  }
  const names = Object.keys(artifacts).sort();
  const expectedNames = [...SUPPORTED_ARCHIVES].sort();
  if (
    names.length !== expectedNames.length ||
    names.some((name, index) => name !== expectedNames[index])
  ) {
    throw new Error("Bundled checksum manifest must cover every supported platform exactly once");
  }
  for (const [name, digest] of Object.entries(artifacts)) {
    if (typeof digest !== "string" || !SHA256_HEX.test(digest) || SHA256_HEX_ZEROED.test(digest)) {
      throw new Error(`Bundled checksum for ${name} is not a lowercase SHA-256 digest`);
    }
  }
  const digest = artifacts[filename];
  if (!SUPPORTED_ARCHIVES.includes(filename) || typeof digest !== "string") {
    throw new Error(`Archive ${filename} is not a supported release-glz platform`);
  }
  return digest;
}

/**
 * Refuse a provenance file unless it has the expected digest and binds `filename` to `archiveDigest`.
 * @param {string} file
 * @param {string} expectedDigest
 * @param {string} filename
 * @param {string} archiveDigest
 * @returns {void}
 */
function verifyProvenance(file, expectedDigest, filename, archiveDigest) {
  const metadata = fs.lstatSync(file);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > CHECKSUM_MANIFEST_LIMIT) {
    throw new Error("Provenance must be a regular file no larger than 1 MiB");
  }
  verifyChecksum(file, expectedDigest);
  const lines = fs
    .readFileSync(file, "utf8")
    .split(/\r?\n/)
    .filter((line) => line.trim());
  const [line] = lines;
  if (lines.length !== 1 || line === undefined) {
    throw new Error("Provenance must contain exactly one JSON statement");
  }
  /** @type {unknown} */
  let statement;
  try {
    statement = JSON.parse(line);
  } catch (error) {
    throw new Error(`Provenance is invalid JSON: ${errorMessage(error)}`);
  }
  const subjects = isRecord(statement) ? statement.subject : undefined;
  /** @type {unknown} */
  const subject = Array.isArray(subjects) && subjects.length === 1 ? subjects[0] : undefined;
  const subjectDigest = isRecord(subject) && isRecord(subject.digest) ? subject.digest : undefined;
  if (
    !isRecord(statement) ||
    statement._type !== "https://in-toto.io/Statement/v1" ||
    statement.predicateType !== "https://slsa.dev/provenance/v1" ||
    !statement.predicate ||
    typeof statement.predicate !== "object" ||
    !isRecord(subject) ||
    subject.name !== filename ||
    subjectDigest?.sha256 !== archiveDigest
  ) {
    throw new Error("Provenance subject does not bind the selected release archive");
  }
}

/**
 * @param {string} hostname
 * @returns {boolean}
 */
function isLoopback(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

const GITHUB_RELEASE_ASSET_HOSTS = new Set([
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
]);

/**
 * Whether a download that started at `initial` may follow a redirect to `target`.
 * @param {string | URL} initial
 * @param {string | URL} target
 * @returns {boolean}
 */
function isAllowedDownloadRedirect(initial, target) {
  const initialUrl = initial instanceof URL ? initial : new URL(initial);
  const targetUrl = target instanceof URL ? target : new URL(target);
  if (targetUrl.origin === initialUrl.origin) return true;
  return (
    initialUrl.protocol === "https:" &&
    initialUrl.hostname === "github.com" &&
    initialUrl.port === "" &&
    targetUrl.protocol === "https:" &&
    targetUrl.port === "" &&
    GITHUB_RELEASE_ASSET_HOSTS.has(targetUrl.hostname)
  );
}

/**
 * @typedef {object} DownloadOptions
 * @property {number} [maxBytes] Bytes the response body may hold.
 * @property {number} [timeoutMs] Milliseconds the connection may stay silent.
 * @property {number} [totalTimeoutMs] Milliseconds the download may take across its redirects.
 * @property {number} [deadline] Epoch milliseconds the download has to finish by.
 * @property {boolean} [allowHttpLoopback] Whether a loopback URL may use plain HTTP.
 * @property {number} [redirects] Redirects already followed.
 * @property {string | URL} [initialUrl] URL the download started from.
 */

/**
 * Download `url` into a new file at `destination`, following only redirects that stay at the origin or move to GitHub's release asset hosts.
 * @param {string} url
 * @param {string} destination
 * @param {DownloadOptions} options
 * @returns {Promise<void>}
 */
function download(url, destination, options = {}) {
  const maxBytes = options.maxBytes ?? DOWNLOAD_LIMIT;
  const timeoutMs = options.timeoutMs ?? DOWNLOAD_TIMEOUT_MS;
  const totalTimeoutMs = options.totalTimeoutMs ?? DOWNLOAD_TOTAL_TIMEOUT_MS;
  const deadline = options.deadline ?? Date.now() + totalTimeoutMs;
  const allowHttpLoopback = options.allowHttpLoopback === true;
  const redirects = options.redirects ?? 0;
  const initialUrl = options.initialUrl ?? url;
  if (redirects > 8) return Promise.reject(new Error(`Too many redirects downloading ${url}`));

  const parsed = new URL(url);
  if (parsed.username || parsed.password) {
    return Promise.reject(new Error("Download URLs must not contain credentials"));
  }
  if (
    parsed.protocol !== "https:" &&
    !(allowHttpLoopback && parsed.protocol === "http:" && isLoopback(parsed.hostname))
  ) {
    return Promise.reject(new Error(`Download URL must use HTTPS: ${url}`));
  }
  if (!isAllowedDownloadRedirect(initialUrl, parsed)) {
    return Promise.reject(new Error(`Refusing cross-origin redirect to ${parsed.origin}`));
  }
  const transport = parsed.protocol === "https:" ? https : http;

  return new Promise((resolve, reject) => {
    let settled = false;
    /** @type {NodeJS.Timeout | undefined} */
    let deadlineTimer;
    /** @param {Error} error */
    const fail = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadlineTimer);
      try {
        fs.unlinkSync(destination);
      } catch (unlinkError) {
        if (
          !(unlinkError instanceof Error && "code" in unlinkError && unlinkError.code === "ENOENT")
        )
          error.message += `; cleanup failed: ${errorMessage(unlinkError)}`;
      }
      reject(error);
    };
    const request = transport.get(
      parsed,
      {
        headers: { "user-agent": "release-glz-action" },
        timeout: timeoutMs,
      },
      (response) => {
        const status = response.statusCode ?? 0;
        if (
          status >= HTTP_REDIRECT_MIN &&
          status < HTTP_REDIRECT_MAX &&
          response.headers.location
        ) {
          response.resume();
          const next = new URL(response.headers.location, parsed);
          if (!isAllowedDownloadRedirect(initialUrl, next)) {
            fail(
              new Error(`Refusing cross-origin redirect from ${parsed.origin} to ${next.origin}`),
            );
            return;
          }
          settled = true;
          clearTimeout(deadlineTimer);
          download(next.toString(), destination, {
            maxBytes,
            timeoutMs,
            totalTimeoutMs,
            deadline,
            allowHttpLoopback,
            redirects: redirects + 1,
            initialUrl,
          }).then(resolve, reject);
          return;
        }
        if (status !== HTTP_OK) {
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
        response.on("data", (/** @type {Buffer} */ chunk) => {
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
              clearTimeout(deadlineTimer);
              resolve();
            }
          });
        });
      },
    );
    request.on("timeout", () => request.destroy(new Error(`Download timed out: ${url}`)));
    request.on("error", fail);
    // The idle timeout above ends only a silent connection, so a server that trickles bytes needs this total deadline across redirects.
    deadlineTimer = setTimeout(
      () => request.destroy(new Error(`Download passed its ${totalTimeoutMs} ms deadline: ${url}`)),
      Math.max(deadline - Date.now(), 0),
    );
  });
}

/**
 * One entry of an archive inventory.
 * @typedef {object} ArchiveEntry
 * @property {string} path Path inside the archive, with `/` separators.
 * @property {string} kind `file` or `directory` for an entry this Action extracts.
 * @property {number} size Bytes the entry expands to.
 */

/**
 * @typedef {object} ArchiveLimits
 * @property {number} [maxEntries] Entries the archive may hold.
 * @property {number} [maxBytes] Bytes its entries may expand to in total.
 */

/**
 * Refuse an inventory with an unsafe path, an entry that isn't a file or directory, a duplicate, or one beyond the limits.
 * @param {ArchiveEntry[]} entries
 * @param {ArchiveLimits} limits
 * @returns {ArchiveEntry[]}
 */
function validateArchiveInventory(entries, limits = {}) {
  const maxEntries = limits.maxEntries ?? ARCHIVE_ENTRY_LIMIT;
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
      !name ||
      name.startsWith("/") ||
      /^[A-Za-z]:\//.test(name) ||
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
    if (!Number.isSafeInteger(size) || size < 0)
      throw new Error(`Archive has invalid size for ${name}`);
    total += size;
    if (total > maxBytes) throw new Error(`Archive expands beyond the ${maxBytes} byte limit`);
  }
  return entries;
}

/**
 * Signal a child and, on Unix, its process group.
 * @param {import("node:child_process").ChildProcess} child
 * @param {boolean} force
 * @returns {void}
 */
function terminateProcess(child, force = false) {
  if (!child || child.exitCode !== null) return;
  const signal = force ? "SIGKILL" : "SIGTERM";
  if (process.platform !== "win32" && child.pid) {
    try {
      process.kill(-child.pid, signal);
    } catch {
      child.kill(signal);
    }
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

/**
 * @typedef {object} ProcessOptions
 * @property {number} [timeoutMs] Milliseconds the child may run.
 * @property {number} [terminateGraceMs] Milliseconds a terminated child has before it is killed.
 * @property {number} [maxOutputBytes] Bytes each output stream may hold.
 * @property {string} [cwd]
 * @property {NodeJS.ProcessEnv} [env]
 * @property {AbortSignal} [signal] Cancels the child.
 * @property {boolean} [streamStderr] Whether to relay the child's stderr as it arrives.
 * @property {OutputSink} [stderr] Stream that relays the child's stderr.
 */

/** @typedef {{stdout: string, stderr: string, code: number | null}} ProcessResult */

/** A child that exited with a status other than 0, with what it printed. */
class ProcessExitError extends Error {
  /**
   * @param {string} message
   * @param {number} exitCode
   * @param {string} stdout
   * @param {string} stderr
   */
  constructor(message, exitCode, stdout, stderr) {
    super(message);
    this.exitCode = exitCode;
    this.stdout = stdout;
    this.stderr = stderr;
  }
}

/**
 * Run `executable` without a shell, bounded in time and output, and reject unless it exits with status 0.
 * @param {string} executable
 * @param {string[]} args
 * @param {ProcessOptions} options
 * @returns {Promise<ProcessResult>}
 */
function runProcess(executable, args, options = {}) {
  const timeoutMs = options.timeoutMs ?? PROCESS_TIMEOUT_MS;
  const terminateGraceMs = options.terminateGraceMs ?? TERMINATE_GRACE_MS;
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
    /** @type {Buffer} */
    let stdout = Buffer.alloc(0);
    /** @type {Buffer} */
    let stderr = Buffer.alloc(0);
    /** @type {Error | undefined} */
    let failure;
    /** @type {NodeJS.Timeout | undefined} */
    let forceTimer;
    /** @param {Error} error */
    const stop = (error) => {
      if (failure) return;
      failure = error;
      terminateProcess(child, false);
      forceTimer = setTimeout(() => terminateProcess(child, true), terminateGraceMs);
    };
    /**
     * @param {string} name
     * @param {Buffer} current
     * @param {Buffer} chunk
     * @returns {Buffer}
     */
    const collect = (name, current, chunk) => {
      if (current.length + chunk.length > maxOutputBytes) {
        stop(new Error(`${name} exceeded the subprocess output limit`));
        return current;
      }
      return Buffer.concat([current, chunk]);
    };
    child.stdout.on("data", (/** @type {Buffer} */ chunk) => {
      stdout = collect("stdout", stdout, chunk);
    });
    child.stderr.on("data", (/** @type {Buffer} */ chunk) => {
      stderr = collect("stderr", stderr, chunk);
      if (options.streamStderr !== false) (options.stderr ?? process.stderr).write(chunk);
    });
    child.on("error", stop);
    const timer = setTimeout(
      () => stop(new Error(`Subprocess timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
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
        return reject(
          new ProcessExitError(
            `release-glz exited with status ${code ?? signal}`,
            typeof code === "number" ? code : 1,
            stdout.toString("utf8"),
            stderr.toString("utf8"),
          ),
        );
      }
      resolve({ stdout: stdout.toString("utf8"), stderr: stderr.toString("utf8"), code });
    });
  });
}

/**
 * @param {Buffer} field
 * @returns {string}
 */
function tarString(field) {
  const end = field.indexOf(0);
  const bytes = end === -1 ? field : field.subarray(0, end);
  const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (!value || /[\0\r\n]/.test(value)) throw new Error("Tar header contains an invalid path");
  return value;
}

/**
 * @param {Buffer} field
 * @param {string} description
 * @returns {number}
 */
function tarOctal(field, description) {
  if ((field[0] ?? 0) & TAR_BASE256_FLAG)
    throw new Error(`Tar ${description} uses unsupported base-256 encoding`);
  const value = field.toString("ascii").replace(/\0.*$/, "").trim();
  if (!value || !/^[0-7]+$/.test(value)) throw new Error(`Tar ${description} is not valid octal`);
  const parsed = Number.parseInt(value, OCTAL_RADIX);
  if (!Number.isSafeInteger(parsed))
    throw new Error(`Tar ${description} exceeds the safe integer range`);
  return parsed;
}

/**
 * @param {Buffer} header
 * @returns {ArchiveEntry}
 */
function parseTarHeader(header) {
  const expectedChecksum = tarOctal(
    header.subarray(TAR_CHECKSUM_START, TAR_CHECKSUM_END),
    "checksum",
  );
  let actualChecksum = 0;
  for (const [index, byte] of header.entries()) {
    actualChecksum +=
      index >= TAR_CHECKSUM_START && index < TAR_CHECKSUM_END ? TAR_CHECKSUM_BLANK : byte;
  }
  if (actualChecksum !== expectedChecksum) throw new Error("Tar header checksum mismatch");
  const name = tarString(header.subarray(0, TAR_NAME_END));
  const prefixBytes = header.subarray(TAR_PREFIX_START, TAR_PREFIX_END);
  const prefix = prefixBytes.every((byte) => byte === 0) ? "" : tarString(prefixBytes);
  const entryPath = `${prefix ? `${prefix}/` : ""}${name}`.replace(/\/+$/, "");
  const type = header[TAR_TYPE_OFFSET];
  /** @type {string} */
  let kind;
  if (type === 0 || type === TAR_TYPE_FILE_ALTERNATE) kind = "file";
  else if (type === TAR_TYPE_DIRECTORY) kind = "directory";
  else kind = "unsupported";
  const size = tarOctal(header.subarray(TAR_SIZE_START, TAR_SIZE_END), "entry size");
  if (kind === "directory" && size !== 0) throw new Error(`Tar directory ${entryPath} has content`);
  return { path: entryPath, kind, size };
}

/**
 * The inventory of a gzip-compressed tar, read from its headers within the limits.
 * @param {string} archive
 * @param {ArchiveLimits} limits
 * @returns {Promise<ArchiveEntry[]>}
 */
async function inventoryTarGz(archive, limits = {}) {
  const maxEntries = limits.maxEntries ?? ARCHIVE_ENTRY_LIMIT;
  const maxBytes = limits.maxBytes ?? DOWNLOAD_LIMIT;
  const maxStreamBytes = maxBytes + maxEntries * KIB + KIB;
  const input = fs.createReadStream(archive);
  const gunzip = zlib.createGunzip();
  input.pipe(gunzip);
  /** @type {ArchiveEntry[]} */
  const entries = [];
  /** @type {Buffer} */
  let buffer = Buffer.alloc(0);
  let contentRemaining = 0;
  let paddingRemaining = 0;
  let zeroBlocks = 0;
  let ended = false;
  let streamBytes = 0;
  try {
    for await (const decompressed of gunzip) {
      /** @type {Buffer} */
      const chunk = decompressed;
      streamBytes += chunk.length;
      if (streamBytes > maxStreamBytes)
        throw new Error("Tar stream exceeds its bounded expansion size");
      buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
      while (buffer.length > 0) {
        if (ended) {
          if (buffer.some((byte) => byte !== 0))
            throw new Error("Tar contains data after its end marker");
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
        if (buffer.length < TAR_BLOCK_BYTES) break;
        const header = buffer.subarray(0, TAR_BLOCK_BYTES);
        buffer = buffer.subarray(TAR_BLOCK_BYTES);
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
        paddingRemaining = (TAR_BLOCK_BYTES - (entry.size % TAR_BLOCK_BYTES)) % TAR_BLOCK_BYTES;
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

/**
 * Whether a ZIP entry is a file, a directory, or something this Action refuses, from its Unix mode and Windows attributes.
 * @param {string} entryPath
 * @param {unknown} externalAttributes
 * @returns {"file" | "directory" | "unsupported"}
 */
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

// Windows PowerShell runs on .NET Framework, which loads ZipFile only on request and has no overwrite overload.
const WINDOWS_ZIP_ASSEMBLY = "Add-Type -AssemblyName System.IO.Compression.FileSystem;";

/** @returns {string} */
function windowsZipInventoryScript() {
  return [
    WINDOWS_ZIP_ASSEMBLY,
    "$a=[IO.Compression.ZipFile]::OpenRead($env:RELEASE_GLZ_ARCHIVE);",
    "try {$a.Entries | ForEach-Object { Write-Output ($_.FullName+[char]9+$_.Length+[char]9+$_.ExternalAttributes) }} finally {$a.Dispose()}",
  ].join(" ");
}

/** @returns {string} */
function windowsZipExtractScript() {
  return [
    WINDOWS_ZIP_ASSEMBLY,
    "[IO.Compression.ZipFile]::ExtractToDirectory($env:RELEASE_GLZ_ARCHIVE,$env:RELEASE_GLZ_DESTINATION)",
  ].join(" ");
}

/**
 * Extract a release archive into a new directory after checking its inventory.
 * @param {string} archive
 * @param {ArchiveExtension} extension
 * @param {string} destination
 * @returns {Promise<void>}
 */
async function extract(archive, extension, destination) {
  fs.mkdirSync(destination, { recursive: false, mode: 0o700 });
  if (extension === "zip") {
    const powershellEnvironment = {
      ...process.env,
      RELEASE_GLZ_ARCHIVE: archive,
      RELEASE_GLZ_DESTINATION: destination,
    };
    const inventory = await runProcess(
      "powershell",
      ["-NoProfile", "-NonInteractive", "-Command", windowsZipInventoryScript()],
      { env: powershellEnvironment },
    );
    const entries = inventory.stdout
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => {
        const [entryPath = "", size, externalAttributes] = line.split("\t");
        return {
          path: entryPath.replace(/\/$/, ""),
          kind: zipEntryKind(entryPath, externalAttributes),
          size: Number(size),
        };
      });
    validateArchiveInventory(entries);
    await runProcess(
      "powershell",
      ["-NoProfile", "-NonInteractive", "-Command", windowsZipExtractScript()],
      { env: powershellEnvironment },
    );
  } else {
    await inventoryTarGz(archive);
    await runProcess("tar", [
      "--extract",
      "--gzip",
      "--file",
      archive,
      "--directory",
      destination,
      "--no-same-owner",
      "--no-same-permissions",
    ]);
  }
}

/**
 * Append one step output under a random delimiter, so its value can't end the output early.
 * @param {string} name
 * @param {string | undefined} value
 * @param {string | undefined} outputFile
 * @returns {void}
 */
function setOutput(name, value, outputFile = process.env.GITHUB_OUTPUT) {
  if (!outputFile) return;
  const delimiter = `release_glz_${crypto.randomBytes(12).toString("hex")}`;
  fs.appendFileSync(outputFile, `${name}<<${delimiter}\n${value ?? ""}\n${delimiter}\n`, {
    encoding: "utf8",
  });
}

/**
 * @param {NodeJS.ProcessEnv} environment
 * @param {string} name
 * @returns {boolean}
 */
function booleanInput(environment, name) {
  const key = `INPUT_${name.toUpperCase()}`;
  const value = (environment[key] || "false").toLowerCase();
  if (value !== "true" && value !== "false") {
    throw new Error(`${name.toLowerCase()} must be true or false`);
  }
  return value === "true";
}

/**
 * The release-glz arguments for `command`, refusing an input that the command doesn't take.
 * @param {string | undefined} command
 * @param {NodeJS.ProcessEnv} environment
 * @returns {string[]}
 */
function buildCommandArgs(command, environment = process.env) {
  if (command === undefined || !SUPPORTED_COMMANDS.has(command)) {
    throw new Error(
      `command is required and must be one of: ${[...SUPPORTED_COMMANDS].join(", ")}`,
    );
  }
  const args = [
    "--manifest-path",
    environment["INPUT_MANIFEST-PATH"] || "gleam.toml",
    "--output",
    "json",
  ];
  args.push(command);
  const dryRun = booleanInput(environment, "DRY-RUN");
  if (dryRun && !new Set(["release", "release-pr"]).has(command)) {
    throw new Error(`dry-run is not supported by the ${command} command`);
  }
  if (dryRun) args.push("--dry-run");
  const online = booleanInput(environment, "ONLINE");
  if (online && !new Set(["verify", "status", "doctor"]).has(command)) {
    throw new Error(`online is not supported by the ${command} command`);
  }
  const candidate = environment.INPUT_CANDIDATE;
  const sourceRef = environment["INPUT_SOURCE-REF"];
  const candidateBuild = booleanInput(environment, "CANDIDATE-BUILD");
  if (sourceRef && command !== "rehearse") {
    throw new Error(`source-ref is not supported by the ${command} command`);
  }
  if (
    candidate &&
    !new Set(["rehearse", "verify", "release", "release-pr", "status"]).has(command)
  ) {
    throw new Error(`candidate is not supported by the ${command} command`);
  }
  if (candidateBuild && command !== "doctor") {
    throw new Error(`candidate-build is not supported by the ${command} command`);
  }
  const planFile = environment["INPUT_PLAN-FILE"];
  if (planFile && !["plan", "release-pr"].includes(command)) {
    throw new Error(`plan-file is not supported by the ${command} command`);
  }
  if (planFile && candidate) {
    throw new Error("plan-file and candidate cannot both be set");
  }
  if (command === "plan" && planFile) {
    args.push("--out", planFile);
  } else if (command === "release-pr" && planFile) {
    args.push("--plan", planFile);
  } else if (command === "rehearse") {
    if (sourceRef === undefined || !GIT_OBJECT_HEX.test(sourceRef)) {
      throw new Error("rehearse requires source-ref to be a full lowercase commit SHA");
    }
    if (!candidate) throw new Error("rehearse requires the candidate output directory input");
    args.push("--ref", sourceRef, "--out", candidate);
  } else if (["verify", "release"].includes(command)) {
    if (!candidate) throw new Error(`${command} requires the candidate input`);
    args.push("--candidate", candidate);
    if (command === "verify" && online) {
      args.push("--online");
    }
  } else if (command === "release-pr" && candidate) {
    args.push("--candidate", candidate);
  } else if (command === "status") {
    if (candidate) args.push("--candidate", candidate);
    if (online) args.push("--online");
  } else if (command === "doctor") {
    if (online) args.push("--online");
    if (candidateBuild) args.push("--candidate-build");
  }
  return args;
}

/**
 * One diagnostic of a `command/v2` result, with the fields the Action reads.
 * @typedef {{code: string, message: string} & Record<string, unknown>} Diagnostic
 */

/**
 * One next action of a `command/v2` result, with the fields the Action reads.
 * @typedef {{command: string, argv: string[]} & Record<string, unknown>} NextAction
 */

/**
 * A `command/v2` result, typed as far as the Action reads it.
 * @typedef {object} CommandEnvelopeFields
 * @property {"command/v2"} schema
 * @property {boolean} ok
 * @property {string} command
 * @property {unknown} [result]
 * @property {Diagnostic[]} diagnostics
 * @property {NextAction[]} next_actions
 */

/** @typedef {CommandEnvelopeFields & Record<string, unknown>} CommandEnvelope */

/**
 * @param {unknown} value
 * @returns {value is Diagnostic}
 */
function isDiagnostic(value) {
  return isRecord(value) && typeof value.code === "string" && typeof value.message === "string";
}

/**
 * @param {unknown} value
 * @returns {value is NextAction}
 */
function isNextAction(value) {
  return (
    isRecord(value) &&
    typeof value.command === "string" &&
    Array.isArray(value.argv) &&
    value.argv.every((argument) => typeof argument === "string")
  );
}

/**
 * @param {unknown} value
 * @returns {value is CommandEnvelope}
 */
function isCommandEnvelope(value) {
  return (
    isRecord(value) &&
    value.schema === "command/v2" &&
    typeof value.ok === "boolean" &&
    typeof value.command === "string" &&
    Array.isArray(value.diagnostics) &&
    value.diagnostics.every(isDiagnostic) &&
    Array.isArray(value.next_actions) &&
    value.next_actions.every(isNextAction)
  );
}

/**
 * The `command/v2` result that release-glz printed.
 * @param {string} stdout
 * @returns {CommandEnvelope}
 */
function parseCommandEnvelope(stdout) {
  /** @type {unknown} */
  let value;
  try {
    value = JSON.parse(stdout.trim());
  } catch (error) {
    throw new Error(`release-glz returned invalid JSON: ${errorMessage(error)}`);
  }
  if (
    !isRecord(value) ||
    value.schema !== "command/v2" ||
    typeof value.ok !== "boolean" ||
    typeof value.command !== "string" ||
    !Array.isArray(value.diagnostics) ||
    !Array.isArray(value.next_actions)
  ) {
    throw new Error("release-glz output is not command/v2");
  }
  if (!value.next_actions.every(isNextAction)) {
    throw new Error("release-glz next action does not contain canonical argv");
  }
  // What remains is a diagnostic without a code or a message.
  if (!isCommandEnvelope(value)) {
    throw new Error("release-glz output is not command/v2");
  }
  return value;
}

/**
 * The first argument that is a non-empty string, or an empty string.
 * @param {...unknown} values
 * @returns {string}
 */
function firstText(...values) {
  for (const value of values) {
    if (typeof value === "string" && value) return value;
  }
  return "";
}

/**
 * The step outputs that a command result sets.
 * @param {{result?: unknown, next_actions: NextAction[]} & Record<string, unknown>} envelope
 * @returns {Record<string, string>}
 */
function resultOutputs(envelope) {
  const result = isRecord(envelope.result) ? envelope.result : {};
  const candidate = isRecord(result.candidate) ? result.candidate : {};
  return {
    state: firstText(result.state, candidate.state),
    "release-required": String(Boolean(result.release_required)),
    version: firstText(result.version, candidate.version),
    "intent-digest": firstText(result.intent_digest, candidate.intent_digest),
    "candidate-digest": firstText(result.candidate_digest, candidate.candidate_digest),
    "pr-url": firstText(result.pr_url),
    "release-pr-head": firstText(result.release_pr_head),
    "intent-binding": firstText(result.intent_binding),
    "hex-url": firstText(result.hex_url),
    "github-release-url": firstText(result.github_release_url),
    "next-action": envelope.next_actions[0]?.command || "",
    "next-action-argv": JSON.stringify(envelope.next_actions[0]?.argv || []),
  };
}

/**
 * Set the step outputs of a command result and print it.
 * @param {CommandEnvelope} envelope
 * @param {NodeJS.ProcessEnv} environment
 * @param {OutputSink} stdout
 * @returns {void}
 */
function emitEnvelope(envelope, environment, stdout = process.stdout) {
  for (const [name, value] of Object.entries(resultOutputs(envelope))) {
    setOutput(name, value, environment.GITHUB_OUTPUT);
  }
  stdout.write(`${JSON.stringify(envelope)}\n`);
}

/**
 * @typedef {object} AcquiredBinary
 * @property {string} binary Path of the verified executable.
 * @property {() => void} cleanup Removes the download directory.
 */

/**
 * Download, verify, and extract the release-glz binary for this runner.
 * @param {NodeJS.ProcessEnv} environment
 * @returns {Promise<AcquiredBinary>}
 */
async function acquireBinary(environment = process.env) {
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
  const temporary = fs.mkdtempSync(
    path.join(environment.RUNNER_TEMP || os.tmpdir(), "release-glz-action-"),
  );
  const cleanup = () => fs.rmSync(temporary, { recursive: true, force: true });
  try {
    const archive = path.join(temporary, filename);
    let expected = environment["INPUT_BINARY-CHECKSUM"] || "";
    if (inputVersion) {
      const provenanceExpected = environment.INPUT_PROVENANCE ?? "";
      if (!SHA256_HEX.test(expected) || !SHA256_HEX.test(provenanceExpected)) {
        throw new Error(
          "Explicit override checksum and provenance must be lowercase SHA-256 digests",
        );
      }
      const provenance = path.join(temporary, `${filename}.intoto.jsonl`);
      await Promise.all([
        download(`${base}/${filename}`, archive),
        download(`${base}/${filename}.intoto.jsonl`, provenance, { maxBytes: MIB }),
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

/** A release-glz command that failed, with the result it printed and its exit status. */
class CommandFailure extends Error {
  /**
   * @param {string} message
   * @param {number | undefined} exitCode
   * @param {CommandEnvelope} envelope
   */
  constructor(message, exitCode, envelope) {
    super(message);
    this.exitCode = exitCode;
    this.envelope = envelope;
  }
}

/**
 * Run the release-glz command that the inputs name and relay its result as step outputs.
 * @param {NodeJS.ProcessEnv} environment
 * @param {OutputSink} stdout
 * @param {(environment: NodeJS.ProcessEnv) => Promise<AcquiredBinary>} acquire
 * @param {OutputSink} stderr
 * @returns {Promise<CommandEnvelope>}
 */
async function main(
  environment = process.env,
  stdout = process.stdout,
  acquire = acquireBinary,
  stderr = process.stderr,
) {
  const command = environment.INPUT_COMMAND;
  const args = buildCommandArgs(command, environment);
  const acquired = await acquire(environment);
  const controller = new AbortController();
  const cancel = () => controller.abort();
  process.once("SIGINT", cancel);
  process.once("SIGTERM", cancel);
  try {
    const childEnvironment = { ...environment };
    if (environment["INPUT_GITHUB-TOKEN"])
      childEnvironment.GITHUB_TOKEN = environment["INPUT_GITHUB-TOKEN"];
    const timeoutSeconds = Number(environment["INPUT_TIMEOUT-SECONDS"] || DEFAULT_TIMEOUT_SECONDS);
    if (
      !Number.isSafeInteger(timeoutSeconds) ||
      timeoutSeconds < MIN_TIMEOUT_SECONDS ||
      timeoutSeconds > MAX_TIMEOUT_SECONDS
    ) {
      throw new Error(
        `timeout-seconds must be between ${MIN_TIMEOUT_SECONDS} and ${MAX_TIMEOUT_SECONDS}`,
      );
    }
    /** @type {ProcessResult} */
    let result;
    try {
      result = await runProcess(acquired.binary, args, {
        env: childEnvironment,
        timeoutMs: timeoutSeconds * SECOND_MS,
        maxOutputBytes: PROCESS_OUTPUT_LIMIT,
        signal: controller.signal,
        stderr,
      });
    } catch (error) {
      const printed = isRecord(error) && typeof error.stdout === "string" ? error.stdout : "";
      if (printed.trim()) {
        const envelope = parseCommandEnvelope(printed);
        emitEnvelope(envelope, environment, stdout);
        const diagnostics = envelope.diagnostics
          .map((diagnostic) => `${diagnostic.code}: ${diagnostic.message}`)
          .join("; ");
        const next = envelope.next_actions[0]?.command;
        throw new CommandFailure(
          [diagnostics || `release-glz ${command} failed`, next ? `next: ${next}` : ""]
            .filter(Boolean)
            .join("; "),
          isRecord(error) && typeof error.exitCode === "number" ? error.exitCode : undefined,
          envelope,
        );
      }
      throw error;
    }
    const envelope = parseCommandEnvelope(result.stdout);
    emitEnvelope(envelope, environment, stdout);
    return envelope;
  } finally {
    process.removeListener("SIGINT", cancel);
    process.removeListener("SIGTERM", cancel);
    acquired.cleanup();
  }
}

/**
 * Pause workflow commands until the returned function runs, so text that release-glz relays can't issue one.
 * @param {OutputSink} stream
 * @returns {() => void}
 */
function pauseWorkflowCommands(stream) {
  const token = crypto.randomBytes(WORKFLOW_COMMAND_TOKEN_BYTES).toString("hex");
  stream.write(`::stop-commands::${token}\n`);
  return () => stream.write(`::${token}::\n`);
}

/**
 * @typedef {object} ActionIo
 * @property {OutputSink} [stdout]
 * @property {OutputSink} [stderr]
 * @property {(environment: NodeJS.ProcessEnv) => Promise<AcquiredBinary>} [acquire]
 */

/**
 * Run the Action and return its exit code, with workflow commands paused until the last diagnostic is written.
 * @param {NodeJS.ProcessEnv} environment
 * @param {ActionIo} io
 * @returns {Promise<number>}
 */
async function run(environment = process.env, io = {}) {
  const stderr = io.stderr ?? process.stderr;
  const resume = pauseWorkflowCommands(stderr);
  try {
    await main(environment, io.stdout ?? process.stdout, io.acquire ?? acquireBinary, stderr);
    return 0;
  } catch (error) {
    stderr.write(`release-glz action failed: ${errorMessage(error)}\n`);
    return isRecord(error) && typeof error.exitCode === "number" && error.exitCode
      ? error.exitCode
      : 1;
  } finally {
    resume();
  }
}

if (require.main === module) {
  run().then((code) => {
    process.exitCode = code;
  });
}

module.exports = {
  CommandFailure,
  ProcessExitError,
  acquireBinary,
  buildCommandArgs,
  bundledChecksum,
  download,
  expectedChecksum,
  emitEnvelope,
  extract,
  inventoryTarGz,
  isAllowedDownloadRedirect,
  main,
  normalizedVersion,
  parseCommandEnvelope,
  resultOutputs,
  run,
  runProcess,
  setOutput,
  sha256,
  targetFor,
  validateArchiveInventory,
  verifyChecksum,
  verifyProvenance,
  windowsZipExtractScript,
  windowsZipInventoryScript,
  zipEntryKind,
};
