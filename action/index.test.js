"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const zlib = require("node:zlib");
const {
  expectedChecksum,
  inventoryTarGz,
  buildCommandArgs,
  bundledChecksum,
  download,
  normalizedVersion,
  parseCommandEnvelope,
  runProcess,
  setOutput,
  sha256,
  targetFor,
  validateArchiveInventory,
  verifyChecksum,
  verifyProvenance,
  zipEntryKind,
} = require("./index.js");

test("maps all published runner targets", () => {
  assert.deepEqual(targetFor("linux", "x64"), ["x86_64-unknown-linux-musl", "tar.gz"]);
  assert.deepEqual(targetFor("linux", "arm64"), ["aarch64-unknown-linux-musl", "tar.gz"]);
  assert.deepEqual(targetFor("darwin", "x64"), ["x86_64-apple-darwin", "tar.gz"]);
  assert.deepEqual(targetFor("darwin", "arm64"), ["aarch64-apple-darwin", "tar.gz"]);
  assert.deepEqual(targetFor("win32", "x64"), ["x86_64-pc-windows-msvc", "zip"]);
  assert.deepEqual(targetFor("win32", "arm64"), ["aarch64-pc-windows-msvc", "zip"]);
});

test("builds v1 candidate command arguments without a shell", () => {
  const common = { "INPUT_MANIFEST-PATH": "packages/widget/gleam.toml" };
  assert.deepEqual(
    buildCommandArgs("rehearse", {
      ...common,
      "INPUT_SOURCE-REF": "a".repeat(40),
      "INPUT_CANDIDATE": ".release-glz/candidate",
    }),
    [
      "--manifest-path", "packages/widget/gleam.toml", "--output", "json",
      "rehearse", "--ref", "a".repeat(40), "--out", ".release-glz/candidate",
    ],
  );
  assert.deepEqual(
    buildCommandArgs("verify", {
      ...common,
      "INPUT_CANDIDATE": "candidate",
      "INPUT_ONLINE": "true",
    }).slice(-4),
    ["verify", "--candidate", "candidate", "--online"],
  );
  assert.throws(() => buildCommandArgs("release", common), /candidate/i);
  assert.deepEqual(
    buildCommandArgs("release-pr", {
      ...common,
      "INPUT_CANDIDATE": "candidate",
    }).slice(-3),
    ["release-pr", "--candidate", "candidate"],
  );
});

test("accepts only command envelope schema v2 and extracts domain outputs", () => {
  const envelope = parseCommandEnvelope(JSON.stringify({
    schema: "command/v2",
    ok: true,
    command: "rehearse",
    result: {
      state: "candidate_ready",
      version: "1.2.3",
      intent_digest: "i".repeat(64),
      candidate_digest: "c".repeat(64),
    },
    diagnostics: [],
    next_actions: [],
  }));
  assert.equal(envelope.result.state, "candidate_ready");
  assert.throws(() => parseCommandEnvelope('{"ok":true}'), /command\/v2/);
});

test("rejects unsafe, linked, duplicate, or excessive archive inventories", () => {
  assert.doesNotThrow(() => validateArchiveInventory([
    { path: "release-glz", kind: "file", size: 100 },
  ], { maxEntries: 2, maxBytes: 200 }));
  for (const entries of [
    [{ path: "../escape", kind: "file", size: 1 }],
    [{ path: "/absolute", kind: "file", size: 1 }],
    [{ path: "link", kind: "symlink", size: 0 }],
    [
      { path: "same", kind: "file", size: 1 },
      { path: "same", kind: "file", size: 1 },
    ],
    [{ path: "huge", kind: "file", size: 201 }],
  ]) {
    assert.throws(() => validateArchiveInventory(entries, { maxEntries: 2, maxBytes: 200 }));
  }
});

test("reads tar header sizes instead of trusting text listings", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-tar-test-"));
  const archive = path.join(directory, "binary.tar.gz");
  fs.writeFileSync(archive, tarGz([{ path: "release-glz", body: Buffer.alloc(201, 7) }]));
  await assert.rejects(
    inventoryTarGz(archive, { maxEntries: 2, maxBytes: 200 }),
    /expands beyond/,
  );
  const entries = await inventoryTarGz(archive, { maxEntries: 2, maxBytes: 201 });
  assert.deepEqual(entries, [{ path: "release-glz", kind: "file", size: 201 }]);
});

test("classifies zip links and special files from external attributes", () => {
  assert.equal(zipEntryKind("release-glz.exe", 0o100644 * 0x10000), "file");
  assert.equal(zipEntryKind("bin/", 0o040755 * 0x10000), "directory");
  assert.equal(zipEntryKind("link", 0o120777 * 0x10000), "unsupported");
  assert.equal(zipEntryKind("device", 0o060600 * 0x10000), "unsupported");
  assert.equal(zipEntryKind("junction", 0x400), "unsupported");
});

test("download follows only same-origin redirects and enforces the byte limit", async (t) => {
  const server = http.createServer((request, response) => {
    if (request.url === "/redirect") {
      response.writeHead(302, { location: "/file" }).end();
    } else if (request.url === "/cross") {
      response.writeHead(302, { location: "http://example.test/file" }).end();
    } else {
      response.writeHead(200, { "content-length": "8" }).end("12345678");
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const { port } = server.address();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-download-test-"));
  const destination = path.join(directory, "file");
  await download(`http://127.0.0.1:${port}/redirect`, destination, {
    maxBytes: 8,
    allowHttpLoopback: true,
  });
  assert.equal(fs.readFileSync(destination, "utf8"), "12345678");
  await assert.rejects(
    download(`http://127.0.0.1:${port}/cross`, destination, {
      maxBytes: 8,
      allowHttpLoopback: true,
    }),
    /cross-origin/,
  );
  await assert.rejects(
    download(`http://127.0.0.1:${port}/file`, destination, {
      maxBytes: 7,
      allowHttpLoopback: true,
    }),
    /limit/,
  );
});

test("streaming subprocess execution is bounded and times out", async () => {
  const ok = await runProcess(process.execPath, ["-e", "process.stdout.write('ok')"], {
    timeoutMs: 2_000,
    maxOutputBytes: 10,
  });
  assert.equal(ok.stdout, "ok");
  await assert.rejects(
    runProcess(process.execPath, ["-e", "setTimeout(() => {}, 5000)"], {
      timeoutMs: 50,
      maxOutputBytes: 10,
    }),
    /timed out/,
  );
  await assert.rejects(
    runProcess(process.execPath, ["-e", "process.stdout.write('x'.repeat(100))"], {
      timeoutMs: 2_000,
      maxOutputBytes: 10,
    }),
    /output limit/,
  );
  const started = Date.now();
  await assert.rejects(
    runProcess(process.execPath, [
      "-e",
      "process.on('SIGTERM',()=>setTimeout(()=>process.exit(0),500));setInterval(()=>{},1000)",
    ], {
      timeoutMs: 50,
      terminateGraceMs: 100,
      maxOutputBytes: 10,
    }),
    /timed out/,
  );
  assert.ok(Date.now() - started < 400, "SIGTERM-resistant child was not force-killed");
});

test("accepts only immutable semantic versions", () => {
  assert.equal(normalizedVersion("", "v1.2.3"), "v1.2.3");
  assert.equal(normalizedVersion("1.2.3", "main"), "v1.2.3");
  assert.equal(normalizedVersion("", "v1", "2.0.1"), "v2.0.1");
  assert.throws(() => normalizedVersion("", "main", "dev"), /immutable/);
});

test("finds and verifies the named archive checksum", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-action-test-"));
  const file = path.join(directory, "archive.tar.gz");
  fs.writeFileSync(file, "release-glz");
  const digest = sha256(file);
  assert.equal(expectedChecksum(`${digest}  archive.tar.gz\n`, "archive.tar.gz"), digest);
  assert.doesNotThrow(() => verifyChecksum(file, digest));
  assert.throws(() => verifyChecksum(file, "0".repeat(64)), /Checksum mismatch/);
});

test("bundled checksum manifest covers every platform and exact action version", () => {
  const digest = "a".repeat(64);
  const artifacts = Object.fromEntries([
    "release-glz-x86_64-unknown-linux-musl.tar.gz",
    "release-glz-aarch64-unknown-linux-musl.tar.gz",
    "release-glz-x86_64-apple-darwin.tar.gz",
    "release-glz-aarch64-apple-darwin.tar.gz",
    "release-glz-x86_64-pc-windows-msvc.zip",
    "release-glz-aarch64-pc-windows-msvc.zip",
  ].map((name) => [name, digest]));
  const manifest = JSON.stringify({
    schema: "release-glz-action-checksums/v1",
    version: "v1.0.0",
    artifacts,
  });
  assert.equal(
    bundledChecksum(manifest, "v1.0.0", "release-glz-aarch64-apple-darwin.tar.gz"),
    digest,
  );
  delete artifacts["release-glz-aarch64-pc-windows-msvc.zip"];
  assert.throws(() => bundledChecksum(JSON.stringify({
    schema: "release-glz-action-checksums/v1",
    version: "v1.0.0",
    artifacts,
  }), "v1.0.0", "release-glz-aarch64-apple-darwin.tar.gz"), /every supported platform/);
  assert.throws(() => bundledChecksum(manifest, "v1.0.1", "release-glz-aarch64-apple-darwin.tar.gz"), /version/);
});

test("explicit override provenance is content addressed and binds the archive subject", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-provenance-test-"));
  const provenance = path.join(directory, "archive.intoto.jsonl");
  const archiveDigest = "b".repeat(64);
  fs.writeFileSync(provenance, JSON.stringify({
    _type: "https://in-toto.io/Statement/v1",
    subject: [{
      name: "release-glz-x86_64-unknown-linux-musl.tar.gz",
      digest: { sha256: archiveDigest },
    }],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {},
  }));
  const provenanceDigest = sha256(provenance);
  assert.doesNotThrow(() => verifyProvenance(
    provenance,
    provenanceDigest,
    "release-glz-x86_64-unknown-linux-musl.tar.gz",
    archiveDigest,
  ));
  assert.throws(() => verifyProvenance(
    provenance,
    provenanceDigest,
    "release-glz-aarch64-unknown-linux-musl.tar.gz",
    archiveDigest,
  ), /subject/);
});

test("writes multiline-safe GitHub outputs", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-output-test-"));
  const output = path.join(directory, "output");
  setOutput("pr", "https://example.test/pr/1", output);
  const contents = fs.readFileSync(output, "utf8");
  assert.match(contents, /^pr<<release_glz_[a-f0-9]+\nhttps:\/\/example\.test\/pr\/1\nrelease_glz_[a-f0-9]+\n$/);
  const delimiters = contents.match(/release_glz_[a-f0-9]+/g);
  assert.equal(delimiters[0], delimiters[1]);
});

function tarGz(entries) {
  const chunks = [];
  for (const entry of entries) {
    const header = Buffer.alloc(512);
    header.write(entry.path, 0, 100, "utf8");
    header.write("0000644\0", 100, 8, "ascii");
    header.write("0000000\0", 108, 8, "ascii");
    header.write("0000000\0", 116, 8, "ascii");
    header.write(`${entry.body.length.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
    header.write("00000000000\0", 136, 12, "ascii");
    header.fill(0x20, 148, 156);
    header[156] = "0".charCodeAt(0);
    header.write("ustar\0", 257, 6, "ascii");
    const checksum = [...header].reduce((sum, byte) => sum + byte, 0);
    header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
    chunks.push(header, entry.body, Buffer.alloc((512 - (entry.body.length % 512)) % 512));
  }
  chunks.push(Buffer.alloc(1024));
  return zlib.gzipSync(Buffer.concat(chunks));
}
