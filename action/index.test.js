// @ts-check
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const zlib = require("node:zlib");
const {
  CommandFailure,
  ProcessExitError,
  acquireBinary,
  expectedChecksum,
  extract,
  inventoryTarGz,
  isAllowedDownloadRedirect,
  buildCommandArgs,
  bundledChecksum,
  download,
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
      INPUT_CANDIDATE: ".release-glz/candidate",
    }),
    [
      "--manifest-path",
      "packages/widget/gleam.toml",
      "--output",
      "json",
      "rehearse",
      "--ref",
      "a".repeat(40),
      "--out",
      ".release-glz/candidate",
    ],
  );
  assert.deepEqual(
    buildCommandArgs("verify", {
      ...common,
      INPUT_CANDIDATE: "candidate",
      INPUT_ONLINE: "true",
    }).slice(-4),
    ["verify", "--candidate", "candidate", "--online"],
  );
  assert.throws(() => buildCommandArgs("release", common), /candidate/i);
  assert.deepEqual(
    buildCommandArgs("release-pr", {
      ...common,
      INPUT_CANDIDATE: "candidate",
    }).slice(-3),
    ["release-pr", "--candidate", "candidate"],
  );
  assert.deepEqual(
    buildCommandArgs("plan", { ...common, "INPUT_PLAN-FILE": "plan.json" }).slice(-3),
    ["plan", "--out", "plan.json"],
  );
  assert.deepEqual(
    buildCommandArgs("release-pr", {
      ...common,
      "INPUT_PLAN-FILE": "plan.json",
      "INPUT_DRY-RUN": "true",
    }).slice(-4),
    ["release-pr", "--dry-run", "--plan", "plan.json"],
  );
});

test("accepts only command envelope schema v2 and extracts domain outputs", () => {
  const envelope = parseCommandEnvelope(
    JSON.stringify({
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
    }),
  );
  assert.equal(resultOutputs(envelope).state, "candidate_ready");
  assert.throws(() => parseCommandEnvelope('{"ok":true}'), /command\/v2/);
  assert.throws(
    () =>
      parseCommandEnvelope(
        JSON.stringify({
          ...envelope,
          diagnostics: [{ level: "error", message: "no code", detail: null }],
        }),
      ),
    /command\/v2/,
  );
  assert.throws(
    () =>
      parseCommandEnvelope(
        JSON.stringify({
          ...envelope,
          next_actions: [{ command: "release-glz release", description: "release" }],
        }),
      ),
    /canonical argv/,
  );
  assert.equal(
    resultOutputs({
      ...envelope,
      next_actions: [
        {
          argv: ["release-glz", "release", "--candidate", "path with space"],
          command: 'release-glz release --candidate "path with space"',
          description: "release",
        },
      ],
    })["next-action-argv"],
    JSON.stringify(["release-glz", "release", "--candidate", "path with space"]),
  );
  const written = resultOutputs({
    ...envelope,
    command: "release-pr",
    result: {
      state: "planned",
      pr_url: "https://github.test/acme/widget/pull/9",
      release_pr_head: "b".repeat(40),
    },
  });
  assert.equal(written["pr-url"], "https://github.test/acme/widget/pull/9");
  assert.equal(written["release-pr-head"], "b".repeat(40));
  assert.equal(resultOutputs(envelope)["release-pr-head"], "");
  const superseded = resultOutputs({
    ...envelope,
    command: "release-pr",
    result: { schema: "release-pr-intent/v1", state: "planned", intent_binding: "superseded" },
  });
  assert.equal(superseded["intent-binding"], "superseded");
  assert.equal(superseded["pr-url"], "");
  assert.equal(resultOutputs(envelope)["intent-binding"], "");
});

test("the Action metadata declares exactly the inputs it reads and the outputs it writes", () => {
  const metadata = fs.readFileSync(path.join(__dirname, "..", "action.yml"), "utf8");
  /**
   * @param {string} section
   * @returns {string[]}
   */
  const declared = (section) => {
    const block = metadata.split(`\n${section}:\n`)[1]?.split(/\n(?=\S)/)[0] ?? "";
    return [...block.matchAll(/^ {2}([a-z-]+):$/gm)].map((match) => match[1] ?? "").sort();
  };
  const source = fs.readFileSync(path.join(__dirname, "index.js"), "utf8");
  const read = [
    ...source.matchAll(/INPUT_([A-Z-]+)|booleanInput\(environment, "([A-Z-]+)"\)/g),
  ].map((match) => (match[1] || match[2] || "").toLowerCase());
  assert.deepEqual([...new Set(read)].sort(), declared("inputs"));
  const written = Object.keys(resultOutputs({ result: {}, next_actions: [] }));
  assert.deepEqual(written.sort(), declared("outputs"));
});

test("rejects dry-run and online inputs for commands that cannot use them", () => {
  assert.throws(() => buildCommandArgs("plan", { "INPUT_DRY-RUN": "true" }), /dry-run/);
  assert.throws(() => buildCommandArgs("plan", { INPUT_ONLINE: "tru" }), /true or false/);
  assert.throws(
    () =>
      buildCommandArgs("rehearse", {
        "INPUT_SOURCE-REF": "a".repeat(40),
        INPUT_CANDIDATE: "candidate",
        INPUT_ONLINE: "true",
      }),
    /online/,
  );
  assert.throws(
    () =>
      buildCommandArgs("plan", {
        "INPUT_CANDIDATE-BUILD": "true",
      }),
    /candidate-build/,
  );
  assert.throws(
    () =>
      buildCommandArgs("doctor", {
        "INPUT_SOURCE-REF": "a".repeat(40),
      }),
    /source-ref/,
  );
  assert.throws(
    () =>
      buildCommandArgs("plan", {
        INPUT_CANDIDATE: "candidate",
      }),
    /candidate/,
  );
  assert.throws(
    () =>
      buildCommandArgs("verify", {
        INPUT_CANDIDATE: "candidate",
        "INPUT_PLAN-FILE": "plan.json",
      }),
    /plan-file is not supported by the verify command/,
  );
  assert.throws(
    () =>
      buildCommandArgs("release-pr", {
        INPUT_CANDIDATE: "candidate",
        "INPUT_PLAN-FILE": "plan.json",
      }),
    /plan-file and candidate/,
  );
  assert.deepEqual(
    buildCommandArgs("doctor", {
      INPUT_ONLINE: "true",
      "INPUT_CANDIDATE-BUILD": "true",
    }).slice(-3),
    ["doctor", "--online", "--candidate-build"],
  );
});

test("rejects unsafe, linked, duplicate, or excessive archive inventories", () => {
  assert.doesNotThrow(() =>
    validateArchiveInventory([{ path: "release-glz", kind: "file", size: 100 }], {
      maxEntries: 2,
      maxBytes: 200,
    }),
  );
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
  await assert.rejects(inventoryTarGz(archive, { maxEntries: 2, maxBytes: 200 }), /expands beyond/);
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
  const port = await listenOnLoopback(server);
  t.after(() => server.close());
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

test("download stops a server that trickles bytes at its total deadline", {
  timeout: 10_000,
}, async (t) => {
  const sockets = new Set();
  const server = http.createServer((request, response) => {
    if (request.url === "/redirect") {
      response.writeHead(302, { location: "/slow" }).end();
      return;
    }
    response.writeHead(200, { "content-length": "1000000" });
    const trickle = setInterval(() => response.write("x"), 20);
    response.on("close", () => clearInterval(trickle));
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  const port = await listenOnLoopback(server);
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    server.close();
  });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-deadline-test-"));
  const destination = path.join(directory, "file");
  const started = Date.now();
  await assert.rejects(
    download(`http://127.0.0.1:${port}/redirect`, destination, {
      allowHttpLoopback: true,
      timeoutMs: 5_000,
      totalTimeoutMs: 300,
    }),
    /deadline/,
  );
  assert.ok(Date.now() - started < 5_000, "the idle timeout ended the download instead");
  assert.equal(fs.existsSync(destination), false);
});

test("download permits only GitHub's exact HTTPS release asset redirect hosts", () => {
  const github =
    "https://github.com/P4suta/release-glz/releases/download/v1.0.0/release-glz.tar.gz";
  assert.equal(
    isAllowedDownloadRedirect(
      github,
      "https://release-assets.githubusercontent.com/signed?token=x",
    ),
    true,
  );
  assert.equal(
    isAllowedDownloadRedirect(
      github,
      "https://objects.githubusercontent.com/github-production-release-asset/x",
    ),
    true,
  );
  assert.equal(isAllowedDownloadRedirect(github, "https://github.com/another/path"), true);
  for (const target of [
    "http://release-assets.githubusercontent.com/file",
    "https://release-assets.githubusercontent.com.evil.test/file",
    "https://githubusercontent.com/file",
    "https://release-assets.githubusercontent.com:444/file",
    "https://example.test/file",
  ]) {
    assert.equal(isAllowedDownloadRedirect(github, target), false, target);
  }
  assert.equal(
    isAllowedDownloadRedirect(
      "https://example.test/file",
      "https://release-assets.githubusercontent.com/file",
    ),
    false,
  );
});

test("Windows ZIP scripts use environment-bound paths instead of positional PowerShell args", () => {
  const inventory = windowsZipInventoryScript();
  const extract = windowsZipExtractScript();
  assert.match(inventory, /RELEASE_GLZ_ARCHIVE/);
  assert.match(inventory, /\[char\]9/);
  assert.match(extract, /RELEASE_GLZ_ARCHIVE/);
  assert.match(extract, /RELEASE_GLZ_DESTINATION/);
  assert.doesNotMatch(`${inventory}\n${extract}`, /\$args\[/);
  for (const script of [inventory, extract]) {
    assert.match(script, /^Add-Type -AssemblyName System\.IO\.Compression\.FileSystem;/);
  }
  assert.match(
    extract,
    /ExtractToDirectory\(\$env:RELEASE_GLZ_ARCHIVE,\$env:RELEASE_GLZ_DESTINATION\)$/,
  );
});

test("lists and extracts a real ZIP archive with Windows PowerShell", {
  skip: process.platform !== "win32" && "Windows PowerShell runs only on Windows",
}, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-zip-"));
  const source = path.join(root, "release-glz.exe");
  fs.writeFileSync(source, "binary");
  const archive = path.join(root, "release-glz.zip");
  await runProcess(
    "powershell",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "Compress-Archive -LiteralPath $env:RELEASE_GLZ_SOURCE -DestinationPath $env:RELEASE_GLZ_ARCHIVE",
    ],
    { env: { ...process.env, RELEASE_GLZ_SOURCE: source, RELEASE_GLZ_ARCHIVE: archive } },
  );
  const destination = path.join(root, "extracted");

  await extract(archive, "zip", destination);

  assert.equal(fs.readFileSync(path.join(destination, "release-glz.exe"), "utf8"), "binary");
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
    runProcess(
      process.execPath,
      [
        "-e",
        "process.on('SIGTERM',()=>setTimeout(()=>process.exit(0),500));setInterval(()=>{},1000)",
      ],
      {
        timeoutMs: 50,
        terminateGraceMs: 100,
        maxOutputBytes: 10,
      },
    ),
    /timed out/,
  );
  assert.ok(Date.now() - started < 400, "SIGTERM-resistant child was not force-killed");

  const failureEnvelope = JSON.stringify({
    schema: "command/v2",
    ok: false,
    command: "release",
    result: null,
    diagnostics: [
      {
        code: "immutable_state_conflict",
        level: "error",
        message: "different bytes",
        detail: null,
      },
    ],
    next_actions: [
      { argv: ["release-glz", "status"], command: "release-glz status", description: "inspect" },
    ],
  });
  await assert.rejects(
    runProcess(
      process.execPath,
      ["-e", `process.stdout.write(${JSON.stringify(failureEnvelope)});process.exit(4)`],
      {
        timeoutMs: 2_000,
        maxOutputBytes: 10_000,
        streamStderr: false,
      },
    ),
    (error) => {
      assert.ok(error instanceof ProcessExitError);
      assert.equal(error.exitCode, 4);
      assert.equal(
        parseCommandEnvelope(error.stdout).diagnostics[0]?.code,
        "immutable_state_conflict",
      );
      return true;
    },
  );
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
  const artifacts = Object.fromEntries(
    [
      "release-glz-x86_64-unknown-linux-musl.tar.gz",
      "release-glz-aarch64-unknown-linux-musl.tar.gz",
      "release-glz-x86_64-apple-darwin.tar.gz",
      "release-glz-aarch64-apple-darwin.tar.gz",
      "release-glz-x86_64-pc-windows-msvc.zip",
      "release-glz-aarch64-pc-windows-msvc.zip",
    ].map((name) => [name, digest]),
  );
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
  assert.throws(
    () =>
      bundledChecksum(
        JSON.stringify({
          schema: "release-glz-action-checksums/v1",
          version: "v1.0.0",
          artifacts,
        }),
        "v1.0.0",
        "release-glz-aarch64-apple-darwin.tar.gz",
      ),
    /every supported platform/,
  );
  assert.throws(
    () => bundledChecksum(manifest, "v1.0.1", "release-glz-aarch64-apple-darwin.tar.gz"),
    /version/,
  );
  const placeholders = Object.fromEntries(
    Object.keys(JSON.parse(manifest).artifacts).map((name) => [name, "0".repeat(64)]),
  );
  assert.throws(
    () =>
      bundledChecksum(
        JSON.stringify({
          schema: "release-glz-action-checksums/v1",
          version: "v1.0.0",
          artifacts: placeholders,
        }),
        "v1.0.0",
        "release-glz-aarch64-apple-darwin.tar.gz",
      ),
    /SHA-256/,
  );
});

test("explicit override provenance is content addressed and binds the archive subject", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-provenance-test-"));
  const provenance = path.join(directory, "archive.intoto.jsonl");
  const archiveDigest = "b".repeat(64);
  fs.writeFileSync(
    provenance,
    JSON.stringify({
      _type: "https://in-toto.io/Statement/v1",
      subject: [
        {
          name: "release-glz-x86_64-unknown-linux-musl.tar.gz",
          digest: { sha256: archiveDigest },
        },
      ],
      predicateType: "https://slsa.dev/provenance/v1",
      predicate: {},
    }),
  );
  const provenanceDigest = sha256(provenance);
  assert.doesNotThrow(() =>
    verifyProvenance(
      provenance,
      provenanceDigest,
      "release-glz-x86_64-unknown-linux-musl.tar.gz",
      archiveDigest,
    ),
  );
  assert.throws(
    () =>
      verifyProvenance(
        provenance,
        provenanceDigest,
        "release-glz-aarch64-unknown-linux-musl.tar.gz",
        archiveDigest,
      ),
    /subject/,
  );
});

test("writes multiline-safe GitHub outputs", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-output-test-"));
  const output = path.join(directory, "output");
  setOutput("pr", "https://example.test/pr/1", output);
  const contents = fs.readFileSync(output, "utf8");
  assert.match(
    contents,
    /^pr<<release_glz_[a-f0-9]+\nhttps:\/\/example\.test\/pr\/1\nrelease_glz_[a-f0-9]+\n$/,
  );
  const delimiters = contents.match(/release_glz_[a-f0-9]+/g);
  assert.equal(delimiters?.length, 2);
  assert.equal(delimiters[0], delimiters[1]);
});

test("Action pauses workflow commands while release-glz output reaches the log", async (t) => {
  if (process.platform === "win32") return t.skip("Unix executable fixture");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-commands-test-"));
  const binary = path.join(directory, "release-glz");
  const envelope = {
    schema: "command/v2",
    ok: false,
    command: "plan",
    result: null,
    diagnostics: [
      {
        code: "blocked",
        level: "error",
        message: "first line\n::error::from a diagnostic",
        detail: null,
      },
    ],
    next_actions: [],
  };
  fs.writeFileSync(
    binary,
    `#!/bin/sh\nprintf '%s\\n' '::error::from stderr' >&2\nprintf '%s\\n' '${JSON.stringify(envelope)}'\nexit 4\n`,
  );
  fs.chmodSync(binary, 0o700);
  const tokens = [];
  for (const attempt of [1, 2]) {
    let logged = "";
    const code = await run(
      {
        ...process.env,
        INPUT_COMMAND: "plan",
        GITHUB_OUTPUT: path.join(directory, `output-${attempt}`),
        "INPUT_TIMEOUT-SECONDS": "10",
      },
      {
        stdout: { write: () => true },
        stderr: {
          write(chunk) {
            logged += chunk;
            return true;
          },
        },
        acquire: async () => ({ binary, cleanup: () => {} }),
      },
    );
    assert.equal(code, 4);
    const lines = logged.trimEnd().split("\n");
    const token = lines[0]?.match(/^::stop-commands::([a-f0-9]{32})$/)?.[1];
    assert.ok(token !== undefined, "the Action didn't pause workflow commands first");
    assert.equal(lines.at(-1), `::${token}::`);
    assert.deepEqual(
      lines.filter((line) => line.startsWith("::error::")),
      ["::error::from stderr", "::error::from a diagnostic"],
    );
    assert.ok(lines.slice(1, -1).every((line) => !line.includes(token)));
    tokens.push(token);
  }
  assert.notEqual(tokens[0], tokens[1]);
});

test("acquireBinary ignores RELEASE_GLZ_BINARY and keeps its own checks", async () => {
  await assert.rejects(
    acquireBinary({
      RELEASE_GLZ_BINARY: process.execPath,
      GITHUB_ACTION_REPOSITORY: "not a repository",
    }),
    /GITHUB_ACTION_REPOSITORY is unsafe/,
  );
});

test("Action preserves a nonzero command envelope, diagnostics, argv, and exit code", async (t) => {
  if (process.platform === "win32") return t.skip("Unix executable fixture");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-failure-test-"));
  const binary = path.join(directory, "release-glz");
  const output = path.join(directory, "github-output");
  const envelope = {
    schema: "command/v2",
    ok: false,
    command: "plan",
    result: null,
    diagnostics: [
      {
        code: "immutable_state_conflict",
        level: "error",
        message: "sealed bytes differ",
        detail: null,
      },
    ],
    next_actions: [
      {
        argv: ["release-glz", "status", "--candidate", "path with space"],
        command: 'release-glz status --candidate "path with space"',
        description: "inspect the Candidate",
      },
    ],
  };
  fs.writeFileSync(binary, `#!/bin/sh\nprintf '%s\\n' '${JSON.stringify(envelope)}'\nexit 4\n`);
  fs.chmodSync(binary, 0o700);
  let displayed = "";
  await assert.rejects(
    main(
      {
        ...process.env,
        INPUT_COMMAND: "plan",
        GITHUB_OUTPUT: output,
        "INPUT_TIMEOUT-SECONDS": "10",
      },
      {
        write(chunk) {
          displayed += chunk;
          return true;
        },
      },
      async () => ({ binary, cleanup: () => {} }),
    ),
    (error) => {
      assert.ok(error instanceof CommandFailure);
      assert.equal(error.exitCode, 4);
      assert.equal(error.envelope.diagnostics[0]?.code, "immutable_state_conflict");
      assert.match(error.message, /sealed bytes differ/);
      assert.match(error.message, /next:/);
      return true;
    },
  );
  assert.equal(JSON.parse(displayed).ok, false);
  const outputs = fs.readFileSync(output, "utf8");
  assert.match(outputs, /next-action-argv/);
  assert.match(outputs, /path with space/);
});

/**
 * Start `server` on a loopback port and return the port.
 * @param {http.Server} server
 * @returns {Promise<number>}
 */
async function listenOnLoopback(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(undefined)));
  const address = server.address();
  assert.ok(address !== null && typeof address === "object", "the server has no TCP address");
  return address.port;
}

/**
 * A gzip-compressed ustar archive of `entries`, each a regular file.
 * @param {Array<{path: string, body: Buffer}>} entries
 * @returns {Buffer}
 */
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
