"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const archives = [
  "release-glz-x86_64-unknown-linux-musl.tar.gz",
  "release-glz-aarch64-unknown-linux-musl.tar.gz",
  "release-glz-x86_64-apple-darwin.tar.gz",
  "release-glz-aarch64-apple-darwin.tar.gz",
  "release-glz-x86_64-pc-windows-msvc.zip",
  "release-glz-aarch64-pc-windows-msvc.zip",
];

test("generates one deterministic SLSA statement for every supported archive", (context) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-provenance-"));
  context.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const left = path.join(root, "left");
  const right = path.join(root, "right");
  populate(left);
  populate(right);

  const common = [
    "--repository", "P4suta/release-glz",
    "--source", "a".repeat(40),
    "--version", "v1.0.0",
    "--run-id", "123456",
  ];
  const first = run(["--artifacts", left, ...common]);
  const second = run(["--artifacts", right, ...common]);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(second.status, 0, second.stderr);

  for (const archive of archives) {
    const name = `${archive}.intoto.jsonl`;
    const leftBytes = fs.readFileSync(path.join(left, name));
    assert.deepEqual(leftBytes, fs.readFileSync(path.join(right, name)));
    assert.equal(leftBytes.toString("utf8").trim().split("\n").length, 1);

    const statement = JSON.parse(leftBytes);
    const expectedDigest = crypto.createHash("sha256")
      .update(fs.readFileSync(path.join(left, archive)))
      .digest("hex");
    assert.equal(statement._type, "https://in-toto.io/Statement/v1");
    assert.equal(statement.predicateType, "https://slsa.dev/provenance/v1");
    assert.deepEqual(statement.subject, [{ name: archive, digest: { sha256: expectedDigest } }]);
    assert.equal(
      statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit,
      "a".repeat(40),
    );
    assert.match(statement.predicate.runDetails.builder.id, /distribute\.yml@refs\/tags\/v1\.0\.0$/);
    assert.match(statement.predicate.runDetails.metadata.invocationId, /actions\/runs\/123456$/);
  }
});

test("rejects ambiguous source identity and incomplete archive sets", (context) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-provenance-invalid-"));
  const complete = fs.mkdtempSync(path.join(os.tmpdir(), "release-glz-provenance-identity-"));
  context.after(() => fs.rmSync(root, { recursive: true, force: true }));
  context.after(() => fs.rmSync(complete, { recursive: true, force: true }));
  populate(root);
  populate(complete);
  fs.unlinkSync(path.join(root, archives[0]));
  const incomplete = run([
    "--artifacts", root,
    "--repository", "P4suta/release-glz",
    "--source", "b".repeat(40),
    "--version", "v1.0.0",
    "--run-id", "9",
  ]);
  assert.notEqual(incomplete.status, 0);
  assert.match(incomplete.stderr, /bounded regular release archive|ENOENT/);

  const unsafe = run([
    "--artifacts", complete,
    "--repository", "owner/repo?token=secret",
    "--source", "not-a-full-sha",
    "--version", "main",
    "--run-id", "run",
  ]);
  assert.notEqual(unsafe.status, 0);
  assert.doesNotMatch(unsafe.stderr, /secret/);
});

function populate(directory) {
  fs.mkdirSync(directory, { recursive: true });
  for (const archive of archives) {
    fs.writeFileSync(path.join(directory, archive), `bytes:${archive}\n`, { flag: "wx" });
  }
}

function run(args) {
  const result = spawnSync(process.execPath, [
    path.join(__dirname, "generate-provenance.js"),
    ...args,
  ], { encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}
