"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const { generateDocuments, parseLockChecksums } = require("./generate-sbom.js");

test("generates deterministic CycloneDX and third-party license documents", () => {
  const metadata = {
    packages: [
      {
        name: "zeta",
        version: "2.0.0",
        id: "registry+zeta@2.0.0",
        license: null,
        source: "registry+https://github.com/rust-lang/crates.io-index",
        repository: null,
      },
      {
        name: "release-glz",
        version: "1.0.0",
        id: "path+file:///repo#release-glz@1.0.0",
        license: "MIT OR Apache-2.0",
        source: null,
        repository: "https://github.com/P4suta/release-glz",
      },
      {
        name: "alpha",
        version: "1.2.3",
        id: "registry+alpha@1.2.3",
        license: "Apache-2.0",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        repository: "https://example.test/alpha",
      },
    ],
    workspace_members: ["path+file:///repo#release-glz@1.0.0"],
    resolve: {
      nodes: [{
        id: "path+file:///repo#release-glz@1.0.0",
        deps: [
          { pkg: "registry+zeta@2.0.0", dep_kinds: [{ kind: null, target: null }] },
          { pkg: "registry+alpha@1.2.3", dep_kinds: [{ kind: null, target: null }] },
        ],
      }, {
        id: "registry+zeta@2.0.0",
        deps: [],
      }, {
        id: "registry+alpha@1.2.3",
        deps: [],
      }],
    },
  };
  const lock = `
[[package]]
name = "zeta"
version = "2.0.0"
checksum = "${"b".repeat(64)}"

[[package]]
name = "alpha"
version = "1.2.3"
checksum = "${"a".repeat(64)}"
`;
  const documents = generateDocuments(metadata, parseLockChecksums(lock));
  assert.equal(documents.sbom.bomFormat, "CycloneDX");
  assert.equal(documents.sbom.specVersion, "1.6");
  assert.deepEqual(
    documents.sbom.components.map((component) => component.name),
    ["alpha", "zeta"],
  );
  assert.equal(documents.sbom.components[0].hashes[0].content, "a".repeat(64));
  assert.deepEqual(
    documents.licenses.packages.map((entry) => [entry.name, entry.license]),
    [["alpha", "Apache-2.0"], ["zeta", "NOASSERTION"]],
  );
  assert.equal(
    JSON.stringify(documents),
    JSON.stringify(generateDocuments(metadata, parseLockChecksums(lock))),
  );
});

test("includes only the union of runtime dependencies for shipped targets", () => {
  const root = {
    name: "release-glz",
    version: "1.0.0",
    id: "root",
    license: "MIT",
    source: null,
    repository: null,
  };
  const pkg = (name) => ({
    name,
    version: "1.0.0",
    id: name,
    license: "MIT",
    source: `registry+${name}`,
    repository: null,
  });
  const packages = [
    root,
    pkg("runtime"),
    pkg("linux-only"),
    pkg("windows-only"),
    pkg("dev-only"),
    pkg("build-only"),
    pkg("unsupported-target"),
  ];
  const snapshot = (targetDependency) => ({
    packages,
    workspace_members: ["root"],
    resolve: {
      nodes: [{
        id: "root",
        deps: [
          { pkg: "runtime", dep_kinds: [{ kind: null, target: null }] },
          { pkg: targetDependency, dep_kinds: [{ kind: null, target: "filtered" }] },
          { pkg: "dev-only", dep_kinds: [{ kind: "dev", target: null }] },
          { pkg: "build-only", dep_kinds: [{ kind: "build", target: null }] },
        ],
      }, {
        id: "runtime",
        deps: [],
      }, {
        id: targetDependency,
        deps: [],
      }],
    },
  });

  const documents = generateDocuments(
    [snapshot("linux-only"), snapshot("windows-only")],
    new Map(),
  );

  assert.deepEqual(
    documents.sbom.components.map((component) => component.name),
    ["linux-only", "runtime", "windows-only"],
  );
  assert.deepEqual(
    documents.licenses.packages.map((entry) => entry.name),
    ["linux-only", "runtime", "windows-only"],
  );
});

test("compares workspace identity independently of metadata member order", () => {
  const workspacePackage = (id, name) => ({
    name,
    version: "1.0.0",
    id,
    license: "MIT",
    source: null,
    repository: null,
  });
  const snapshot = (members) => ({
    packages: [workspacePackage("root", "release-glz"), workspacePackage("helper", "z-helper")],
    workspace_members: members,
    resolve: {
      nodes: [
        { id: "root", deps: [] },
        { id: "helper", deps: [] },
      ],
    },
  });

  assert.doesNotThrow(() => generateDocuments(
    [snapshot(["root", "helper"]), snapshot(["helper", "root"])],
    new Map(),
  ));
  assert.throws(
    () => generateDocuments(
      [snapshot(["root", "helper"]), snapshot(["root", "different"])],
      new Map(),
    ),
    /disagree on workspace identity/,
  );
});
