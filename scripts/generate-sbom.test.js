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
