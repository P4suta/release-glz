"use strict";

const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const MAX_METADATA_BYTES = 32 * 1024 * 1024;
const MAX_LOCK_BYTES = 16 * 1024 * 1024;

function packageKey(name, version) {
  return `${name}\0${version}`;
}

function parseLockChecksums(source) {
  if (Buffer.byteLength(source, "utf8") > MAX_LOCK_BYTES) {
    throw new Error("Cargo.lock exceeds the 16 MiB evidence limit");
  }
  const checksums = new Map();
  for (const block of source.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const value = (field) => {
      const match = block.match(new RegExp(`^${field}\\s*=\\s*"([^"]+)"\\s*$`, "m"));
      return match?.[1];
    };
    const name = value("name");
    const version = value("version");
    const checksum = value("checksum");
    if (!name || !version || !checksum) continue;
    if (!/^[0-9a-f]{64}$/.test(checksum)) {
      throw new Error(`Cargo.lock has an invalid checksum for ${name} ${version}`);
    }
    const key = packageKey(name, version);
    if (checksums.has(key) && checksums.get(key) !== checksum) {
      throw new Error(`Cargo.lock has conflicting checksums for ${name} ${version}`);
    }
    checksums.set(key, checksum);
  }
  return checksums;
}

function componentFor(pkg, checksum) {
  const purl = `pkg:cargo/${encodeURIComponent(pkg.name)}@${encodeURIComponent(pkg.version)}`;
  const component = {
    type: "library",
    "bom-ref": purl,
    name: pkg.name,
    version: pkg.version,
    purl,
    licenses: [{ expression: pkg.license || "NOASSERTION" }],
  };
  if (checksum) component.hashes = [{ alg: "SHA-256", content: checksum }];
  if (pkg.repository) {
    component.externalReferences = [{ type: "vcs", url: pkg.repository }];
  }
  if (pkg.source) {
    component.properties = [{ name: "cargo:source", value: pkg.source }];
  }
  return component;
}

function generateDocuments(metadata, lockChecksums) {
  if (!metadata || !Array.isArray(metadata.packages) || !Array.isArray(metadata.workspace_members)) {
    throw new Error("cargo metadata has an unsupported shape");
  }
  const workspace = new Set(metadata.workspace_members);
  const root = metadata.packages
    .filter((pkg) => workspace.has(pkg.id))
    .sort((left, right) => left.name.localeCompare(right.name))[0];
  if (!root) throw new Error("cargo metadata has no workspace package");
  const dependencies = metadata.packages
    .filter((pkg) => !workspace.has(pkg.id))
    .sort((left, right) =>
      left.name.localeCompare(right.name)
        || left.version.localeCompare(right.version)
        || String(left.source || "").localeCompare(String(right.source || ""))
    );
  const components = dependencies.map((pkg) =>
    componentFor(pkg, lockChecksums.get(packageKey(pkg.name, pkg.version)))
  );
  return {
    sbom: {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      version: 1,
      metadata: {
        component: {
          type: "application",
          "bom-ref": `pkg:cargo/${encodeURIComponent(root.name)}@${encodeURIComponent(root.version)}`,
          name: root.name,
          version: root.version,
          licenses: [{ expression: root.license || "NOASSERTION" }],
        },
      },
      components,
    },
    licenses: {
      schema: "third-party-licenses/v1",
      package: root.name,
      version: root.version,
      packages: dependencies.map((pkg) => ({
        name: pkg.name,
        version: pkg.version,
        license: pkg.license || "NOASSERTION",
        source: pkg.source || null,
        repository: pkg.repository || null,
      })),
    },
  };
}

function main(outputDirectory = process.argv[2] || "dist") {
  const metadataBytes = childProcess.execFileSync(
    "cargo",
    ["metadata", "--format-version", "1", "--locked"],
    { encoding: "utf8", maxBuffer: MAX_METADATA_BYTES },
  );
  const metadata = JSON.parse(metadataBytes);
  const lock = fs.readFileSync("Cargo.lock", "utf8");
  const documents = generateDocuments(metadata, parseLockChecksums(lock));
  fs.mkdirSync(outputDirectory, { recursive: true });
  fs.writeFileSync(
    path.join(outputDirectory, "release-glz.cdx.json"),
    `${JSON.stringify(documents.sbom, null, 2)}\n`,
    { encoding: "utf8", flag: "wx" },
  );
  fs.writeFileSync(
    path.join(outputDirectory, "THIRD_PARTY_LICENSES.json"),
    `${JSON.stringify(documents.licenses, null, 2)}\n`,
    { encoding: "utf8", flag: "wx" },
  );
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`evidence generation failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { generateDocuments, main, parseLockChecksums };
