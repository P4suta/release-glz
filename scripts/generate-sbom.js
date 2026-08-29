"use strict";

const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const MAX_METADATA_BYTES = 32 * 1024 * 1024;
const MAX_LOCK_BYTES = 16 * 1024 * 1024;
const SHIPPED_TARGETS = Object.freeze([
  "x86_64-unknown-linux-musl",
  "aarch64-unknown-linux-musl",
  "x86_64-apple-darwin",
  "aarch64-apple-darwin",
  "x86_64-pc-windows-msvc",
  "aarch64-pc-windows-msvc",
]);

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

function generateDocuments(metadataInput, lockChecksums) {
  const snapshots = Array.isArray(metadataInput) ? metadataInput : [metadataInput];
  if (snapshots.length === 0) throw new Error("cargo metadata has no target snapshots");
  for (const metadata of snapshots) {
    if (!metadata || !Array.isArray(metadata.packages) ||
        !Array.isArray(metadata.workspace_members) ||
        !metadata.resolve || !Array.isArray(metadata.resolve.nodes)) {
      throw new Error("cargo metadata has an unsupported shape");
    }
  }
  const first = snapshots[0];
  const workspace = new Set(first.workspace_members);
  const root = first.packages
    .filter((pkg) => workspace.has(pkg.id))
    .sort((left, right) => left.name.localeCompare(right.name))[0];
  if (!root) throw new Error("cargo metadata has no workspace package");

  const packages = new Map();
  const runtime = new Set();
  for (const metadata of snapshots) {
    if (metadata.workspace_members.join("\0") !== first.workspace_members.join("\0")) {
      throw new Error("cargo metadata target snapshots disagree on workspace identity");
    }
    for (const pkg of metadata.packages) packages.set(pkg.id, pkg);
    for (const id of runtimeDependencyIds(metadata, root.id)) runtime.add(id);
  }
  const dependencies = [...runtime]
    .filter((id) => !workspace.has(id))
    .map((id) => packages.get(id) || missingPackage(id))
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

function runtimeDependencyIds(metadata, rootId) {
  const nodes = new Map(metadata.resolve.nodes.map((node) => [node.id, node]));
  if (!nodes.has(rootId)) throw new Error("cargo metadata resolve graph has no root package");
  const visited = new Set([rootId]);
  const pending = [rootId];
  while (pending.length > 0) {
    const id = pending.pop();
    const node = nodes.get(id);
    if (!node || !Array.isArray(node.deps)) {
      throw new Error(`cargo metadata resolve graph is incomplete at ${id}`);
    }
    for (const dependency of node.deps) {
      if (typeof dependency.pkg !== "string" || !Array.isArray(dependency.dep_kinds)) {
        throw new Error("cargo metadata dependency has an unsupported shape");
      }
      const runtime = dependency.dep_kinds.some(({ kind }) => kind === null || kind === "normal");
      if (runtime && !visited.has(dependency.pkg)) {
        visited.add(dependency.pkg);
        pending.push(dependency.pkg);
      }
    }
  }
  visited.delete(rootId);
  return visited;
}

function missingPackage(id) {
  throw new Error(`cargo metadata has no package record for runtime dependency ${id}`);
}

function main(outputDirectory = process.argv[2] || "dist") {
  const metadata = SHIPPED_TARGETS.map((target) => {
    const metadataBytes = childProcess.execFileSync(
      "cargo",
      ["metadata", "--format-version", "1", "--locked", "--filter-platform", target],
      { encoding: "utf8", maxBuffer: MAX_METADATA_BYTES },
    );
    return JSON.parse(metadataBytes);
  });
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

module.exports = {
  SHIPPED_TARGETS,
  generateDocuments,
  main,
  parseLockChecksums,
  runtimeDependencyIds,
};
