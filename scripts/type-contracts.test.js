// @ts-check
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const ROOT = path.join(__dirname, "..");
const CHECKED_DIRECTORIES = ["action", "scripts"];
const EXACT_VERSION = /^\d+\.\d+\.\d+$/;
const NAMED_FUNCTION = /^\s*(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/;
const RETURN_TAG = /@(?:returns?|type)\b/;

/**
 * Every JavaScript file of the Action and the release scripts, relative to the repository root.
 * @returns {string[]}
 */
function javascriptFiles() {
  return CHECKED_DIRECTORIES.flatMap((directory) =>
    fs
      .readdirSync(path.join(ROOT, directory))
      .filter((name) => name.endsWith(".js"))
      .map((name) => `${directory}/${name}`),
  ).sort();
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * @param {string} file
 * @returns {Record<string, unknown>}
 */
function readObject(file) {
  const value = JSON.parse(fs.readFileSync(path.join(ROOT, file), "utf8"));
  assert.ok(isRecord(value), `${file} isn't a JSON object`);
  return value;
}

/**
 * The JSDoc block that ends on the line before `index`, or `undefined` when there is none.
 * @param {string[]} lines
 * @param {number} index
 * @returns {string | undefined}
 */
function jsdocBefore(lines, index) {
  const end = lines[index - 1];
  if (end === undefined || !end.trim().endsWith("*/")) return undefined;
  for (let start = index - 1; start >= 0; start -= 1) {
    const line = (lines[start] ?? "").trim();
    if (line.startsWith("/**")) return lines.slice(start, index).join("\n");
    if (start !== index - 1 && !line.startsWith("*")) return undefined;
  }
  return undefined;
}

/**
 * The named functions in `source` whose JSDoc doesn't declare what they return.
 * @param {string} source
 * @returns {string[]}
 */
function functionsWithoutReturnTypes(source) {
  const lines = source.split(/\r?\n/);
  /** @type {string[]} */
  const missing = [];
  for (const [index, line] of lines.entries()) {
    const name = NAMED_FUNCTION.exec(line)?.[1];
    if (name === undefined) continue;
    const jsdoc = jsdocBefore(lines, index);
    if (jsdoc === undefined || !RETURN_TAG.test(jsdoc)) missing.push(`${name}:${index + 1}`);
  }
  return missing;
}

test("every JavaScript file opts into checking and the project checks it", () => {
  const files = javascriptFiles();
  assert.ok(files.includes("action/index.js"));
  assert.ok(files.includes("scripts/type-contracts.test.js"));
  for (const file of files) {
    const head = fs.readFileSync(path.join(ROOT, file), "utf8").split("\n").slice(0, 3);
    assert.ok(head.includes("// @ts-check"), `${file} doesn't start with // @ts-check`);
  }
  const config = readObject("tsconfig.json");
  assert.deepEqual(config.include, ["action/*.js", "scripts/*.js"]);
  const options = config.compilerOptions;
  assert.ok(isRecord(options), "tsconfig.json has no compilerOptions");
  for (const option of ["allowJs", "checkJs", "noEmit", "strict", "noUncheckedIndexedAccess"]) {
    assert.equal(options[option], true, `tsconfig.json leaves ${option} off`);
  }
});

test("the compiler and the Node types are pinned outside the Action", () => {
  const manifest = readObject("package.json");
  assert.equal(manifest.dependencies, undefined);
  const tools = manifest.devDependencies;
  assert.ok(isRecord(tools), "package.json pins no development tools");
  assert.deepEqual(Object.keys(tools).sort(), ["@types/node", "typescript"]);
  const packages = readObject("package-lock.json").packages;
  assert.ok(isRecord(packages), "package-lock.json lists no packages");
  for (const [name, version] of Object.entries(tools)) {
    assert.equal(typeof version, "string");
    assert.match(String(version), EXACT_VERSION, `${name} isn't pinned to one version`);
    /** @type {unknown} */
    const locked = packages[`node_modules/${name}`];
    assert.ok(isRecord(locked), `package-lock.json doesn't lock ${name}`);
    assert.equal(locked.version, version, `package-lock.json doesn't lock ${name} ${version}`);
    assert.match(
      String(locked.integrity),
      /^sha512-/,
      `package-lock.json has no digest for ${name}`,
    );
  }
  const action = readObject("action/package.json");
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    assert.equal(action[field], undefined, `the Action declares ${field}`);
  }
});

test("every named function declares what it returns", () => {
  for (const file of javascriptFiles()) {
    const source = fs.readFileSync(path.join(ROOT, file), "utf8");
    assert.deepEqual(functionsWithoutReturnTypes(source), [], `${file} has undeclared returns`);
  }
});

test("the return check finds a function without a declared return", () => {
  const source = [
    "/**",
    " * @param {number} value",
    " * @returns {number}",
    " */",
    "function declared(value) {",
    "  return value;",
    "}",
    "",
    "/** @param {number} value */",
    "function undeclared(value) {",
    "  return value;",
    "}",
    "",
    "async function bare() {}",
  ].join("\n");
  assert.deepEqual(functionsWithoutReturnTypes(source), ["undeclared:10", "bare:14"]);
});
