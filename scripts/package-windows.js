#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const ENTRY_NAME = "release-glz.exe";
const MAX_BINARY_BYTES = 128 * 1024 * 1024;
const CRC_TABLE = Object.freeze(Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
  }
  return value >>> 0;
}));

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function outputMustNotExist(output) {
  try {
    fs.lstatSync(output);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  throw new Error("output already exists");
}

function createStoredZip(binary, output) {
  const metadata = fs.lstatSync(binary);
  if (!metadata.isFile() || metadata.isSymbolicLink() ||
      metadata.size === 0 || metadata.size > MAX_BINARY_BYTES) {
    throw new Error("binary is not a bounded regular executable");
  }
  outputMustNotExist(output);
  const contents = fs.readFileSync(binary);
  const name = Buffer.from(ENTRY_NAME, "utf8");
  const checksum = crc32(contents);
  const dosTime = 0;
  const dosDate = 0x0021; // 1980-01-01, the earliest date representable by ZIP.

  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0x0800, 6);
  local.writeUInt16LE(0, 8);
  local.writeUInt16LE(dosTime, 10);
  local.writeUInt16LE(dosDate, 12);
  local.writeUInt32LE(checksum, 14);
  local.writeUInt32LE(contents.length, 18);
  local.writeUInt32LE(contents.length, 22);
  local.writeUInt16LE(name.length, 26);
  local.writeUInt16LE(0, 28);

  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(0x0314, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0x0800, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt16LE(dosTime, 12);
  central.writeUInt16LE(dosDate, 14);
  central.writeUInt32LE(checksum, 16);
  central.writeUInt32LE(contents.length, 20);
  central.writeUInt32LE(contents.length, 24);
  central.writeUInt16LE(name.length, 28);
  central.writeUInt16LE(0, 30);
  central.writeUInt16LE(0, 32);
  central.writeUInt16LE(0, 34);
  central.writeUInt16LE(0, 36);
  central.writeUInt32LE((0o100755 << 16) >>> 0, 38);
  central.writeUInt32LE(0, 42);

  const centralOffset = local.length + name.length + contents.length;
  const centralSize = central.length + name.length;
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(centralOffset, 16);
  end.writeUInt16LE(0, 20);

  fs.writeFileSync(output, Buffer.concat([local, name, contents, central, name, end]), {
    flag: "wx",
    mode: 0o600,
  });
}

function argumentsFrom(argv) {
  if (argv.length !== 4 || argv[0] !== "--binary" || argv[2] !== "--out" ||
      !argv[1] || !argv[3]) {
    throw new Error("usage: --binary FILE --out FILE");
  }
  if (path.resolve(argv[1]) === path.resolve(argv[3])) {
    throw new Error("binary and output must be different paths");
  }
  return { binary: argv[1], output: argv[3] };
}

function main(argv = process.argv.slice(2)) {
  const options = argumentsFrom(argv);
  createStoredZip(options.binary, options.output);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`Windows package generation failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { argumentsFrom, createStoredZip, crc32 };
