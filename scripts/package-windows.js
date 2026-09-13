#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const KIB = 1024;
const MIB = 1024 * KIB;

const ENTRY_NAME = "release-glz.exe";
const MAX_BINARY_BYTES = 128 * MIB;

// ZIP layout, from APPNOTE.TXT sections 4.3.7, 4.3.12, and 4.3.16. `*_AT`
// names are byte offsets within their record.
const LOCAL = Object.freeze({
  BYTES: 30,
  SIGNATURE: 0x04034b50,
  SIGNATURE_AT: 0,
  VERSION_NEEDED_AT: 4,
  FLAGS_AT: 6,
  METHOD_AT: 8,
  TIME_AT: 10,
  DATE_AT: 12,
  CRC32_AT: 14,
  COMPRESSED_SIZE_AT: 18,
  UNCOMPRESSED_SIZE_AT: 22,
  NAME_LENGTH_AT: 26,
  EXTRA_LENGTH_AT: 28,
});

const CENTRAL = Object.freeze({
  BYTES: 46,
  SIGNATURE: 0x02014b50,
  SIGNATURE_AT: 0,
  VERSION_MADE_BY_AT: 4,
  VERSION_NEEDED_AT: 6,
  FLAGS_AT: 8,
  METHOD_AT: 10,
  TIME_AT: 12,
  DATE_AT: 14,
  CRC32_AT: 16,
  COMPRESSED_SIZE_AT: 20,
  UNCOMPRESSED_SIZE_AT: 24,
  NAME_LENGTH_AT: 28,
  EXTRA_LENGTH_AT: 30,
  COMMENT_LENGTH_AT: 32,
  DISK_NUMBER_AT: 34,
  INTERNAL_ATTRIBUTES_AT: 36,
  EXTERNAL_ATTRIBUTES_AT: 38,
  LOCAL_HEADER_OFFSET_AT: 42,
});

const END = Object.freeze({
  BYTES: 22,
  SIGNATURE: 0x06054b50,
  SIGNATURE_AT: 0,
  DISK_NUMBER_AT: 4,
  CENTRAL_START_DISK_AT: 6,
  DISK_ENTRY_COUNT_AT: 8,
  TOTAL_ENTRY_COUNT_AT: 10,
  CENTRAL_SIZE_AT: 12,
  CENTRAL_OFFSET_AT: 16,
  COMMENT_LENGTH_AT: 20,
});

// Version 2.0, the minimum that reads a stored entry.
const VERSION_NEEDED = 20;
// Unix host (3) with the same 2.0, which is what carries the file mode.
const VERSION_MADE_BY_UNIX = 0x0314;
const FLAG_UTF8_NAMES = 0x0800;
const METHOD_STORED = 0;
// 1980-01-01 00:00, the earliest instant a ZIP date can hold, so the archive
// does not record when it was built.
const DOS_DATE = 0x0021;
const DOS_TIME = 0;
const UNIX_MODE_EXECUTABLE = 0o100755;
const UNIX_MODE_SHIFT = 16;
const NO_EXTRA_FIELD = 0;
const NO_COMMENT = 0;
const NO_INTERNAL_ATTRIBUTES = 0;
const FIRST_DISK = 0;
const FIRST_ENTRY_OFFSET = 0;
const ENTRY_COUNT = 1;
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

  const local = Buffer.alloc(LOCAL.BYTES);
  local.writeUInt32LE(LOCAL.SIGNATURE, LOCAL.SIGNATURE_AT);
  local.writeUInt16LE(VERSION_NEEDED, LOCAL.VERSION_NEEDED_AT);
  local.writeUInt16LE(FLAG_UTF8_NAMES, LOCAL.FLAGS_AT);
  local.writeUInt16LE(METHOD_STORED, LOCAL.METHOD_AT);
  local.writeUInt16LE(DOS_TIME, LOCAL.TIME_AT);
  local.writeUInt16LE(DOS_DATE, LOCAL.DATE_AT);
  local.writeUInt32LE(checksum, LOCAL.CRC32_AT);
  local.writeUInt32LE(contents.length, LOCAL.COMPRESSED_SIZE_AT);
  local.writeUInt32LE(contents.length, LOCAL.UNCOMPRESSED_SIZE_AT);
  local.writeUInt16LE(name.length, LOCAL.NAME_LENGTH_AT);
  local.writeUInt16LE(NO_EXTRA_FIELD, LOCAL.EXTRA_LENGTH_AT);

  const central = Buffer.alloc(CENTRAL.BYTES);
  central.writeUInt32LE(CENTRAL.SIGNATURE, CENTRAL.SIGNATURE_AT);
  central.writeUInt16LE(VERSION_MADE_BY_UNIX, CENTRAL.VERSION_MADE_BY_AT);
  central.writeUInt16LE(VERSION_NEEDED, CENTRAL.VERSION_NEEDED_AT);
  central.writeUInt16LE(FLAG_UTF8_NAMES, CENTRAL.FLAGS_AT);
  central.writeUInt16LE(METHOD_STORED, CENTRAL.METHOD_AT);
  central.writeUInt16LE(DOS_TIME, CENTRAL.TIME_AT);
  central.writeUInt16LE(DOS_DATE, CENTRAL.DATE_AT);
  central.writeUInt32LE(checksum, CENTRAL.CRC32_AT);
  central.writeUInt32LE(contents.length, CENTRAL.COMPRESSED_SIZE_AT);
  central.writeUInt32LE(contents.length, CENTRAL.UNCOMPRESSED_SIZE_AT);
  central.writeUInt16LE(name.length, CENTRAL.NAME_LENGTH_AT);
  central.writeUInt16LE(NO_EXTRA_FIELD, CENTRAL.EXTRA_LENGTH_AT);
  central.writeUInt16LE(NO_COMMENT, CENTRAL.COMMENT_LENGTH_AT);
  central.writeUInt16LE(FIRST_DISK, CENTRAL.DISK_NUMBER_AT);
  central.writeUInt16LE(NO_INTERNAL_ATTRIBUTES, CENTRAL.INTERNAL_ATTRIBUTES_AT);
  central.writeUInt32LE((UNIX_MODE_EXECUTABLE << UNIX_MODE_SHIFT) >>> 0,
    CENTRAL.EXTERNAL_ATTRIBUTES_AT);
  central.writeUInt32LE(FIRST_ENTRY_OFFSET, CENTRAL.LOCAL_HEADER_OFFSET_AT);

  const centralOffset = local.length + name.length + contents.length;
  const centralSize = central.length + name.length;
  const end = Buffer.alloc(END.BYTES);
  end.writeUInt32LE(END.SIGNATURE, END.SIGNATURE_AT);
  end.writeUInt16LE(FIRST_DISK, END.DISK_NUMBER_AT);
  end.writeUInt16LE(FIRST_DISK, END.CENTRAL_START_DISK_AT);
  end.writeUInt16LE(ENTRY_COUNT, END.DISK_ENTRY_COUNT_AT);
  end.writeUInt16LE(ENTRY_COUNT, END.TOTAL_ENTRY_COUNT_AT);
  end.writeUInt32LE(centralSize, END.CENTRAL_SIZE_AT);
  end.writeUInt32LE(centralOffset, END.CENTRAL_OFFSET_AT);
  end.writeUInt16LE(NO_COMMENT, END.COMMENT_LENGTH_AT);

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
