#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");

const KIB = 1024;
const MIB = 1024 * KIB;

const ENTRY_NAME = "release-glz";
const MAX_BINARY_BYTES = 128 * MIB;

// ustar header layout, from the "ustar Interchange Format" of POSIX.1-2024 `pax`.
// `*_AT` names are byte offsets within the header block.
const HEADER = Object.freeze({
  NAME_AT: 0,
  MODE_AT: 100,
  UID_AT: 108,
  GID_AT: 116,
  SIZE_AT: 124,
  MTIME_AT: 136,
  CHECKSUM_AT: 148,
  CHECKSUM_BYTES: 8,
  TYPE_AT: 156,
  MAGIC_AT: 257,
  VERSION_AT: 263,
  DEVMAJOR_AT: 329,
  DEVMINOR_AT: 337,
});

const BLOCK_BYTES = 512;
// A stock tar writes whole records of 20 blocks, so the archive ends where theirs would.
const RECORD_BYTES = 20 * BLOCK_BYTES;
const END_OF_ARCHIVE_BYTES = 2 * BLOCK_BYTES;
const SIZE_DIGITS = 11;
const CHECKSUM_DIGITS = 6;
const CHECKSUM_PLACEHOLDER = 0x20;
const MODE_EXECUTABLE = "0000755\0";
// Root's numeric owner and group with empty names, so the archive doesn't record who built it.
const ROOT_ID = "0000000\0";
// 1970-01-01 00:00 UTC in every time zone, so the archive doesn't record when it was built.
const EPOCH = "00000000000\0";
const TYPE_REGULAR_FILE = "0";
const MAGIC = "ustar\0";
const VERSION = "00";
const NO_DEVICE = "0000000\0";

// gzip member layout, from RFC 1952 section 2.3.
// The header names Unix as the OS on every host, and it records neither a time nor a compression level.
const GZIP_HEADER = Object.freeze([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3]);
const GZIP_TRAILER_BYTES = 8;
const ISIZE_MODULUS = 2 ** 32;
// Stored deflate blocks, from RFC 1951 section 3.2.4.
// The archive stores the binary uncompressed, as the Windows ZIP does, so its bytes depend on no compressor's version or CPU features.
// A block's LEN and NLEN are 16-bit fields.
const UINT16_MAX = 0xffff;
const MAX_STORED_BLOCK_BYTES = UINT16_MAX;
const STORED_BLOCK_HEADER_BYTES = 5;
const STORED_LEN_AT = 1;
const STORED_NLEN_AT = 3;
const STORED_BLOCK = 0;
const FINAL_STORED_BLOCK = 1;

function roundUp(value, unit) {
  return Math.ceil(value / unit) * unit;
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

function readBinary(binary) {
  const metadata = fs.lstatSync(binary);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size === 0 ||
    metadata.size > MAX_BINARY_BYTES
  ) {
    throw new Error("binary is not a bounded regular executable");
  }
  const contents = fs.readFileSync(binary);
  if (contents.length !== metadata.size) throw new Error("binary changed while it was read");
  return contents;
}

function ustarHeader(size) {
  const header = Buffer.alloc(BLOCK_BYTES);
  header.write(ENTRY_NAME, HEADER.NAME_AT, "ascii");
  header.write(MODE_EXECUTABLE, HEADER.MODE_AT, "ascii");
  header.write(ROOT_ID, HEADER.UID_AT, "ascii");
  header.write(ROOT_ID, HEADER.GID_AT, "ascii");
  header.write(`${size.toString(8).padStart(SIZE_DIGITS, "0")}\0`, HEADER.SIZE_AT, "ascii");
  header.write(EPOCH, HEADER.MTIME_AT, "ascii");
  header.write(TYPE_REGULAR_FILE, HEADER.TYPE_AT, "ascii");
  header.write(MAGIC, HEADER.MAGIC_AT, "ascii");
  header.write(VERSION, HEADER.VERSION_AT, "ascii");
  header.write(NO_DEVICE, HEADER.DEVMAJOR_AT, "ascii");
  header.write(NO_DEVICE, HEADER.DEVMINOR_AT, "ascii");
  header.fill(CHECKSUM_PLACEHOLDER, HEADER.CHECKSUM_AT, HEADER.CHECKSUM_AT + HEADER.CHECKSUM_BYTES);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  header.write(
    `${checksum.toString(8).padStart(CHECKSUM_DIGITS, "0")}\0 `,
    HEADER.CHECKSUM_AT,
    "ascii",
  );
  return header;
}

function ustarArchive(contents) {
  const entryBytes = BLOCK_BYTES + roundUp(contents.length, BLOCK_BYTES);
  const archive = Buffer.alloc(roundUp(entryBytes + END_OF_ARCHIVE_BYTES, RECORD_BYTES));
  ustarHeader(contents.length).copy(archive, 0);
  contents.copy(archive, BLOCK_BYTES);
  return archive;
}

function storedGzip(data) {
  const parts = [Buffer.from(GZIP_HEADER)];
  for (let offset = 0; offset < data.length; offset += MAX_STORED_BLOCK_BYTES) {
    const block = data.subarray(offset, offset + MAX_STORED_BLOCK_BYTES);
    const header = Buffer.alloc(STORED_BLOCK_HEADER_BYTES);
    header[0] = offset + block.length === data.length ? FINAL_STORED_BLOCK : STORED_BLOCK;
    header.writeUInt16LE(block.length, STORED_LEN_AT);
    header.writeUInt16LE(~block.length & UINT16_MAX, STORED_NLEN_AT);
    parts.push(header, block);
  }
  const trailer = Buffer.alloc(GZIP_TRAILER_BYTES);
  trailer.writeUInt32LE(zlib.crc32(data), 0);
  trailer.writeUInt32LE(data.length % ISIZE_MODULUS, 4);
  parts.push(trailer);
  return Buffer.concat(parts);
}

function createTarGz(binary, output) {
  const contents = readBinary(binary);
  outputMustNotExist(output);
  fs.writeFileSync(output, storedGzip(ustarArchive(contents)), { flag: "wx", mode: 0o600 });
}

function argumentsFrom(argv) {
  if (argv.length !== 4 || argv[0] !== "--binary" || argv[2] !== "--out" || !argv[1] || !argv[3]) {
    throw new Error("usage: --binary FILE --out FILE");
  }
  if (path.resolve(argv[1]) === path.resolve(argv[3])) {
    throw new Error("binary and output must be different paths");
  }
  return { binary: argv[1], output: argv[3] };
}

function main(argv = process.argv.slice(2)) {
  const options = argumentsFrom(argv);
  createTarGz(options.binary, options.output);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`Unix package generation failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { argumentsFrom, createTarGz };
