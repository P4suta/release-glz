use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::Archive;
use toml_edit::{DocumentMut, value};

pub type NormalizedArtifact = BTreeMap<String, Vec<u8>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveLimits {
    pub max_entries: usize,
    pub max_entry_bytes: u64,
    pub max_total_bytes: u64,
    pub max_archive_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_entries: 20_000,
            max_entry_bytes: 64 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_archive_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexTarballValidation {
    pub outer_checksum: String,
    pub inner_checksum: String,
    pub content_entries: usize,
    pub expanded_bytes: u64,
}

pub fn validate_hex_tarball(bytes: &[u8], limits: ArchiveLimits) -> Result<HexTarballValidation> {
    if bytes.len() as u64 > limits.max_archive_bytes {
        bail!("Hex package exceeds the archive byte limit");
    }
    let outer =
        read_tar_files(Cursor::new(bytes), limits, false).context("unsafe Hex package tarball")?;
    let expected: BTreeSet<_> = ["CHECKSUM", "VERSION", "contents.tar.gz", "metadata.config"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let actual: BTreeSet<_> = outer.keys().cloned().collect();
    if actual != expected {
        bail!(
            "Hex package entries must be exactly VERSION, metadata.config, contents.tar.gz, and CHECKSUM"
        );
    }
    if trim_ascii(&outer["VERSION"]) != b"3" {
        bail!("unsupported Hex package tarball VERSION");
    }
    let mut inner = Sha256::new();
    inner.update(&outer["VERSION"]);
    inner.update(&outer["metadata.config"]);
    inner.update(&outer["contents.tar.gz"]);
    let inner_checksum = format!("{:X}", inner.finalize());
    let recorded =
        std::str::from_utf8(trim_ascii(&outer["CHECKSUM"])).context("Hex CHECKSUM is not ASCII")?;
    if recorded != inner_checksum {
        bail!("Hex package inner checksum mismatch");
    }
    let contents = read_tar_gz_files(&outer["contents.tar.gz"], limits)
        .context("unsafe Hex contents archive")?;
    let expanded_bytes = contents
        .values()
        .map(|contents| contents.len() as u64)
        .sum();
    Ok(HexTarballValidation {
        outer_checksum: format!("{:x}", Sha256::digest(bytes)),
        inner_checksum: inner_checksum.to_ascii_lowercase(),
        content_entries: contents.len(),
        expanded_bytes,
    })
}

pub fn fingerprint_tar_gz(bytes: &[u8]) -> Result<String> {
    let files = read_tar_gz_files(bytes, ArchiveLimits::default())?;
    fingerprint_files(files)
}

pub fn validate_docs_tarball(bytes: &[u8], limits: ArchiveLimits) -> Result<()> {
    read_tar_gz_files(bytes, limits).context("unsafe documentation archive")?;
    Ok(())
}

pub fn unpack_tar_bytes(bytes: &[u8], destination: &Path, limits: ArchiveLimits) -> Result<()> {
    if bytes.len() as u64 > limits.max_archive_bytes {
        bail!("tar archive exceeds the byte limit");
    }
    let files = read_tar_files(Cursor::new(bytes), limits, true)?;
    fs::create_dir_all(destination)?;
    for (relative, contents) in files {
        let path = destination.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)?;
    }
    Ok(())
}

pub fn normalize_hex_tarball(bytes: &[u8]) -> Result<NormalizedArtifact> {
    let contents = inner_contents(bytes)?;
    normalize_contents_tar_gz(&contents)
}

pub fn fingerprint_hex_tarball(bytes: &[u8]) -> Result<String> {
    let normalized = normalize_hex_tarball(bytes)?;
    let mut digest = Sha256::new();
    for (path, contents) in normalized {
        digest.update((path.len() as u64).to_be_bytes());
        digest.update(path.as_bytes());
        digest.update((contents.len() as u64).to_be_bytes());
        digest.update(contents);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub fn artifacts_equal(old: &[u8], new: &[u8]) -> Result<bool> {
    Ok(normalize_hex_tarball(old)? == normalize_hex_tarball(new)?)
}

/// Normalize the publish inputs in a package directory without invoking the
/// compiler. This is used to recover a missing release tag from git history.
pub fn normalize_package_dir(package_dir: &Path) -> Result<NormalizedArtifact> {
    let mut output = BTreeMap::new();
    collect_publish_inputs(package_dir, package_dir, &mut output)?;
    if let Some(contents) = output.get_mut("gleam.toml") {
        let source = String::from_utf8(std::mem::take(contents))?;
        let mut document = source.parse::<DocumentMut>()?;
        document["version"] = value("<release-glz-version>");
        *contents = document.to_string().into_bytes();
    }
    Ok(output)
}

pub fn interface_from_docs_tarball(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let files = read_tar_gz_files(bytes, ArchiveLimits::default())?;
    Ok(files
        .into_iter()
        .find(|(path, _)| {
            Path::new(path)
                .file_name()
                .is_some_and(|name| name == "package-interface.json")
        })
        .map(|(_, contents)| contents))
}

pub fn unpack_hex_source(bytes: &[u8], destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    let outer = checked_outer_files(bytes, ArchiveLimits::default())?;
    let files = read_tar_gz_files(&outer["contents.tar.gz"], ArchiveLimits::default())?;
    let generated_erlang = generated_erlang_paths(files.keys());
    for (relative, contents) in files {
        if generated_erlang.contains(&relative) {
            continue;
        }
        let path = destination.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)?;
    }
    Ok(())
}

pub fn inner_contents(bytes: &[u8]) -> Result<Vec<u8>> {
    let files = checked_outer_files(bytes, ArchiveLimits::default())?;
    files
        .get("contents.tar.gz")
        .cloned()
        .context("Hex package tarball has no `contents.tar.gz`")
}

pub fn normalize_contents_tar_gz(bytes: &[u8]) -> Result<NormalizedArtifact> {
    let raw = read_tar_gz_files(bytes, ArchiveLimits::default())?;

    let generated_erlang = generated_erlang_paths(raw.keys());
    let mut normalized = BTreeMap::new();
    for (path, mut contents) in raw {
        if is_generated(&path, &generated_erlang) {
            continue;
        }
        if path == "gleam.toml" {
            let source = String::from_utf8(contents).context("gleam.toml is not UTF-8")?;
            let mut document = source
                .parse::<DocumentMut>()
                .context("invalid gleam.toml in Hex tarball")?;
            document["version"] = value("<release-glz-version>");
            contents = document.to_string().into_bytes();
        }
        normalized.insert(path, contents);
    }
    Ok(normalized)
}

fn checked_outer_files(bytes: &[u8], limits: ArchiveLimits) -> Result<BTreeMap<String, Vec<u8>>> {
    validate_hex_tarball(bytes, limits)?;
    read_tar_files(Cursor::new(bytes), limits, false)
}

fn read_tar_gz_files(bytes: &[u8], limits: ArchiveLimits) -> Result<BTreeMap<String, Vec<u8>>> {
    if bytes.len() as u64 > limits.max_archive_bytes {
        bail!("compressed archive exceeds the byte limit");
    }
    let decompressed_limit = limits
        .max_total_bytes
        .saturating_add((limits.max_entries as u64).saturating_mul(1_024));
    let decoder = LimitedReader::new(GzDecoder::new(Cursor::new(bytes)), decompressed_limit);
    read_tar_files(decoder, limits, true)
}

fn read_tar_files<R: Read>(
    reader: R,
    limits: ArchiveLimits,
    allow_directories: bool,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut output = BTreeMap::new();
    let mut total = 0_u64;
    let mut pending_path = None;
    let mut archive = Archive::new(reader);
    for (index, entry) in archive
        .entries()
        .context("invalid tar archive")?
        .raw(true)
        .enumerate()
    {
        if index >= limits.max_entries {
            bail!("archive exceeds the entry limit");
        }
        let mut entry = entry.context("invalid tar entry")?;
        let kind = entry.header().entry_type();
        if matches!(kind.as_byte(), b'g' | b'K') {
            bail!("archive extension headers are not supported");
        }
        let size = entry.size();
        if size > limits.max_entry_bytes {
            bail!("archive entry exceeds the per-file limit");
        }
        total = total
            .checked_add(size)
            .context("archive expanded size overflow")?;
        if total > limits.max_total_bytes {
            bail!("archive exceeds the expanded byte limit");
        }
        if matches!(kind.as_byte(), b'x' | b'L') {
            if pending_path.is_some() {
                bail!("archive contains consecutive path extension headers");
            }
            let contents = read_entry_contents(&mut entry, size, "archive path extension")?;
            let raw_path = if kind.as_byte() == b'L' {
                parse_gnu_long_path(&contents)?
            } else {
                parse_pax_path(&contents)?
            };
            pending_path = Some(safe_archive_path_value(raw_path)?);
            continue;
        }
        let path = match pending_path.take() {
            Some(path) => path,
            None => safe_archive_path(&entry)?,
        };
        if kind.is_dir() && allow_directories {
            if size != 0 {
                bail!("archive directory `{path}` has content");
            }
            continue;
        }
        if !kind.is_file() {
            bail!("archive entry `{path}` is not a regular file");
        }
        if output.contains_key(&path) {
            bail!("archive contains duplicate entry `{path}`");
        }
        let contents = read_entry_contents(&mut entry, size, &format!("archive entry `{path}`"))?;
        output.insert(path, contents);
    }
    if pending_path.is_some() {
        bail!("archive has a dangling path extension header");
    }
    Ok(output)
}

fn safe_archive_path<R: Read>(entry: &tar::Entry<'_, R>) -> Result<String> {
    let raw = entry.path_bytes();
    safe_archive_path_value(&raw)
}

fn safe_archive_path_value(raw: &[u8]) -> Result<String> {
    let value = std::str::from_utf8(raw)
        .context("archive path is not UTF-8")?
        .trim_end_matches('/');
    if value.contains('\\')
        || value.contains('\0')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || value.as_bytes().get(1) == Some(&b':')
    {
        bail!("archive contains unsafe path `{value}`");
    }
    Ok(value.to_owned())
}

fn read_entry_contents<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    size: u64,
    description: &str,
) -> Result<Vec<u8>> {
    let capacity = usize::try_from(size).context("archive entry does not fit in memory")?;
    let mut contents = Vec::with_capacity(capacity);
    entry
        .read_to_end(&mut contents)
        .with_context(|| format!("failed to read {description}"))?;
    if contents.len() as u64 != size {
        bail!("{description} has an inconsistent size");
    }
    Ok(contents)
}

fn parse_gnu_long_path(contents: &[u8]) -> Result<&[u8]> {
    let Some((&terminator, path)) = contents.split_last() else {
        bail!("GNU long path extension is empty");
    };
    if terminator != 0 || path.is_empty() || path.contains(&0) {
        bail!("GNU long path extension is malformed");
    }
    Ok(path)
}

fn parse_pax_path(contents: &[u8]) -> Result<&[u8]> {
    let space = contents
        .iter()
        .position(|byte| *byte == b' ')
        .context("PAX record has no length separator")?;
    let length_bytes = &contents[..space];
    if length_bytes.is_empty()
        || length_bytes.first() == Some(&b'0')
        || !length_bytes.iter().all(u8::is_ascii_digit)
    {
        bail!("PAX record has an invalid length");
    }
    let length = std::str::from_utf8(length_bytes)?
        .parse::<usize>()
        .context("PAX record length is too large")?;
    if length != contents.len() || contents.last() != Some(&b'\n') {
        bail!("PAX record length is inconsistent");
    }
    let record_start = space
        .checked_add(1)
        .context("PAX record length is inconsistent")?;
    let record_end = contents
        .len()
        .checked_sub(1)
        .context("PAX record length is inconsistent")?;
    let record = contents
        .get(record_start..record_end)
        .context("PAX record length is inconsistent")?;
    let equals = record
        .iter()
        .position(|byte| *byte == b'=')
        .context("PAX record has no key/value separator")?;
    let key = std::str::from_utf8(&record[..equals]).context("PAX key is not UTF-8")?;
    if key != "path" {
        bail!("unsupported PAX key `{key}`");
    }
    Ok(&record[equals + 1..])
}

fn fingerprint_files(files: BTreeMap<String, Vec<u8>>) -> Result<String> {
    let mut digest = Sha256::new();
    for (path, contents) in files {
        digest.update((path.len() as u64).to_be_bytes());
        digest.update(path.as_bytes());
        digest.update((contents.len() as u64).to_be_bytes());
        digest.update(contents);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

struct LimitedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> LimitedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::other(
                "archive decompression limit exceeded",
            ));
        }
        let length = buffer.len().min(self.remaining as usize);
        let read = self.inner.read(&mut buffer[..length])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

fn generated_erlang_paths<'a>(paths: impl Iterator<Item = &'a String>) -> BTreeSet<String> {
    paths
        .filter_map(|path| path.strip_prefix("src/")?.strip_suffix(".gleam"))
        .map(|module| format!("src/{}.erl", module.replace('/', "@")))
        .collect()
}

fn is_generated(path: &str, generated_erlang: &BTreeSet<String>) -> bool {
    generated_erlang.contains(path)
        || path.starts_with("include/")
        || (path.starts_with("src/") && path.ends_with(".app.src"))
}

fn collect_publish_inputs(
    root: &Path,
    directory: &Path,
    output: &mut NormalizedArtifact,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        let file_type = entry.file_type()?;
        let include_dir = relative == "src"
            || relative == "priv"
            || relative.starts_with("src/")
            || relative.starts_with("priv/");
        if file_type.is_dir() {
            if include_dir {
                collect_publish_inputs(root, &path, output)?;
            }
            continue;
        }
        if !file_type.is_file() {
            bail!("publish input `{}` is not a regular file", path.display());
        }
        let root_file = !relative.contains('/') && is_publish_root_file(&relative);
        if include_dir || root_file {
            output.insert(relative, fs::read(path)?);
        }
    }
    Ok(())
}

fn is_publish_root_file(path: &str) -> bool {
    matches!(
        path,
        "gleam.toml"
            | "README"
            | "README.md"
            | "README.txt"
            | "LICENSE"
            | "LICENCE"
            | "LICENSE.md"
            | "LICENCE.md"
            | "LICENSE.txt"
            | "LICENCE.txt"
            | "NOTICE"
            | "NOTICE.md"
            | "NOTICE.txt"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    use std::io::{Cursor, Read};

    fn package(version: &str, source: &str, generated: &str) -> Vec<u8> {
        let mut contents = Vec::new();
        {
            let encoder = GzEncoder::new(&mut contents, Compression::default());
            let mut tar = tar::Builder::new(encoder);
            add(
                &mut tar,
                "gleam.toml",
                format!("name = \"x\"\nversion = \"{version}\"\n").as_bytes(),
            );
            add(&mut tar, "src/x.gleam", source.as_bytes());
            add(&mut tar, "src/x.erl", generated.as_bytes());
            add(&mut tar, "include/x_Type.hrl", generated.as_bytes());
            tar.finish().unwrap();
        }
        let mut outer = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut outer);
            let version = b"3";
            let metadata = b"metadata";
            let mut digest = Sha256::new();
            digest.update(version);
            digest.update(metadata);
            digest.update(&contents);
            let checksum = format!("{:X}", digest.finalize());
            add(&mut tar, "VERSION", version);
            add(&mut tar, "metadata.config", metadata);
            add(&mut tar, "contents.tar.gz", &contents);
            add(&mut tar, "CHECKSUM", checksum.as_bytes());
            tar.finish().unwrap();
        }
        outer
    }

    fn add<W: Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, path, bytes).unwrap();
    }

    #[test]
    fn version_and_generated_code_are_ignored() {
        let old = package("1.0.0", "pub fn one() { 1 }", "old compiler output");
        let new = package("2.0.0", "pub fn one() { 1 }", "new compiler output");
        assert!(artifacts_equal(&old, &new).unwrap());
    }

    #[test]
    fn source_changes_are_detected() {
        let old = package("1.0.0", "pub fn one() { 1 }", "same");
        let new = package("1.0.1", "pub fn one() { 2 }", "same");
        assert!(!artifacts_equal(&old, &new).unwrap());
    }

    #[test]
    fn limited_reader_consumes_the_budget_exactly_once() {
        let mut reader = LimitedReader::new(Cursor::new(b"abcdef"), 4);
        let mut exact = [0_u8; 4];
        reader.read_exact(&mut exact).unwrap();
        assert_eq!(&exact, b"abcd");
        let mut extra = [0_u8; 1];
        let error = reader.read(&mut extra).unwrap_err();
        assert!(error.to_string().contains("limit exceeded"));
    }

    #[test]
    fn gnu_long_path_rejects_each_malformed_terminator_and_path_boundary() {
        for malformed in [
            b"safe".as_slice(),
            b"\0".as_slice(),
            b"safe\0tail\0".as_slice(),
        ] {
            assert!(parse_gnu_long_path(malformed).is_err(), "{malformed:?}");
        }
        assert_eq!(parse_gnu_long_path(b"safe\0").unwrap(), b"safe");
    }

    #[test]
    fn pax_length_rejects_a_leading_zero_independently_of_digit_validation() {
        assert!(parse_pax_path(b"011 path=a\n").is_err());
        assert_eq!(parse_pax_path(b"10 path=a\n").unwrap(), b"a");
        assert_eq!(parse_pax_path(b"8 path=\n").unwrap(), b"");
        assert!(parse_pax_path(b"10 path=ab").is_err());
        assert!(parse_pax_path(b"10 path=a\n10 path=b\n").is_err());

        let zero = parse_pax_path(b"0 ").unwrap_err().to_string();
        assert!(zero.contains("invalid length"), "{zero}");
    }
}
