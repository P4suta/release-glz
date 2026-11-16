//! A frozen copy of the sources a proof run reads, and its digest.
//!
//! The run reads the copy, and the digest shows afterward that the repository still holds the same sources.

use crate::fs;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::container::Failure;

/// The most bytes a snapshot may hold.
const SOURCE_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// The files and directories that building and proving the core crates reads.
const SOURCE_ROOTS: [&str; 7] = [
    "Cargo.toml",
    "Cargo.lock",
    ".cargo",
    "crates",
    "src",
    "verification",
    "xtask",
];

/// Generated directories inside the roots, which the snapshot leaves out.
const EXCLUDED_DIRECTORIES: [&str; 2] = ["target", "node_modules"];

/// A copy of the source roots in an evidence directory.
#[derive(Debug)]
pub struct SourceSnapshot {
    directory: PathBuf,
    /// Digest of every path and its bytes.
    pub digest: String,
    /// Number of files.
    pub files: usize,
}

fn files_under(root: &Path, relative: &Path, files: &mut Vec<PathBuf>) -> Result<(), Failure> {
    let metadata =
        std::fs::symlink_metadata(root.join(relative)).map_err(|error| Failure::io(&error))?;
    if metadata.is_symlink() {
        return Err(Failure::new(format!(
            "proof inputs can't contain symbolic links: {}",
            relative.display()
        )));
    }
    if metadata.is_file() {
        files.push(relative.to_path_buf());
    } else if metadata.is_dir() {
        for entry in std::fs::read_dir(root.join(relative)).map_err(|error| Failure::io(&error))? {
            let entry = entry.map_err(|error| Failure::io(&error))?;
            let is_directory = entry
                .file_type()
                .map_err(|error| Failure::io(&error))?
                .is_dir();
            if is_directory
                && EXCLUDED_DIRECTORIES
                    .iter()
                    .any(|name| entry.file_name() == *name)
            {
                continue;
            }
            files_under(root, &relative.join(entry.file_name()), files)?;
        }
    } else {
        return Err(Failure::new(format!(
            "proof input is not a regular file: {}",
            relative.display()
        )));
    }
    Ok(())
}

/// The digest and file count of `roots` under `root`, copying every file to `destination` when there is one.
fn collect(
    root: &Path,
    roots: &[&str],
    destination: Option<&Path>,
    limit: usize,
) -> Result<(String, usize), Failure> {
    let mut files = Vec::new();
    for relative in roots {
        files_under(root, Path::new(relative), &mut files)?;
    }
    files.sort();
    files.dedup();
    if files.is_empty() {
        return Err(Failure::new("the proof source snapshot is empty"));
    }
    let mut digest = Sha256::new();
    let mut total = 0_usize;
    for relative in &files {
        let remaining = limit
            .checked_sub(total)
            .ok_or_else(|| Failure::new("the proof sources exceed their byte budget"))?;
        let bytes = read_bounded(&root.join(relative), remaining)?;
        total = total
            .checked_add(bytes.len())
            .filter(|total| *total <= limit)
            .ok_or_else(|| Failure::new("the proof sources exceed their byte budget"))?;
        let portable = relative
            .to_str()
            .ok_or_else(|| Failure::new("proof inputs must have UTF-8 paths"))?
            .replace('\\', "/");
        digest.update(length_prefix(portable.as_bytes())?);
        digest.update(portable.as_bytes());
        digest.update(length_prefix(&bytes)?);
        digest.update(&bytes);
        if let Some(destination) = destination {
            let path = destination.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, bytes)?;
        }
    }
    Ok((lower_hex(&digest.finalize())?, files.len()))
}

/// The little-endian 64-bit length of `bytes`, which frames them in a digest.
///
/// # Errors
///
/// Returns a failure when the length doesn't fit in 64 bits.
pub fn length_prefix(bytes: &[u8]) -> Result<[u8; 8], Failure> {
    u64::try_from(bytes.len())
        .map(u64::to_le_bytes)
        .map_err(|error| {
            Failure::new(format!(
                "a length of {} bytes doesn't fit in 64 bits: {error}",
                bytes.len()
            ))
        })
}

/// The lowercase hexadecimal form of `bytes`, two digits for each byte.
///
/// # Errors
///
/// Returns a failure when the formatter reports an error.
pub fn lower_hex(bytes: &[u8]) -> Result<String, Failure> {
    bytes
        .iter()
        .try_fold(String::new(), |mut hex, byte| {
            write!(hex, "{byte:02x}").map(|()| hex)
        })
        .map_err(|error| Failure::new(format!("a digest won't format as hexadecimal: {error}")))
}

/// The digest of every path and byte under `roots` of the repository at `root`.
///
/// # Errors
///
/// Returns a failure when a root holds a link, a special file, or a path that isn't UTF-8.
/// Returns a failure when a file can't be read or the files exceed the byte budget.
pub fn digest_of(root: &Path, roots: &[&str]) -> Result<String, Failure> {
    collect(root, roots, None, SOURCE_BUDGET_BYTES).map(|(digest, _)| digest)
}

/// Copy `roots` of the repository at `root` into `destination`.
///
/// # Errors
///
/// Returns a failure when a root holds a link, a special file, or a path that isn't UTF-8.
/// Returns a failure when a file can't be read or written, or the files exceed the byte budget.
pub fn copy_roots(root: &Path, roots: &[&str], destination: &Path) -> Result<(), Failure> {
    collect(root, roots, Some(destination), SOURCE_BUDGET_BYTES).map(|_| ())
}

/// The roots that a snapshot copies, so a copy of a snapshot holds the same sources.
#[must_use]
pub const fn roots() -> [&'static str; 7] {
    SOURCE_ROOTS
}

/// The bytes of `path`, refusing a file larger than `limit`.
///
/// # Errors
///
/// Returns a failure when the file can't be opened or read, or holds more than `limit` bytes.
pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Failure> {
    let file = File::open(path).map_err(|error| Failure::io(&error))?;
    read_within(file, path, limit)
}

/// The bytes of `path`, or `None` when no file exists there, refusing a file larger than `limit`.
///
/// # Errors
///
/// Returns a failure when the file exists but can't be opened or read, or holds more than `limit` bytes.
pub fn read_bounded_if_present(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, Failure> {
    match File::open(path) {
        Ok(file) => read_within(file, path, limit).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Failure::io(&error)),
    }
}

/// The bytes of the open `file` at `path`, refusing more than `limit`.
fn read_within(file: File, path: &Path, limit: usize) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::new();
    let read_limit = u64::try_from(limit)
        .map_err(|error| {
            Failure::new(format!(
                "the byte budget {limit} doesn't fit in 64 bits: {error}"
            ))
        })?
        .saturating_add(1);
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::io(&error))?;
    if bytes.len() > limit {
        return Err(Failure::new(format!(
            "{} exceeds its byte budget",
            path.display()
        )));
    }
    Ok(bytes)
}

impl SourceSnapshot {
    /// Copy the source roots of the repository at `root` into `evidence/source`.
    ///
    /// # Errors
    ///
    /// Returns a failure when the copy can't be made or the sources break a rule of [`digest_of`].
    pub fn capture(root: &Path, evidence: &Path) -> Result<Self, Failure> {
        let directory = evidence.join("source");
        fs::create_dir(&directory)?;
        let (digest, files) = collect(root, &SOURCE_ROOTS, Some(&directory), SOURCE_BUDGET_BYTES)?;
        Ok(Self {
            directory,
            digest,
            files,
        })
    }

    /// The directory that holds the copy.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.directory
    }

    /// Whether both the repository at `root` and the copy still hold exactly the captured sources.
    ///
    /// # Errors
    ///
    /// Returns a failure when the repository or the copy breaks a rule of [`digest_of`].
    pub fn matches(&self, root: &Path) -> Result<bool, Failure> {
        let current = collect(root, &SOURCE_ROOTS, None, SOURCE_BUDGET_BYTES)?;
        let frozen = collect(self.path(), &SOURCE_ROOTS, None, SOURCE_BUDGET_BYTES)?;
        Ok(current == (self.digest.clone(), self.files) && frozen == current)
    }
}

#[cfg(test)]
mod tests {
    use crate::fs;

    use super::{SOURCE_ROOTS, SourceSnapshot, collect, read_bounded, read_bounded_if_present};

    #[test]
    fn the_digest_binds_every_path_and_byte() {
        let root = tempfile::tempdir().unwrap();
        let copy = tempfile::tempdir().unwrap();
        fs::write(root.path().join("input"), b"original").unwrap();
        let first = collect(root.path(), &["input"], Some(copy.path()), 1024).unwrap();
        assert_eq!(first, collect(copy.path(), &["input"], None, 1024).unwrap());
        fs::write(root.path().join("input"), b"modified").unwrap();
        assert_ne!(first, collect(root.path(), &["input"], None, 1024).unwrap());
        fs::rename(copy.path().join("input"), copy.path().join("renamed")).unwrap();
        assert_ne!(
            first,
            collect(copy.path(), &["renamed"], None, 1024).unwrap()
        );
    }

    #[test]
    fn an_empty_or_oversized_source_is_refused() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("input"), b"ab").unwrap();
        collect(root.path(), &[], None, 1024).unwrap_err();
        collect(root.path(), &["input"], None, 1).unwrap_err();
        read_bounded(&root.path().join("input"), 1).unwrap_err();
        assert_eq!(read_bounded(&root.path().join("input"), 2).unwrap(), b"ab");
    }

    #[test]
    fn only_a_missing_file_reads_as_absent_within_the_budget() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            read_bounded_if_present(&root.path().join("missing"), 2).unwrap(),
            None
        );
        fs::write(root.path().join("input"), b"ab").unwrap();
        assert_eq!(
            read_bounded_if_present(&root.path().join("input"), 2)
                .unwrap()
                .as_deref(),
            Some(b"ab".as_slice())
        );
        read_bounded_if_present(&root.path().join("input"), 1).unwrap_err();
        read_bounded_if_present(root.path(), 2).unwrap_err();
    }

    #[test]
    fn a_snapshot_refuses_a_changed_source_and_ignores_generated_targets() {
        let root = tempfile::tempdir().unwrap();
        let evidence = tempfile::tempdir().unwrap();
        for relative in SOURCE_ROOTS {
            if relative.contains('.') && !relative.starts_with('.') {
                fs::write(root.path().join(relative), b"input").unwrap();
            } else {
                fs::create_dir(root.path().join(relative)).unwrap();
                fs::write(root.path().join(relative).join("file"), b"input").unwrap();
            }
        }
        let snapshot = SourceSnapshot::capture(root.path(), evidence.path()).unwrap();
        assert!(snapshot.matches(root.path()).unwrap());
        fs::create_dir(root.path().join("xtask/target")).unwrap();
        fs::write(root.path().join("xtask/target/generated"), b"generated").unwrap();
        assert!(snapshot.matches(root.path()).unwrap());
        fs::write(root.path().join("src/added.rs"), b"added").unwrap();
        assert!(!snapshot.matches(root.path()).unwrap());
        fs::remove_file(root.path().join("src/added.rs")).unwrap();
        assert!(snapshot.matches(root.path()).unwrap());
        fs::write(snapshot.path().join("Cargo.toml"), b"modified").unwrap();
        assert!(!snapshot.matches(root.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_refused_instead_of_followed() {
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc/hosts", root.path().join("input")).unwrap();
        collect(root.path(), &["input"], None, 1024).unwrap_err();
    }
}
