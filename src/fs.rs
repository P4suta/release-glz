//! The one owner of file access in the release engine, which names the path in each error.
//!
//! A path that names nothing, because it or a parent is missing or a parent isn't a directory, reads as absent wherever a caller asks whether something is there.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{File, FileType, Metadata};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

/// A file operation that failed, with the path it concerned and the error the system reported.
#[derive(Debug)]
pub struct Error {
    operation: Operation,
    path: PathBuf,
    source: io::Error,
}

#[derive(Debug)]
enum Operation {
    Read,
    Write,
    Create,
    CreateDirectories,
    Open,
    Inspect,
    List,
    Resolve,
    Move(PathBuf),
    Copy(PathBuf),
}

impl Error {
    fn new(operation: Operation, path: &Path, source: io::Error) -> Self {
        Self {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }

    /// The kind of the error the system reported.
    pub fn kind(&self) -> io::ErrorKind {
        self.source.kind()
    }

    fn describe(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = self.path.display();
        match &self.operation {
            Operation::Read => write!(formatter, "failed to read `{path}`"),
            Operation::Write => write!(formatter, "failed to write `{path}`"),
            Operation::Create => write!(formatter, "failed to create `{path}`"),
            Operation::CreateDirectories => {
                write!(formatter, "failed to create the directory `{path}`")
            }
            Operation::Open => write!(formatter, "failed to open `{path}`"),
            Operation::Inspect => write!(formatter, "failed to inspect `{path}`"),
            Operation::List => write!(formatter, "failed to list `{path}`"),
            Operation::Resolve => write!(formatter, "failed to resolve `{path}`"),
            Operation::Move(to) => {
                write!(formatter, "failed to move `{path}` to `{}`", to.display())
            }
            Operation::Copy(to) => {
                write!(formatter, "failed to copy `{path}` to `{}`", to.display())
            }
        }
    }
}

/// The alternate form `{:#}` appends the system's error, as `anyhow` does for a chain.
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.describe(formatter)?;
        if formatter.alternate() {
            write!(formatter, ": {}", self.source)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Whether `error` means the path names nothing, rather than something that can't be reached.
fn names_nothing(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// What a path names, following symbolic links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Nothing is at the path.
    Absent,
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// Something that is neither a regular file nor a directory, such as a device.
    Other,
}

/// What `path` names, following symbolic links.
///
/// # Errors
///
/// Returns an error naming the path when something is there that can't be inspected.
pub fn kind(path: impl AsRef<Path>) -> Result<Kind, Error> {
    let path = path.as_ref();
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(Kind::File),
        Ok(metadata) if metadata.is_dir() => Ok(Kind::Directory),
        Ok(_) => Ok(Kind::Other),
        Err(error) if names_nothing(&error) => Ok(Kind::Absent),
        Err(error) => Err(Error::new(Operation::Inspect, path, error)),
    }
}

/// The bytes of a file.
///
/// # Errors
///
/// Returns an error naming the path when the file can't be read.
#[expect(
    clippy::disallowed_methods,
    reason = "the file owner reads a file here and names its path in the error"
)]
pub fn read(path: impl AsRef<Path>) -> Result<Vec<u8>, Error> {
    let path = path.as_ref();
    std::fs::read(path).map_err(|error| Error::new(Operation::Read, path, error))
}

/// The UTF-8 text of a file.
///
/// # Errors
///
/// Returns an error naming the path when the file can't be read or isn't UTF-8.
#[expect(
    clippy::disallowed_methods,
    reason = "the file owner reads a file here and names its path in the error"
)]
pub fn read_to_string(path: impl AsRef<Path>) -> Result<String, Error> {
    let path = path.as_ref();
    std::fs::read_to_string(path).map_err(|error| Error::new(Operation::Read, path, error))
}

/// The bytes of a file, or `None` when the path names nothing.
///
/// # Errors
///
/// Returns an error naming the path when something is there that can't be read.
pub fn read_if_present(path: impl AsRef<Path>) -> Result<Option<Vec<u8>>, Error> {
    if_present(read(path))
}

/// The UTF-8 text of a file, or `None` when the path names nothing.
///
/// # Errors
///
/// Returns an error naming the path when something is there that can't be read or isn't UTF-8.
pub fn read_to_string_if_present(path: impl AsRef<Path>) -> Result<Option<String>, Error> {
    if_present(read_to_string(path))
}

/// The value of an operation on a path, or `None` when it failed because the path names nothing.
///
/// # Errors
///
/// Returns the operation's error when something is there that the operation couldn't reach.
pub fn if_present<T>(result: Result<T, Error>) -> Result<Option<T>, Error> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if names_nothing(&error.source) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Writes `contents` to a file, replacing any earlier contents.
///
/// # Errors
///
/// Returns an error naming the path when the file can't be written.
#[expect(
    clippy::disallowed_methods,
    reason = "the file owner writes a file here and names its path in the error"
)]
pub fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<(), Error> {
    let path = path.as_ref();
    std::fs::write(path, contents).map_err(|error| Error::new(Operation::Write, path, error))
}

/// Writes `contents` to a file that must not exist yet, and waits until they reach the disk.
///
/// # Errors
///
/// Returns an error naming the path when something is there already or the file can't be written.
#[expect(
    clippy::disallowed_methods,
    reason = "the file owner creates a new file here and names its path in the error"
)]
pub fn write_new(path: impl AsRef<Path>, contents: &[u8]) -> Result<(), Error> {
    let path = path.as_ref();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| Error::new(Operation::Create, path, error))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| Error::new(Operation::Write, path, error))
}

/// Creates a directory and every missing parent.
///
/// # Errors
///
/// Returns an error naming the path when a directory can't be created.
#[expect(
    clippy::disallowed_methods,
    reason = "the file owner creates directories here and names the path in the error"
)]
pub fn create_dir_all(path: impl AsRef<Path>) -> Result<(), Error> {
    let path = path.as_ref();
    std::fs::create_dir_all(path)
        .map_err(|error| Error::new(Operation::CreateDirectories, path, error))
}

/// Moves a file or directory to another path.
///
/// # Errors
///
/// Returns an error naming both paths when the move fails.
#[expect(
    clippy::disallowed_methods,
    reason = "the file owner moves a file here and names both paths in the error"
)]
pub fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<(), Error> {
    let (from, to) = (from.as_ref(), to.as_ref());
    std::fs::rename(from, to)
        .map_err(|error| Error::new(Operation::Move(to.to_path_buf()), from, error))
}

/// Copies a file's contents and permissions to another path.
///
/// # Errors
///
/// Returns an error naming both paths when the copy fails.
#[expect(
    clippy::disallowed_methods,
    reason = "the file owner copies a file here and names both paths in the error"
)]
pub fn copy(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<(), Error> {
    let (from, to) = (from.as_ref(), to.as_ref());
    std::fs::copy(from, to)
        .map(drop)
        .map_err(|error| Error::new(Operation::Copy(to.to_path_buf()), from, error))
}

/// Opens a file for reading.
///
/// # Errors
///
/// Returns an error naming the path when the file can't be opened.
pub fn open(path: impl AsRef<Path>) -> Result<File, Error> {
    let path = path.as_ref();
    File::open(path).map_err(|error| Error::new(Operation::Open, path, error))
}

/// The metadata of what `path` names, following symbolic links.
///
/// # Errors
///
/// Returns an error naming the path when it can't be inspected.
pub fn metadata(path: impl AsRef<Path>) -> Result<Metadata, Error> {
    let path = path.as_ref();
    std::fs::metadata(path).map_err(|error| Error::new(Operation::Inspect, path, error))
}

/// The metadata of what `path` names, without following a symbolic link.
///
/// # Errors
///
/// Returns an error naming the path when it can't be inspected.
pub fn symlink_metadata(path: impl AsRef<Path>) -> Result<Metadata, Error> {
    let path = path.as_ref();
    std::fs::symlink_metadata(path).map_err(|error| Error::new(Operation::Inspect, path, error))
}

/// The absolute path that `path` resolves to, with every symbolic link followed.
///
/// # Errors
///
/// Returns an error naming the path when it can't be resolved.
pub fn canonicalize(path: impl AsRef<Path>) -> Result<PathBuf, Error> {
    let path = path.as_ref();
    std::fs::canonicalize(path).map_err(|error| Error::new(Operation::Resolve, path, error))
}

/// One entry of a listed directory.
#[derive(Debug)]
pub struct Entry {
    path: PathBuf,
    name: OsString,
    file_type: FileType,
}

impl Entry {
    /// The entry's path, which joins the listed directory and the entry's name.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The entry's name within the listed directory.
    pub fn file_name(&self) -> &OsStr {
        &self.name
    }

    /// The entry's type, without following a symbolic link.
    pub const fn file_type(&self) -> FileType {
        self.file_type
    }
}

/// The entries of a directory, sorted by name.
///
/// # Errors
///
/// Returns an error naming the directory when it can't be listed, or naming an entry whose type can't be read.
pub fn read_dir(directory: impl AsRef<Path>) -> Result<Vec<Entry>, Error> {
    let directory = directory.as_ref();
    let listed = |error| Error::new(Operation::List, directory, error);
    let mut entries = std::fs::read_dir(directory)
        .map_err(listed)?
        .map(|entry| {
            let entry = entry.map_err(listed)?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| Error::new(Operation::Inspect, &path, error))?;
            Ok(Entry {
                path,
                name: entry.file_name(),
                file_type,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::{Kind, kind, read_dir, read_if_present, read_to_string, write, write_new};
    use release_glz_test_support::fs as fixture;
    use std::io::ErrorKind;

    #[test]
    fn an_error_names_the_operation_and_the_path() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing.txt");
        let error = read_to_string(&missing).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert_eq!(
            error.to_string(),
            format!("failed to read `{}`", missing.display())
        );
        let reason = std::error::Error::source(&error).unwrap().to_string();
        let shown = format!("failed to read `{}`: {reason}", missing.display());
        assert_eq!(format!("{error:#}"), shown);
        assert_eq!(
            format!("{:#}", anyhow::Error::from(error)),
            shown,
            "anyhow shows the reason once"
        );
        let present = root.path().join("present");
        fixture::write(&present, "x");
        let refused = write_new(&present, b"y").unwrap_err();
        assert_eq!(
            (refused.kind(), refused.to_string()),
            (
                ErrorKind::AlreadyExists,
                format!("failed to create `{}`", present.display())
            )
        );
        assert_eq!(fixture::read_to_string(&present), "x");
    }

    #[test]
    fn only_a_path_that_names_nothing_reads_as_absent() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        write(&file, "text").unwrap();
        assert_eq!(
            read_if_present(&file).unwrap().as_deref(),
            Some(&b"text"[..])
        );
        assert_eq!(read_if_present(root.path().join("missing")).unwrap(), None);
        assert_eq!(read_if_present(file.join("below")).unwrap(), None);
        assert!(read_if_present(root.path()).is_err());
    }

    #[test]
    fn a_kind_tells_files_directories_and_absence_apart() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        fixture::write(&file, "");
        assert_eq!(kind(&file).unwrap(), Kind::File);
        assert_eq!(kind(root.path()).unwrap(), Kind::Directory);
        assert_eq!(kind(root.path().join("missing")).unwrap(), Kind::Absent);
        assert_eq!(kind(file.join("below")).unwrap(), Kind::Absent);
    }

    #[test]
    fn a_listing_holds_every_entry_in_name_order() {
        let root = tempfile::tempdir().unwrap();
        for name in ["b", "a", "c"] {
            fixture::write(root.path().join(name), "");
        }
        fixture::create_dir_all(root.path().join("d"));
        let entries = read_dir(root.path()).unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| (entry.file_name().to_owned(), entry.file_type().is_dir()))
                .collect::<Vec<_>>(),
            [("a", false), ("b", false), ("c", false), ("d", true)]
                .map(|(name, directory)| (name.into(), directory))
        );
        assert!(
            entries
                .iter()
                .all(|entry| entry.path() == root.path().join(entry.file_name()))
        );
        assert_eq!(
            read_dir(root.path().join("missing"))
                .unwrap_err()
                .to_string(),
            format!("failed to list `{}`", root.path().join("missing").display())
        );
    }
}
