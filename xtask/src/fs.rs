//! The one owner of file access in the repository tasks, which names the path in each error.

use crate::container::Failure;
use std::io;
use std::path::{Path, PathBuf};

#[expect(
    clippy::disallowed_methods,
    clippy::create_dir,
    reason = "the file owner calls the standard library once per operation and names the path in the error"
)]
mod raw {
    use std::path::Path;

    pub(super) fn read_to_string(path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }

    pub(super) fn write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
        std::fs::write(path, contents)
    }

    pub(super) fn create_dir(path: &Path) -> std::io::Result<()> {
        std::fs::create_dir(path)
    }

    pub(super) fn create_dir_all(path: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(path)
    }

    pub(super) fn rename(from: &Path, to: &Path) -> std::io::Result<()> {
        std::fs::rename(from, to)
    }

    pub(super) fn remove_file(path: &Path) -> std::io::Result<()> {
        std::fs::remove_file(path)
    }
}

fn failed(operation: &str, path: &Path, error: &io::Error) -> Failure {
    Failure::new(format!("{operation} {} failed: {error}", path.display()))
}

/// The UTF-8 text of a file.
///
/// # Errors
///
/// Returns a failure naming the path when the file can't be read or isn't UTF-8.
pub fn read_to_string(path: impl AsRef<Path>) -> Result<String, Failure> {
    let path = path.as_ref();
    raw::read_to_string(path).map_err(|error| failed("reading", path, &error))
}

/// The UTF-8 text of a file, or `None` when no file exists at the path.
///
/// # Errors
///
/// Returns a failure naming the path when the file exists but can't be read or isn't UTF-8.
pub fn read_if_present(path: impl AsRef<Path>) -> Result<Option<String>, Failure> {
    let path = path.as_ref();
    match raw::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(failed("reading", path, &error)),
    }
}

/// Writes `contents` to a file, replacing any earlier contents.
///
/// # Errors
///
/// Returns a failure naming the path when the file can't be written.
pub fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<(), Failure> {
    let path = path.as_ref();
    raw::write(path, contents.as_ref()).map_err(|error| failed("writing", path, &error))
}

/// Creates one directory, whose parent has to exist.
///
/// # Errors
///
/// Returns a failure naming the path when the directory exists already or can't be created.
pub fn create_dir(path: impl AsRef<Path>) -> Result<(), Failure> {
    let path = path.as_ref();
    raw::create_dir(path).map_err(|error| failed("creating the directory", path, &error))
}

/// Creates a directory and every missing parent.
///
/// # Errors
///
/// Returns a failure naming the path when a directory can't be created.
pub fn create_dir_all(path: impl AsRef<Path>) -> Result<(), Failure> {
    let path = path.as_ref();
    raw::create_dir_all(path).map_err(|error| failed("creating the directories", path, &error))
}

/// Moves a file to another path.
///
/// # Errors
///
/// Returns a failure naming the source when the file can't be moved.
pub fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<(), Failure> {
    let from = from.as_ref();
    raw::rename(from, to.as_ref()).map_err(|error| failed("moving", from, &error))
}

/// Deletes a file.
///
/// # Errors
///
/// Returns a failure naming the path when the file can't be deleted.
pub fn remove_file(path: impl AsRef<Path>) -> Result<(), Failure> {
    let path = path.as_ref();
    raw::remove_file(path).map_err(|error| failed("deleting", path, &error))
}

/// Whether a symbolic link sits at `path`, which a path that names nothing never is.
///
/// # Errors
///
/// Returns a failure naming the path when it names something that can't be inspected.
pub fn is_symlink(path: &Path) -> Result<bool, Failure> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(failed("inspecting", path, &error)),
    }
}

/// The files under `directory` and its subdirectories whose names end with `suffix`, in sorted order.
///
/// # Errors
///
/// Returns a failure naming the directory when it or a subdirectory can't be listed.
pub fn files_with_suffix(directory: &Path, suffix: &str) -> Result<Vec<PathBuf>, Failure> {
    let mut pending = vec![directory.to_path_buf()];
    let mut files = Vec::new();
    while let Some(listed) = pending.pop() {
        let entries =
            std::fs::read_dir(&listed).map_err(|error| failed("listing", &listed, &error))?;
        for entry in entries {
            let path = entry
                .map_err(|error| failed("listing", &listed, &error))?
                .path();
            let kind = std::fs::symlink_metadata(&path)
                .map_err(|error| failed("inspecting", &path, &error))?
                .file_type();
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file()
                && path
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|name| name.ends_with(suffix))
            {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

/// A new directory under `target/assurance` for the evidence of one `kind` of run.
///
/// # Errors
///
/// Returns a failure when the directory can't be created.
pub fn evidence_directory(root: &Path, kind: &str) -> Result<PathBuf, Failure> {
    let directory = root.join("target").join("assurance").join(format!(
        "{kind}-{}-{}",
        run_stamp()?,
        std::process::id()
    ));
    create_dir_all(&directory)?;
    Ok(directory)
}

/// The nanoseconds since the Unix epoch, which only keep one run's evidence directory apart from another's.
#[expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "an evidence directory's name only has to differ from earlier runs, and no decision reads the time"
)]
fn run_stamp() -> Result<u128, Failure> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .map_err(|error| Failure::new(format!("the clock reads before the Unix epoch: {error}")))
}

#[cfg(test)]
mod tests {
    use super::{
        create_dir, create_dir_all, files_with_suffix, is_symlink, read_if_present, read_to_string,
        write,
    };

    #[cfg(unix)]
    #[test]
    fn only_a_symbolic_link_reads_as_one() {
        let root = tempfile::tempdir().unwrap();
        write(root.path().join("file"), "").unwrap();
        std::os::unix::fs::symlink(root.path().join("file"), root.path().join("link")).unwrap();
        assert!(is_symlink(&root.path().join("link")).unwrap());
        assert!(!is_symlink(&root.path().join("file")).unwrap());
        assert!(!is_symlink(&root.path().join("missing")).unwrap());
        assert!(!is_symlink(&root.path().join("file/below")).unwrap());
    }

    #[test]
    fn a_listing_holds_every_matching_file_below_the_directory_in_order() {
        let root = tempfile::tempdir().unwrap();
        create_dir_all(root.path().join("b/c")).unwrap();
        for name in ["b/c/deep.rs", "b/top.rs", "a.rs", "notes.md"] {
            write(root.path().join(name), "").unwrap();
        }
        assert_eq!(
            files_with_suffix(root.path(), ".rs").unwrap(),
            ["a.rs", "b/c/deep.rs", "b/top.rs"].map(|name| root.path().join(name))
        );
        assert!(
            files_with_suffix(&root.path().join("missing"), ".rs")
                .is_err_and(|failure| failure.to_string().starts_with("listing "))
        );
    }

    #[test]
    fn a_failure_names_the_operation_and_the_path() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing.txt");
        let failure = read_to_string(&missing).unwrap_err().to_string();
        assert!(failure.starts_with(&format!("reading {} failed:", missing.display())));
        write(root.path().join("present"), "x").unwrap();
        let refused = create_dir(root.path().join("present"))
            .unwrap_err()
            .to_string();
        assert!(refused.starts_with("creating the directory "));
    }

    #[test]
    fn only_a_missing_file_reads_as_absent() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(read_if_present(root.path().join("missing")).unwrap(), None);
        write(root.path().join("present"), "text").unwrap();
        assert_eq!(
            read_if_present(root.path().join("present"))
                .unwrap()
                .as_deref(),
            Some("text")
        );
        assert!(
            read_if_present(root.path())
                .is_err_and(|failure| failure.to_string().starts_with("reading "))
        );
    }
}
