//! File fixtures that end the calling test with the path when the file system refuses an operation.

use crate::fail;
use std::fs::Metadata;
use std::io::ErrorKind;
use std::path::Path;

/// Writes `contents` to `path`, replacing any earlier contents.
///
/// # Panics
///
/// When the file can't be written.
#[expect(
    clippy::disallowed_methods,
    reason = "the test support writes fixture files in this one place and names the path when it fails"
)]
#[track_caller]
pub fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) {
    let path = path.as_ref();
    std::fs::write(path, contents)
        .unwrap_or_else(|error| fail(format_args!("writing `{}` failed: {error}", path.display())));
}

/// The bytes of a file.
///
/// # Panics
///
/// When the file can't be read.
#[expect(
    clippy::disallowed_methods,
    reason = "the test support reads fixture files in this one place and names the path when it fails"
)]
#[must_use]
#[track_caller]
pub fn read(path: impl AsRef<Path>) -> Vec<u8> {
    let path = path.as_ref();
    std::fs::read(path)
        .unwrap_or_else(|error| fail(format_args!("reading `{}` failed: {error}", path.display())))
}

/// The UTF-8 text of a file.
///
/// # Panics
///
/// When the file can't be read or isn't UTF-8.
#[expect(
    clippy::disallowed_methods,
    reason = "the test support reads fixture files in this one place and names the path when it fails"
)]
#[must_use]
#[track_caller]
pub fn read_to_string(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| fail(format_args!("reading `{}` failed: {error}", path.display())))
}

/// Creates one directory, whose parent has to exist.
///
/// # Panics
///
/// When the directory exists already or can't be created.
#[expect(
    clippy::disallowed_methods,
    clippy::create_dir,
    reason = "a test that needs its parent to exist already creates one directory, and the test support names the path when it fails"
)]
#[track_caller]
pub fn create_dir(path: impl AsRef<Path>) {
    let path = path.as_ref();
    std::fs::create_dir(path).unwrap_or_else(|error| {
        fail(format_args!(
            "creating the directory `{}` failed: {error}",
            path.display()
        ))
    });
}

/// Creates a directory and every missing parent.
///
/// # Panics
///
/// When a directory can't be created.
#[expect(
    clippy::disallowed_methods,
    reason = "the test support creates fixture directories in this one place and names the path when it fails"
)]
#[track_caller]
pub fn create_dir_all(path: impl AsRef<Path>) {
    let path = path.as_ref();
    std::fs::create_dir_all(path).unwrap_or_else(|error| {
        fail(format_args!(
            "creating the directory `{}` failed: {error}",
            path.display()
        ))
    });
}

/// Copies a file's contents and permissions to another path.
///
/// # Panics
///
/// When the file can't be copied.
#[expect(
    clippy::disallowed_methods,
    reason = "the test support copies fixture files in this one place and names both paths when it fails"
)]
#[track_caller]
pub fn copy(from: impl AsRef<Path>, to: impl AsRef<Path>) {
    let (from, to) = (from.as_ref(), to.as_ref());
    std::fs::copy(from, to).unwrap_or_else(|error| {
        fail(format_args!(
            "copying `{}` to `{}` failed: {error}",
            from.display(),
            to.display()
        ))
    });
}

/// Moves a file or directory to another path.
///
/// # Panics
///
/// When the move fails.
#[expect(
    clippy::disallowed_methods,
    reason = "the test support moves fixture files in this one place and names both paths when it fails"
)]
#[track_caller]
pub fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) {
    let (from, to) = (from.as_ref(), to.as_ref());
    std::fs::rename(from, to).unwrap_or_else(|error| {
        fail(format_args!(
            "moving `{}` to `{}` failed: {error}",
            from.display(),
            to.display()
        ))
    });
}

/// Deletes a file.
///
/// # Panics
///
/// When the file can't be deleted.
#[expect(
    clippy::disallowed_methods,
    reason = "the test support deletes fixture files in this one place and names the path when it fails"
)]
#[track_caller]
pub fn remove_file(path: impl AsRef<Path>) {
    let path = path.as_ref();
    std::fs::remove_file(path).unwrap_or_else(|error| {
        fail(format_args!(
            "deleting `{}` failed: {error}",
            path.display()
        ))
    });
}

/// The metadata of what `path` names, following symbolic links, or `None` when nothing is there.
#[track_caller]
fn metadata_if_present(path: &Path) -> Option<Metadata> {
    match std::fs::metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => fail(format_args!(
            "inspecting `{}` failed: {error}",
            path.display()
        )),
    }
}

/// Whether something is at `path`, following symbolic links.
///
/// # Panics
///
/// When something is there that can't be inspected.
#[must_use]
#[track_caller]
pub fn exists(path: impl AsRef<Path>) -> bool {
    metadata_if_present(path.as_ref()).is_some()
}

/// Whether a regular file is at `path`, following symbolic links.
///
/// # Panics
///
/// When something is there that can't be inspected.
#[must_use]
#[track_caller]
pub fn is_file(path: impl AsRef<Path>) -> bool {
    metadata_if_present(path.as_ref()).is_some_and(|metadata| metadata.is_file())
}

/// Whether a directory is at `path`, following symbolic links.
///
/// # Panics
///
/// When something is there that can't be inspected.
#[must_use]
#[track_caller]
pub fn is_dir(path: impl AsRef<Path>) -> bool {
    metadata_if_present(path.as_ref()).is_some_and(|metadata| metadata.is_dir())
}

#[cfg(test)]
mod tests {
    use super::{exists, is_dir, is_file, read_to_string};
    use std::path::PathBuf;

    fn missing() -> PathBuf {
        std::env::temp_dir().join(format!(
            "release-glz-test-support-missing-{}",
            std::process::id()
        ))
    }

    #[test]
    fn a_missing_path_reads_as_absent_and_a_directory_as_one() {
        assert!(!exists(missing()) && !is_file(missing()) && !is_dir(missing()));
        let directory = std::env::temp_dir();
        assert!(exists(&directory) && is_dir(&directory) && !is_file(&directory));
    }

    #[test]
    #[should_panic(expected = "release-glz-test-support-missing-")]
    fn a_failed_read_names_the_path() {
        drop(read_to_string(missing()));
    }
}
