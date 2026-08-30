use std::collections::BTreeMap;
use std::fs;
use std::io::Write;

use flate2::{Compression, write::GzEncoder};
use release_glz::artifact::{
    ArchiveLimits, build_hex_tarball, interface_from_docs_tarball, normalize_package_dir,
    package_publish_inputs, unpack_hex_source, unpack_tar_bytes, validate_docs_tarball,
    validate_hex_tarball,
};
use sha2::{Digest, Sha256};

#[test]
fn hex_v3_builder_is_deterministic_bounded_and_rejects_unsafe_paths() {
    let files = BTreeMap::from([
        (
            "gleam.toml".to_owned(),
            b"name = \"x\"\nversion = \"1.0.0\"\n".to_vec(),
        ),
        ("src/x.gleam".to_owned(), b"pub fn value() { 1 }\n".to_vec()),
    ]);
    let metadata = b"{<<\"name\">>, <<\"x\"/utf8>>}.\n";

    let first = build_hex_tarball(metadata, &files, ArchiveLimits::default()).unwrap();
    let second = build_hex_tarball(metadata, &files, ArchiveLimits::default()).unwrap();

    assert_eq!(first, second);
    let validation = validate_hex_tarball(&first, ArchiveLimits::default()).unwrap();
    assert_eq!(validation.content_entries, 2);
    let temp = tempfile::tempdir().unwrap();
    unpack_hex_source(&first, temp.path()).unwrap();
    assert_eq!(
        fs::read(temp.path().join("src/x.gleam")).unwrap(),
        files["src/x.gleam"]
    );

    let unsafe_files = BTreeMap::from([("../escape".to_owned(), b"secret".to_vec())]);
    assert_error_contains(
        build_hex_tarball(metadata, &unsafe_files, ArchiveLimits::default()),
        "safe relative path",
    );
    assert_error_contains(
        build_hex_tarball(
            metadata,
            &files,
            ArchiveLimits {
                max_total_bytes: 1,
                ..ArchiveLimits::default()
            },
        ),
        "expanded archive limit",
    );
    assert_error_contains(
        build_hex_tarball(
            metadata,
            &files,
            ArchiveLimits {
                max_entries: 1,
                ..ArchiveLimits::default()
            },
        ),
        "entry limit",
    );
    assert_error_contains(
        build_hex_tarball(
            metadata,
            &files,
            ArchiveLimits {
                max_entry_bytes: 1,
                ..ArchiveLimits::default()
            },
        ),
        "metadata",
    );
    assert_error_contains(
        build_hex_tarball(
            b"",
            &files,
            ArchiveLimits {
                max_entry_bytes: 1,
                ..ArchiveLimits::default()
            },
        ),
        "contents file",
    );
    assert_error_contains(
        build_hex_tarball(
            metadata,
            &files,
            ArchiveLimits {
                max_archive_bytes: 1,
                ..ArchiveLimits::default()
            },
        ),
        "generated Hex package failed validation",
    );
}

#[test]
fn hex_v3_builder_accepts_every_exact_limit_boundary() {
    let metadata = vec![b'm'; 4_096];
    let files = BTreeMap::from([
        ("src/a.gleam".to_owned(), vec![b'a'; metadata.len()]),
        ("src/b.gleam".to_owned(), vec![b'b'; metadata.len()]),
        ("src/c.gleam".to_owned(), vec![b'c'; metadata.len()]),
        ("src/d.gleam".to_owned(), vec![b'd'; metadata.len()]),
    ]);
    let package = build_hex_tarball(&metadata, &files, ArchiveLimits::default()).unwrap();
    let exact = ArchiveLimits {
        max_entries: files.len(),
        max_entry_bytes: metadata.len() as u64,
        max_total_bytes: (files.len() * metadata.len()) as u64,
        max_archive_bytes: package.len() as u64,
    };

    assert_eq!(
        build_hex_tarball(&metadata, &files, exact).unwrap(),
        package
    );
}

#[test]
fn hex_outer_archive_has_an_exact_bounded_v3_inventory() {
    let contents = tar_gz(&[("gleam.toml", b"name = \"x\"\nversion = \"1.0.0\"\n")]);
    let valid = outer_package(b"3", b"metadata", &contents, None, &[]);
    let validation = validate_hex_tarball(&valid, ArchiveLimits::default()).unwrap();
    assert_eq!(validation.content_entries, 1);
    validate_hex_tarball(
        &valid,
        ArchiveLimits {
            max_archive_bytes: valid.len() as u64,
            ..ArchiveLimits::default()
        },
    )
    .unwrap();

    let too_small = ArchiveLimits {
        max_archive_bytes: valid.len() as u64 - 1,
        ..ArchiveLimits::default()
    };
    assert_error_contains(
        validate_hex_tarball(&valid, too_small),
        "archive byte limit",
    );

    for (name, package, expected) in [
        (
            "missing entry",
            tar(&[
                ("VERSION", b"3"),
                ("metadata.config", b"metadata"),
                ("contents.tar.gz", contents.as_slice()),
            ]),
            "exactly",
        ),
        (
            "extra entry",
            outer_package(b"3", b"metadata", &contents, None, &[("EXTRA", b"x")]),
            "exactly",
        ),
        (
            "unsupported version",
            outer_package(b"2", b"metadata", &contents, None, &[]),
            "VERSION",
        ),
        (
            "non-ASCII checksum",
            outer_package(b"3", b"metadata", &contents, Some(&[0xff]), &[]),
            "ASCII",
        ),
    ] {
        let error = validate_hex_tarball(&package, ArchiveLimits::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{name}: {error}");
    }
}

#[test]
fn archive_paths_reject_every_ambiguous_or_traversing_form() {
    for raw_path in [
        b"/absolute".as_slice(),
        b"../parent",
        b"dir/../parent",
        b"dir/./file",
        b"dir//file",
        b"dir\\file",
        b"C:/windows",
        &[0xff, b'x'],
    ] {
        let archive = tar_gz_with_rewritten_first_path(raw_path);
        let error = validate_docs_tarball(&archive, ArchiveLimits::default())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("unsafe") || error.contains("UTF-8"),
            "accepted or misclassified {raw_path:?}: {error}"
        );
    }
}

#[test]
fn archives_reject_links_devices_and_nonempty_directories() {
    for (kind, payload) in [
        (tar::EntryType::Symlink, b"".as_slice()),
        (tar::EntryType::Link, b""),
        (tar::EntryType::Block, b""),
        (tar::EntryType::Char, b""),
        (tar::EntryType::Fifo, b""),
        (tar::EntryType::Directory, b"x"),
    ] {
        let archive = special_tar_gz(kind, payload);
        assert!(
            validate_docs_tarball(&archive, ArchiveLimits::default()).is_err(),
            "accepted unsafe tar entry type {kind:?}"
        );
    }

    let directory_only = special_tar_gz(tar::EntryType::Directory, b"");
    validate_docs_tarball(&directory_only, ArchiveLimits::default()).unwrap();
}

#[test]
fn archives_accept_path_only_long_names_and_reject_unsafe_extensions() {
    for kind in [tar::EntryType::GNULongName, tar::EntryType::XHeader] {
        validate_docs_tarball(&extension_tar_gz(kind), ArchiveLimits::default()).unwrap();
    }

    let long_path = format!("nested/{}/index.html", "a".repeat(140));
    validate_docs_tarball(
        &tar_gz(&[(long_path.as_str(), b"generated docs")]),
        ArchiveLimits::default(),
    )
    .unwrap();

    for kind in [tar::EntryType::GNULongLink, tar::EntryType::XGlobalHeader] {
        assert_error_contains(
            validate_docs_tarball(&extension_tar_gz(kind), ArchiveLimits::default()),
            "extension",
        );
    }

    let unsafe_long_name =
        extension_tar_gz_with_contents(tar::EntryType::GNULongName, b"../outside\0");
    assert_error_contains(
        validate_docs_tarball(&unsafe_long_name, ArchiveLimits::default()),
        "unsafe",
    );

    let unsafe_pax =
        extension_tar_gz_with_contents(tar::EntryType::XHeader, &pax_record("path", "../outside"));
    assert_error_contains(
        validate_docs_tarball(&unsafe_pax, ArchiveLimits::default()),
        "unsafe",
    );

    let unsupported_pax =
        extension_tar_gz_with_contents(tar::EntryType::XHeader, &pax_record("mtime", "1.5"));
    assert_error_contains(
        validate_docs_tarball(&unsupported_pax, ArchiveLimits::default()),
        "PAX",
    );

    let malformed_pax =
        extension_tar_gz_with_contents(tar::EntryType::XHeader, b"99 path=safe.txt\n");
    assert_error_contains(
        validate_docs_tarball(&malformed_pax, ArchiveLimits::default()),
        "PAX",
    );
}

#[test]
fn archive_entry_total_count_and_compressed_limits_are_independent() {
    let two_files = tar_gz(&[("a", b"12345678"), ("b", b"abcdefgh")]);
    let per_entry = ArchiveLimits {
        max_entries: 10,
        max_entry_bytes: 7,
        max_total_bytes: 100,
        max_archive_bytes: two_files.len() as u64,
    };
    assert_error_contains(validate_docs_tarball(&two_files, per_entry), "per-file");

    let total = ArchiveLimits {
        max_entries: 10,
        max_entry_bytes: 8,
        max_total_bytes: 15,
        max_archive_bytes: two_files.len() as u64,
    };
    assert_error_contains(
        validate_docs_tarball(&two_files, total),
        "expanded byte limit",
    );

    let entries = ArchiveLimits {
        max_entries: 1,
        max_entry_bytes: 8,
        max_total_bytes: 16,
        max_archive_bytes: two_files.len() as u64,
    };
    assert_error_contains(validate_docs_tarball(&two_files, entries), "entry limit");

    let compressed = ArchiveLimits {
        max_archive_bytes: two_files.len() as u64 - 1,
        ..ArchiveLimits::default()
    };
    assert_error_contains(
        validate_docs_tarball(&two_files, compressed),
        "compressed archive",
    );

    let decompressed = ArchiveLimits {
        max_entries: 0,
        max_entry_bytes: 0,
        max_total_bytes: 0,
        max_archive_bytes: two_files.len() as u64,
    };
    assert!(validate_docs_tarball(&two_files, decompressed).is_err());

    let exact = ArchiveLimits {
        max_entries: 10,
        max_entry_bytes: 8,
        max_total_bytes: 16,
        max_archive_bytes: two_files.len() as u64,
    };
    validate_docs_tarball(&two_files, exact).unwrap();
}

#[test]
fn unpacking_uses_only_validated_relative_regular_files() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("out");
    let archive = tar(&[("nested/file.txt", b"ok"), ("root.txt", b"root")]);
    unpack_tar_bytes(&archive, &destination, ArchiveLimits::default()).unwrap();
    assert_eq!(
        fs::read(destination.join("nested/file.txt")).unwrap(),
        b"ok"
    );
    assert_eq!(fs::read(destination.join("root.txt")).unwrap(), b"root");

    let exact_destination = temp.path().join("exact");
    unpack_tar_bytes(
        &archive,
        &exact_destination,
        ArchiveLimits {
            max_archive_bytes: archive.len() as u64,
            ..ArchiveLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        fs::read(exact_destination.join("nested/file.txt")).unwrap(),
        b"ok"
    );

    let limit = ArchiveLimits {
        max_archive_bytes: archive.len() as u64 - 1,
        ..ArchiveLimits::default()
    };
    assert_error_contains(
        unpack_tar_bytes(&archive, &temp.path().join("blocked"), limit),
        "byte limit",
    );
    assert!(!temp.path().join("blocked").exists());
}

#[test]
fn validated_hex_source_unpacking_omits_generated_erlang_but_keeps_native_ffi() {
    let contents = tar_gz(&[
        ("gleam.toml", b"name = \"x\"\nversion = \"1.0.0\"\n"),
        ("src/x.gleam", b"pub fn value() { 1 }\n"),
        ("src/x.erl", b"% compiler-generated Erlang\n"),
        ("src/x_ffi.erl", b"% package-authored native Erlang\n"),
    ]);
    let package = outer_package(b"3", b"metadata", &contents, None, &[]);
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("source");

    unpack_hex_source(&package, &destination).unwrap();
    assert_eq!(
        fs::read(destination.join("gleam.toml")).unwrap(),
        b"name = \"x\"\nversion = \"1.0.0\"\n"
    );
    assert_eq!(
        fs::read(destination.join("src/x.gleam")).unwrap(),
        b"pub fn value() { 1 }\n"
    );
    assert!(
        !destination.join("src/x.erl").exists(),
        "paired compiler output must not clash when the source is rebuilt"
    );
    assert_eq!(
        fs::read(destination.join("src/x_ffi.erl")).unwrap(),
        b"% package-authored native Erlang\n"
    );
}

#[test]
fn package_directory_normalization_includes_only_publishable_inputs() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("src/nested")).unwrap();
    fs::create_dir_all(temp.path().join("priv/assets")).unwrap();
    fs::create_dir_all(temp.path().join("test")).unwrap();
    fs::create_dir_all(temp.path().join("build")).unwrap();
    fs::write(
        temp.path().join("gleam.toml"),
        "name = \"x\"\nversion = \"1.2.3\"\n",
    )
    .unwrap();
    fs::write(temp.path().join("README.txt"), "read me").unwrap();
    fs::write(temp.path().join("NOTICE.md"), "notice").unwrap();
    fs::write(temp.path().join("ignored.txt"), "ignored").unwrap();
    fs::write(temp.path().join("src/nested/x.gleam"), "pub fn x() { 1 }").unwrap();
    fs::write(temp.path().join("src/nested/x.mjs"), "export const x = 1;").unwrap();
    fs::write(temp.path().join("src/nested/secret.txt"), "not publishable").unwrap();
    fs::write(temp.path().join("priv/assets/data"), "private asset").unwrap();
    fs::write(temp.path().join("test/x.gleam"), "ignored").unwrap();
    fs::write(temp.path().join("build/output"), "ignored").unwrap();

    let publish_inputs = package_publish_inputs(temp.path()).unwrap();
    assert!(
        String::from_utf8_lossy(&publish_inputs["gleam.toml"]).contains("1.2.3"),
        "raw publish inputs must preserve the candidate version"
    );
    let normalized = normalize_package_dir(temp.path()).unwrap();
    assert_eq!(
        normalized.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "NOTICE.md",
            "README.txt",
            "gleam.toml",
            "priv/assets/data",
            "src/nested/x.gleam",
            "src/nested/x.mjs",
        ]
    );
    assert!(
        String::from_utf8(normalized["gleam.toml"].clone())
            .unwrap()
            .contains("<release-glz-version>")
    );
}

#[cfg(unix)]
#[test]
fn package_directory_normalization_rejects_symlink_publish_inputs() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("src")).unwrap();
    fs::write(temp.path().join("outside"), "secret").unwrap();
    symlink("../outside", temp.path().join("src/leak.gleam")).unwrap();
    assert_error_contains(normalize_package_dir(temp.path()), "not a regular file");
}

#[test]
fn docs_interface_lookup_handles_nested_absent_and_malformed_archives() {
    let nested = tar_gz(&[("doc/widget/package-interface.json", br#"{"modules":{}}"#)]);
    assert_eq!(
        interface_from_docs_tarball(&nested).unwrap(),
        Some(br#"{"modules":{}}"#.to_vec())
    );
    assert_eq!(
        interface_from_docs_tarball(&tar_gz(&[("index.html", b"ok")])).unwrap(),
        None
    );
    assert!(interface_from_docs_tarball(b"not gzip").is_err());
}

fn assert_error_contains<T: std::fmt::Debug>(result: anyhow::Result<T>, expected: &str) {
    let error = format!("{:#}", result.unwrap_err());
    assert!(
        error.contains(expected),
        "expected {expected:?} in {error:?}"
    );
}

fn outer_package(
    version: &[u8],
    metadata: &[u8],
    contents: &[u8],
    checksum: Option<&[u8]>,
    extra: &[(&str, &[u8])],
) -> Vec<u8> {
    let expected = checksum.map(Vec::from).unwrap_or_else(|| {
        let mut digest = Sha256::new();
        digest.update(version);
        digest.update(metadata);
        digest.update(contents);
        format!("{:X}", digest.finalize()).into_bytes()
    });
    let mut files = vec![
        ("VERSION", version),
        ("metadata.config", metadata),
        ("contents.tar.gz", contents),
        ("CHECKSUM", expected.as_slice()),
    ];
    files.extend_from_slice(extra);
    tar(&files)
}

fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (path, contents) in files {
        append(&mut archive, path, contents, tar::EntryType::Regular);
    }
    archive.into_inner().unwrap().finish().unwrap()
}

fn special_tar_gz(kind: tar::EntryType, contents: &[u8]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let name = if kind.is_dir() { "directory/" } else { "entry" };
    append(&mut archive, name, contents, kind);
    archive.into_inner().unwrap().finish().unwrap()
}

fn extension_tar_gz(kind: tar::EntryType) -> Vec<u8> {
    let contents = match kind {
        tar::EntryType::GNULongName => b"nested/extended.txt\0".to_vec(),
        tar::EntryType::GNULongLink => b"outside\0".to_vec(),
        tar::EntryType::XHeader | tar::EntryType::XGlobalHeader => {
            pax_record("path", "nested/file.txt")
        }
        _ => unreachable!(),
    };
    extension_tar_gz_with_contents(kind, &contents)
}

fn extension_tar_gz_with_contents(kind: tar::EntryType, contents: &[u8]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    append(&mut archive, "extension", contents, kind);
    append(&mut archive, "short.txt", b"safe", tar::EntryType::Regular);
    archive.into_inner().unwrap().finish().unwrap()
}

fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!("{key}={value}\n");
    let mut length = body.len() + 2;
    loop {
        let next = body.len() + length.to_string().len() + 1;
        if next == length {
            return format!("{length} {body}").into_bytes();
        }
        length = next;
    }
}

fn tar_gz_with_rewritten_first_path(path: &[u8]) -> Vec<u8> {
    let mut raw = tar(&[("safe", b"contents")]);
    raw[..100].fill(0);
    raw[..path.len()].copy_from_slice(path);
    raw[148..156].fill(b' ');
    let checksum: u32 = raw[..512].iter().map(|byte| u32::from(*byte)).sum();
    let field = format!("{checksum:06o}\0 ");
    raw[148..156].copy_from_slice(field.as_bytes());

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&raw).unwrap();
    encoder.finish().unwrap()
}

fn tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut bytes);
        for (path, contents) in files {
            append(&mut archive, path, contents, tar::EntryType::Regular);
        }
        archive.finish().unwrap();
    }
    bytes
}

fn append<W: Write>(
    archive: &mut tar::Builder<W>,
    path: &str,
    contents: &[u8],
    kind: tar::EntryType,
) {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_size(contents.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    if kind.is_symlink() || kind.is_hard_link() {
        header.set_link_name("outside").unwrap();
    }
    header.set_cksum();
    archive.append_data(&mut header, path, contents).unwrap();
}
