//! The release step that a Conventional Commits message asks for.

use crate::Bump;

/// The release step that a Conventional Commits message asks for.
///
/// A `!` right before the colon of the header, or a body line that starts with `BREAKING CHANGE:` or `BREAKING-CHANGE:`, asks for a major release.
/// Otherwise the type decides in any letter case: `feat` asks for a minor release, and `fix` or `perf` for a patch.
pub fn conventional_bump(subject: &str, body: &str) -> Bump {
    let header = subject.split(':').next().unwrap_or(subject);
    if header.ends_with('!') || body.lines().any(breaking_footer) {
        return Bump::Major;
    }
    let kind = header.split('(').next().unwrap_or(header);
    if names(kind, "feat") {
        Bump::Minor
    } else if names(kind, "fix") || names(kind, "perf") {
        Bump::Patch
    } else {
        Bump::None
    }
}

/// Whether a body line opens a breaking-change footer, which Conventional Commits spells only in uppercase.
fn breaking_footer(line: &str) -> bool {
    #[cfg(feature = "negative-control-breaking-footer")]
    return line.starts_with("BREAKING CHANGE:");
    #[cfg(not(feature = "negative-control-breaking-footer"))]
    return line.starts_with("BREAKING CHANGE:") || line.starts_with("BREAKING-CHANGE:");
}

/// Whether a commit type is `name` in any letter case.
fn names(kind: &str, name: &str) -> bool {
    #[cfg(feature = "negative-control-commit-type-case")]
    return kind == name;
    #[cfg(not(feature = "negative-control-commit-type-case"))]
    return kind.eq_ignore_ascii_case(name);
}

#[cfg(kani)]
mod proofs {
    use super::conventional_bump;
    use crate::Bump;

    /// The longest free text around a marker that the proofs cover.
    const FREE: usize = 3;

    /// A symbolic ASCII string of at most `N` bytes over `bytes`.
    fn any_text<const N: usize>(bytes: &[u8; N]) -> &str {
        let length: usize = kani::any();
        kani::assume(length <= N);
        let text = &bytes[..length];
        kani::assume(text.iter().all(u8::is_ascii));
        core::str::from_utf8(text).unwrap_or_default()
    }

    /// A breaking-change footer anywhere after the first body line, or a `!` before the colon, always asks for a major release.
    ///
    /// The subject and the text around the footer are symbolic ASCII of at most three bytes each.
    #[kani::proof]
    #[kani::unwind(24)]
    fn a_breaking_marker_always_asks_for_a_major_release() {
        let subject_bytes: [u8; FREE] = kani::any();
        let subject = any_text(&subject_bytes);
        let before_bytes: [u8; FREE] = kani::any();
        let before = any_text(&before_bytes);
        kani::assume(!before.contains('\n'));
        let after_bytes: [u8; FREE] = kani::any();
        let after = any_text(&after_bytes);
        let hyphen: bool = kani::any();
        let marker = if hyphen {
            "BREAKING-CHANGE:"
        } else {
            "BREAKING CHANGE:"
        };
        let mut body = [0_u8; 2 * FREE + 18];
        let mut length = 0;
        for part in [
            before.as_bytes(),
            b"\n",
            marker.as_bytes(),
            after.as_bytes(),
        ] {
            body[length..length + part.len()].copy_from_slice(part);
            length += part.len();
        }
        let body = core::str::from_utf8(&body[..length]).unwrap_or_default();
        kani::assert(
            conventional_bump(subject, body) == Bump::Major,
            "a breaking-change footer must ask for a major release",
        );
        kani::cover!(hyphen);
        kani::cover!(!hyphen);

        let header_bytes: [u8; FREE] = kani::any();
        let header = any_text(&header_bytes);
        kani::assume(!header.contains(':'));
        let mut subject = [0_u8; 2 * FREE + 2];
        let mut length = 0;
        for part in [header.as_bytes(), b"!:", after.as_bytes()] {
            subject[length..length + part.len()].copy_from_slice(part);
            length += part.len();
        }
        let subject = core::str::from_utf8(&subject[..length]).unwrap_or_default();
        assert!(conventional_bump(subject, before) == Bump::Major);
    }

    /// Without a breaking marker, the type decides the step in any letter case, and any other type asks for none.
    ///
    /// The type's letter case is symbolic, and so are a scope or description of at most three bytes and an unknown type of at most four.
    #[kani::proof]
    #[kani::unwind(12)]
    fn the_commit_type_decides_the_step_without_a_breaking_marker() {
        let which: u8 = kani::any();
        kani::assume(which < 3);
        let (name, step) = match which {
            0 => ("feat", Bump::Minor),
            1 => ("fix", Bump::Patch),
            _ => ("perf", Bump::Patch),
        };
        let mut kind = [0_u8; 4];
        for (index, letter) in name.bytes().enumerate() {
            kind[index] = if kani::any() {
                letter.to_ascii_uppercase()
            } else {
                letter
            };
        }
        let kind = core::str::from_utf8(&kind[..name.len()]).unwrap_or_default();
        let rest_bytes: [u8; FREE] = kani::any();
        let rest = any_text(&rest_bytes);
        kani::assume(!rest.contains(':') && !rest.contains('!'));
        let open: bool = kani::any();
        let mut subject = [0_u8; 4 + 2 + FREE];
        let mut length = 0;
        let separator: &[u8] = if open { b"(" } else { b": " };
        for part in [kind.as_bytes(), separator, rest.as_bytes()] {
            subject[length..length + part.len()].copy_from_slice(part);
            length += part.len();
        }
        let subject = core::str::from_utf8(&subject[..length]).unwrap_or_default();
        kani::assert(
            conventional_bump(subject, "") == step,
            "a commit type must decide the step in any letter case",
        );
        kani::cover!(which == 0 && kind != name);

        let other_bytes: [u8; 4] = kani::any();
        let other = any_text(&other_bytes);
        kani::assume(!other.contains(':') && !other.contains('(') && !other.ends_with('!'));
        kani::assume(
            !other.eq_ignore_ascii_case("feat")
                && !other.eq_ignore_ascii_case("fix")
                && !other.eq_ignore_ascii_case("perf"),
        );
        assert!(conventional_bump(other, "") == Bump::None);
    }
}
