//! The release step that a Conventional Commits message asks for.

use crate::Bump;

/// The release step that a Conventional Commits message asks for.
///
/// A `!` right before the colon of the header, or a body line that starts with `BREAKING CHANGE:` or `BREAKING-CHANGE:`, asks for a major release.
/// Otherwise the type decides in any letter case: `feat` asks for a minor release, and `fix` or `perf` for a patch.
pub fn conventional_bump(subject: &str, body: &str) -> Bump {
    bump_of(subject.as_bytes(), body.as_bytes())
}

fn bump_of(subject: &[u8], body: &[u8]) -> Bump {
    let header = before(subject, b':');
    if header.last() == Some(&b'!') || has_breaking_footer(body) {
        return Bump::Major;
    }
    let kind = before(header, b'(');
    if names(kind, b"feat") {
        Bump::Minor
    } else if names(kind, b"fix") || names(kind, b"perf") {
        Bump::Patch
    } else {
        Bump::None
    }
}

/// The bytes of `text` before its first `separator`, or all of them.
fn before(text: &[u8], separator: u8) -> &[u8] {
    let mut end = 0;
    while let Some(byte) = text.get(end)
        && *byte != separator
    {
        end += 1;
    }
    text.get(..end).unwrap_or(text)
}

/// Whether a line of `body` opens a breaking-change footer.
///
/// One indexed scan visits every line start, which a proof unwinds once per byte.
fn has_breaking_footer(body: &[u8]) -> bool {
    let mut index = 0;
    let mut line_start = true;
    while let Some(byte) = body.get(index) {
        if line_start && breaking_footer(body.get(index..).unwrap_or_default()) {
            return true;
        }
        line_start = *byte == b'\n';
        index += 1;
    }
    false
}

/// Whether a body line opens a breaking-change footer, which Conventional Commits spells only in uppercase.
fn breaking_footer(line: &[u8]) -> bool {
    #[cfg(feature = "negative-control-breaking-footer")]
    if let Some(footer) = negative_control_spaced_footer_only(line) {
        return footer;
    }
    line.starts_with(b"BREAKING CHANGE:") || line.starts_with(b"BREAKING-CHANGE:")
}

/// Misses the hyphenated breaking-change footer.
#[cfg(feature = "negative-control-breaking-footer")]
fn negative_control_spaced_footer_only(line: &[u8]) -> Option<bool> {
    Some(line.starts_with(b"BREAKING CHANGE:"))
}

/// Whether a commit type is `name` in any letter case.
fn names(kind: &[u8], name: &[u8]) -> bool {
    #[cfg(feature = "negative-control-commit-type-case")]
    if let Some(named) = negative_control_exact_case(kind, name) {
        return named;
    }
    kind.eq_ignore_ascii_case(name)
}

/// Matches commit types in lowercase only.
#[cfg(feature = "negative-control-commit-type-case")]
fn negative_control_exact_case(kind: &[u8], name: &[u8]) -> Option<bool> {
    Some(kind == name)
}

#[cfg(kani)]
mod proofs {
    use super::bump_of;
    use crate::Bump;

    /// The number of free bytes around each marker that the proofs cover.
    const FREE: usize = 3;

    /// The length of a breaking-change footer's marker.
    const MARKER: usize = 16;

    /// Symbolic ASCII bytes.
    fn ascii<const N: usize>() -> [u8; N] {
        let bytes: [u8; N] = kani::any();
        kani::assume(bytes.is_ascii());
        bytes
    }

    /// A breaking-change footer on a line after the first, or a `!` right before the header's colon, always asks for a major release.
    ///
    /// The subject and the text before and after each marker are three symbolic ASCII bytes each.
    #[kani::proof]
    #[kani::unwind(24)]
    fn a_breaking_marker_always_asks_for_a_major_release() {
        let subject: [u8; FREE] = ascii();
        let before: [u8; FREE] = ascii();
        let after: [u8; FREE] = ascii();
        let hyphen: bool = kani::any();
        let marker: &[u8; MARKER] = if hyphen {
            b"BREAKING-CHANGE:"
        } else {
            b"BREAKING CHANGE:"
        };
        let mut body = [0_u8; 2 * FREE + 1 + MARKER];
        body[..FREE].copy_from_slice(&before);
        body[FREE] = b'\n';
        body[FREE + 1..FREE + 1 + MARKER].copy_from_slice(marker);
        body[FREE + 1 + MARKER..].copy_from_slice(&after);
        kani::assert(
            bump_of(&subject, &body) == Bump::Major,
            "a breaking-change footer must ask for a major release",
        );
        kani::cover!(hyphen);
        kani::cover!(!hyphen);

        let header: [u8; FREE] = ascii();
        kani::assume(!header.contains(&b':'));
        let mut subject = [0_u8; 2 * FREE + 2];
        subject[..FREE].copy_from_slice(&header);
        subject[FREE..FREE + 2].copy_from_slice(b"!:");
        subject[FREE + 2..].copy_from_slice(&after);
        assert!(bump_of(&subject, &before) == Bump::Major);
    }

    /// Without a breaking marker, the type decides the step in any letter case, and any other type asks for none.
    ///
    /// The type's letter case is symbolic, and so are a scope or description of three ASCII bytes and an unknown type of at most four.
    #[kani::proof]
    #[kani::unwind(10)]
    fn the_commit_type_decides_the_step_without_a_breaking_marker() {
        let which: u8 = kani::any();
        kani::assume(which < 3);
        let (name, step): (&[u8], Bump) = match which {
            0 => (b"feat", Bump::Minor),
            1 => (b"fix", Bump::Patch),
            _ => (b"perf", Bump::Patch),
        };
        let separator: &[u8] = if kani::any() { b"(" } else { b": " };
        let rest: [u8; FREE] = ascii();
        kani::assume(!rest.contains(&b':') && !rest.contains(&b'!'));
        let mut subject = [0_u8; 4 + 2 + FREE];
        let mut length = 0;
        for letter in name {
            subject[length] = if kani::any() {
                letter.to_ascii_uppercase()
            } else {
                *letter
            };
            length += 1;
        }
        for byte in separator.iter().chain(&rest) {
            subject[length] = *byte;
            length += 1;
        }
        kani::assert(
            bump_of(&subject[..length], b"") == step,
            "a commit type must decide the step in any letter case",
        );
        kani::cover!(which == 0 && subject[..4] != *b"feat");

        let other: [u8; 4] = ascii();
        let other_length: usize = kani::any();
        kani::assume(other_length <= 4);
        let other = &other[..other_length];
        kani::assume(
            !other.contains(&b':') && !other.contains(&b'(') && other.last() != Some(&b'!'),
        );
        kani::assume(
            !other.eq_ignore_ascii_case(b"feat")
                && !other.eq_ignore_ascii_case(b"fix")
                && !other.eq_ignore_ascii_case(b"perf"),
        );
        assert!(bump_of(other, b"") == Bump::None);
    }
}
