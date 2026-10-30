//! Which archive entry paths release-glz extracts, and when two entries name the same file.
//!
//! The rules hold on every supported OS at once, so a verdict never depends on the host that reaches it.
//! They read the bytes of a path: every byte they look for is ASCII, and UTF-8 never uses an ASCII byte inside a longer character, so on UTF-8 they decide what the same rules on characters would.

use core::ops::RangeInclusive;

/// The path that an archive entry names, without its trailing slashes, when every component is portable.
///
/// The shell decodes the entry's path as UTF-8 first, and a slash is ASCII, so the path without its trailing slashes is UTF-8 too.
pub fn archive_path(value: &str) -> Option<&str> {
    let path = value.get(..without_trailing_slashes(value.as_bytes()))?;
    portable_path(path.as_bytes()).then_some(path)
}

/// The length of `path` without its trailing slashes.
fn without_trailing_slashes(path: &[u8]) -> usize {
    #[cfg(feature = "negative-control-keep-trailing-slashes")]
    if let Some(length) = negative_control_keep_trailing_slashes(path) {
        return length;
    }
    path.iter()
        .rposition(|byte| *byte != b'/')
        .map_or(0, |last| last + 1)
}

/// Whether every `/`-separated component of `path` is portable.
pub fn portable_path(path: &[u8]) -> bool {
    #[cfg(feature = "negative-control-first-component")]
    if let Some(portable) = negative_control_first_component(path) {
        return portable;
    }
    path.split(|byte| *byte == b'/').all(portable_component)
}

/// Keeps the trailing slashes of a path, so a directory entry reads as a path with an empty last component.
#[cfg(feature = "negative-control-keep-trailing-slashes")]
fn negative_control_keep_trailing_slashes(path: &[u8]) -> Option<usize> {
    Some(path.len())
}

/// Checks only the first component of a path, so a later `..` passes.
#[cfg(feature = "negative-control-first-component")]
fn negative_control_first_component(path: &[u8]) -> Option<bool> {
    Some(
        path.split(|byte| *byte == b'/')
            .next()
            .is_some_and(portable_component),
    )
}

/// Whether every supported OS stores a path component under exactly this name.
///
/// Windows forbids some characters, reads a colon as a stream separator, drops a trailing dot or space, and reserves device names in every directory.
/// Refusing those names on every host keeps a verdict from depending on where release-glz runs.
pub fn portable_component(component: &[u8]) -> bool {
    let mut portable = !component.is_empty() && !dropped_suffix(component);
    let mut previous = None;
    for &byte in component {
        portable &= !forbidden_byte(byte) && !previous.is_some_and(|lead| c1_control(lead, byte));
        previous = Some(byte);
    }
    portable && !device_stem(stem(component))
}

/// Whether Windows would drop the last character of a component, which also refuses `.` and `..`.
fn dropped_suffix(component: &[u8]) -> bool {
    #[cfg(feature = "negative-control-path-traversal")]
    if let Some(dropped) = negative_control_path_traversal(component) {
        return dropped;
    }
    matches!(component.last(), Some(b'.' | b' '))
}

/// Whether `byte` is an ASCII control character or one that Windows forbids in a name.
fn forbidden_byte(byte: u8) -> bool {
    #[cfg(feature = "negative-control-path-colon")]
    if let Some(forbidden) = negative_control_path_colon(byte) {
        return forbidden;
    }
    byte.is_ascii_control()
        || matches!(byte, b'\\' | b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*')
}

/// The UTF-8 lead byte of U+0080 to U+00BF, which hold the C1 controls and the superscript one, two, and three.
const LATIN_1_LEAD: u8 = 0xc2;
/// The UTF-8 trail bytes of the C1 controls, U+0080 to U+009F.
const C1_TRAILS: RangeInclusive<u8> = 0x80..=0x9f;
/// The UTF-8 trail byte of the superscript one, U+00B9.
const SUPERSCRIPT_ONE: u8 = 0xb9;
/// The UTF-8 trail byte of the superscript two, U+00B2.
const SUPERSCRIPT_TWO: u8 = 0xb2;
/// The UTF-8 trail byte of the superscript three, U+00B3.
const SUPERSCRIPT_THREE: u8 = 0xb3;

/// Whether two bytes encode a C1 control character.
fn c1_control(lead: u8, trail: u8) -> bool {
    lead == LATIN_1_LEAD && C1_TRAILS.contains(&trail)
}

/// The stem of a component: its bytes before the first dot, without trailing spaces.
fn stem(component: &[u8]) -> &[u8] {
    #[cfg(feature = "negative-control-device-stem")]
    if let Some(stem) = negative_control_device_stem(component) {
        return stem;
    }
    let end = component
        .iter()
        .position(|byte| *byte == b'.')
        .unwrap_or(component.len());
    without_trailing_spaces(&component[..end])
}

fn without_trailing_spaces(mut name: &[u8]) -> &[u8] {
    while let [rest @ .., b' '] = name {
        name = rest;
    }
    name
}

/// Whether a stem names a Windows device, whatever its ASCII letter case.
///
/// A port is `COM` or `LPT` followed by a digit or by the superscript one, two, or three.
fn device_stem(stem: &[u8]) -> bool {
    match *stem {
        [a, b, c] => {
            let name = [a, b, c];
            same_name(&name, b"CON")
                || same_name(&name, b"PRN")
                || same_name(&name, b"AUX")
                || same_name(&name, b"NUL")
        }
        [a, b, c, number] => port(&[a, b, c]) && number.is_ascii_digit(),
        [
            a,
            b,
            c,
            LATIN_1_LEAD,
            SUPERSCRIPT_ONE | SUPERSCRIPT_TWO | SUPERSCRIPT_THREE,
        ] => port(&[a, b, c]),
        [a, b, c, d, e, f] => same_name(&[a, b, c, d, e, f], b"CONIN$"),
        [a, b, c, d, e, f, g] => same_name(&[a, b, c, d, e, f, g], b"CONOUT$"),
        _ => false,
    }
}

/// Whether three bytes are the name of a serial or parallel port.
fn port(name: &[u8; 3]) -> bool {
    same_name(name, b"COM") || same_name(name, b"LPT")
}

/// Whether a stem is a device name once ASCII letter case no longer counts.
fn same_name(stem: &[u8], name: &[u8]) -> bool {
    #[cfg(feature = "negative-control-device-case")]
    if let Some(same) = negative_control_device_case(stem, name) {
        return same;
    }
    stem.eq_ignore_ascii_case(name)
}

/// The folded paths that the entries of one archive claimed so far, which the shell keeps.
///
/// The shell folds each path, and the fold has to keep every `/` where it is, so the prefixes of a folded path name its directories.
pub trait ClaimedPaths {
    /// What the shell keeps for an entry, such as its path.
    type Entry: Clone;

    /// The entry that claimed `folded` as a file.
    fn file(&self, folded: &[u8]) -> Option<&Self::Entry>;

    /// The entry that claimed `folded` as a directory.
    fn directory(&self, folded: &[u8]) -> Option<&Self::Entry>;

    /// Keep `entry` as the claim of the file `folded`.
    fn record_file(&mut self, folded: &[u8], entry: Self::Entry);

    /// Keep `entry` as the claim of the directory `folded`.
    fn record_directory(&mut self, folded: &[u8], entry: Self::Entry);
}

/// An earlier entry that names the same file or directory as a new one once both paths are folded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collision<E> {
    earlier: E,
}

impl<E> Collision<E> {
    /// The earlier entry.
    pub fn earlier(&self) -> &E {
        &self.earlier
    }
}

/// Record `entry` under the folded path `folded`, or refuse it with the earlier entry whose folded path names the same file or directory.
///
/// A directory keeps the first entry that claimed it.
pub fn claim_path<P: ClaimedPaths>(
    paths: &mut P,
    folded: &[u8],
    entry: P::Entry,
) -> Result<(), Collision<P::Entry>> {
    if let Some(earlier) =
        collision(folded, |key| paths.file(key), |key| paths.directory(key)).cloned()
    {
        return Err(Collision { earlier });
    }
    #[cfg(feature = "negative-control-forget-files")]
    if let Some(claimed) = negative_control_forget_files() {
        return claimed;
    }
    for directory in directories_above(folded) {
        if unclaimed(paths, directory) {
            paths.record_directory(directory, entry.clone());
        }
    }
    paths.record_file(folded, entry);
    Ok(())
}

/// Accepts an entry without recording it, so a later entry of the same path passes.
#[cfg(feature = "negative-control-forget-files")]
fn negative_control_forget_files<E>() -> Option<Result<(), Collision<E>>> {
    Some(Ok(()))
}

/// Whether no earlier entry claimed the directory `folded`, so a claim records it.
fn unclaimed<P: ClaimedPaths>(paths: &P, folded: &[u8]) -> bool {
    #[cfg(feature = "negative-control-overwrite-directory")]
    if let Some(unclaimed) = negative_control_overwrite_directory() {
        return unclaimed;
    }
    paths.directory(folded).is_none()
}

/// Records a later entry for a directory that an earlier entry claimed.
#[cfg(feature = "negative-control-overwrite-directory")]
fn negative_control_overwrite_directory() -> Option<bool> {
    Some(true)
}

/// The folded paths of the directories that hold `folded`: its prefixes before each `/`.
fn directories_above(folded: &[u8]) -> impl Iterator<Item = &[u8]> {
    (0..folded.len())
        .filter(move |&end| ends_directory(folded, end))
        .map(move |end| &folded[..end])
}

/// Whether the prefix of `folded` before `end` names a directory, which it does when a `/` follows it.
fn ends_directory(folded: &[u8], end: usize) -> bool {
    #[cfg(feature = "negative-control-directory-at-every-byte")]
    if let Some(ends) = negative_control_directory_at_every_byte() {
        return ends;
    }
    folded.get(end) == Some(&b'/')
}

/// Takes the prefix before every byte for a directory.
#[cfg(feature = "negative-control-directory-at-every-byte")]
fn negative_control_directory_at_every_byte() -> Option<bool> {
    Some(true)
}

/// The earlier entry that a folded path collides with: a file or a directory of the same folded path, or a file that the path lies inside.
///
/// `file` and `directory` find the entry that recorded a folded file, or a directory as one of its prefixes before a `/`.
fn collision<'a, T: ?Sized>(
    folded: &[u8],
    file: impl Fn(&[u8]) -> Option<&'a T>,
    directory: impl Fn(&[u8]) -> Option<&'a T>,
) -> Option<&'a T> {
    #[cfg(feature = "negative-control-case-collision")]
    if let Some(other) = negative_control_case_collision(folded, &file, &directory) {
        return other;
    }
    if let Some(other) = file(folded).or_else(|| directory(folded)) {
        return Some(other);
    }
    for end in 0..folded.len() {
        if folded[end] == b'/'
            && let Some(other) = file(&folded[..end])
        {
            return Some(other);
        }
    }
    None
}

/// Accepts a `..` component.
#[cfg(feature = "negative-control-path-traversal")]
fn negative_control_path_traversal(component: &[u8]) -> Option<bool> {
    (component == b"..").then_some(false)
}

/// Accepts a colon in a component.
#[cfg(feature = "negative-control-path-colon")]
fn negative_control_path_colon(byte: u8) -> Option<bool> {
    (byte == b':').then_some(false)
}

/// Ends the stem of a component at its last dot instead of its first.
#[cfg(feature = "negative-control-device-stem")]
fn negative_control_device_stem(component: &[u8]) -> Option<&[u8]> {
    let end = component.iter().rposition(|byte| *byte == b'.')?;
    Some(without_trailing_spaces(&component[..end]))
}

/// Recognizes a device name only in uppercase.
#[cfg(feature = "negative-control-device-case")]
fn negative_control_device_case(stem: &[u8], name: &[u8]) -> Option<bool> {
    Some(stem == name)
}

/// Lets an entry stand inside an earlier file.
#[cfg(feature = "negative-control-case-collision")]
fn negative_control_case_collision<'a, T: ?Sized>(
    folded: &[u8],
    file: impl Fn(&[u8]) -> Option<&'a T>,
    directory: impl Fn(&[u8]) -> Option<&'a T>,
) -> Option<Option<&'a T>> {
    Some(file(folded).or_else(|| directory(folded)))
}

#[cfg(kani)]
mod proofs {
    use super::{
        ClaimedPaths, archive_path, c1_control, claim_path, collision, device_stem,
        directories_above, forbidden_byte, portable_component, portable_path, stem,
        without_trailing_slashes,
    };

    /// Every stem that Windows reserves for a device, in uppercase, written out rather than parsed.
    const DEVICE_STEMS: [&[u8]; 32] = [
        b"CON",
        b"PRN",
        b"AUX",
        b"NUL",
        b"CONIN$",
        b"CONOUT$",
        b"COM0",
        b"COM1",
        b"COM2",
        b"COM3",
        b"COM4",
        b"COM5",
        b"COM6",
        b"COM7",
        b"COM8",
        b"COM9",
        b"COM\xc2\xb9",
        b"COM\xc2\xb2",
        b"COM\xc2\xb3",
        b"LPT0",
        b"LPT1",
        b"LPT2",
        b"LPT3",
        b"LPT4",
        b"LPT5",
        b"LPT6",
        b"LPT7",
        b"LPT8",
        b"LPT9",
        b"LPT\xc2\xb9",
        b"LPT\xc2\xb2",
        b"LPT\xc2\xb3",
    ];

    /// The characters other than control characters that Windows forbids in a name.
    const WINDOWS_FORBIDDEN: [u8; 8] = *b"\\<>:\"|?*";

    /// What one bounded check found: whether the property held, and whether the input was one that a cover asks for.
    #[derive(Clone, Copy)]
    struct Check {
        held: bool,
        notable: bool,
    }

    /// A byte is refused exactly when it is an ASCII control character or a character that Windows forbids in a name, and a byte pair exactly when it encodes a C1 control character.
    ///
    /// Every byte, and every pair of bytes, with the pair decoded by hand from the UTF-8 rules for two-byte characters.
    #[kani::proof]
    #[kani::unwind(10)]
    fn a_component_refuses_exactly_the_characters_windows_forbids() {
        let byte: u8 = kani::any();
        let mut windows_forbidden = false;
        for index in 0..WINDOWS_FORBIDDEN.len() {
            windows_forbidden |= byte == WINDOWS_FORBIDDEN[index];
        }
        kani::assert(
            forbidden_byte(byte)
                == (byte.is_ascii() && (char::from(byte).is_control() || windows_forbidden)),
            "a component must refuse every character that Windows forbids",
        );
        let lead: u8 = kani::any();
        let trail: u8 = kani::any();
        let two_byte = (0xc2..=0xdf).contains(&lead) && (0x80..=0xbf).contains(&trail);
        let scalar = (u32::from(lead & 0x1f) << 6) | u32::from(trail & 0x3f);
        kani::assert(
            c1_control(lead, trail) == (two_byte && (0x80..=0x9f).contains(&scalar)),
            "a component must refuse every C1 control character",
        );
        kani::cover!(forbidden_byte(byte) && byte > 0x20);
        kani::cover!(c1_control(lead, trail));
    }

    /// A stem names a device exactly when it is a reserved stem in any ASCII letter case.
    ///
    /// Every stem of up to eight bytes, one byte more than the longest reserved stem.
    /// A longer stem matches no length that `device_stem` names.
    #[kani::proof]
    #[kani::unwind(34)]
    fn a_stem_names_a_device_exactly_when_it_is_reserved() {
        let checks = [
            stem_check::<0>(),
            stem_check::<1>(),
            stem_check::<2>(),
            stem_check::<3>(),
            stem_check::<4>(),
            stem_check::<5>(),
            stem_check::<6>(),
            stem_check::<7>(),
            stem_check::<8>(),
        ];
        let mut held = true;
        for index in 0..checks.len() {
            held &= checks[index].held;
        }
        kani::assert(
            held,
            "a stem must name a device exactly when it is reserved",
        );
        kani::cover!(checks[3].notable);
        kani::cover!(checks[4].notable);
        kani::cover!(checks[5].notable);
        kani::cover!(checks[7].notable);
    }

    /// Whether `device_stem` agrees with the table on a stem of `N` arbitrary bytes, which is notable when it is reserved.
    fn stem_check<const N: usize>() -> Check {
        let candidate: [u8; N] = kani::any();
        let mut reserved = false;
        for entry in 0..DEVICE_STEMS.len() {
            let upper = DEVICE_STEMS[entry];
            if upper.len() == N {
                let mut same = true;
                for index in 0..N {
                    same &= candidate[index].to_ascii_uppercase() == upper[index];
                }
                reserved |= same;
            }
        }
        Check {
            held: device_stem(&candidate) == reserved,
            notable: reserved,
        }
    }

    /// The stem of a component ends before its first dot and drops the spaces before that point.
    ///
    /// Every component of one to six bytes.
    #[kani::proof]
    #[kani::unwind(8)]
    fn a_stem_ends_at_the_first_dot_without_trailing_spaces() {
        let checks = [
            stem_end_check::<1>(),
            stem_end_check::<2>(),
            stem_end_check::<3>(),
            stem_end_check::<4>(),
            stem_end_check::<5>(),
            stem_end_check::<6>(),
        ];
        let mut held = true;
        for index in 0..checks.len() {
            held &= checks[index].held;
        }
        kani::assert(held, "the stem of a component must end at its first dot");
        kani::cover!(checks[5].notable);
    }

    /// Whether `stem` ends where it should on a component of `N` arbitrary bytes, which is notable when it has two dots.
    fn stem_end_check<const N: usize>() -> Check {
        let component: [u8; N] = kani::any();
        let mut end = 0;
        while end < N && component[end] != b'.' {
            end += 1;
        }
        while end > 0 && component[end - 1] == b' ' {
            end -= 1;
        }
        let mut dots = 0;
        for index in 0..N {
            dots += usize::from(component[index] == b'.');
        }
        Check {
            held: stem(&component) == &component[..end],
            notable: dots > 1,
        }
    }

    /// An accepted component is never empty, `.`, or `..`, and holds no backslash or colon, which Windows reads as a separator, a drive, or a stream.
    ///
    /// Every component of up to eight bytes.
    /// A longer component can't be `.` or `..`, and the character harness decides every byte of any length.
    /// `portable_path` accepts a path exactly when every `/`-separated component passes, so an accepted path also has no leading, doubled, or trailing slash, and never leaves its destination.
    #[kani::proof]
    #[kani::unwind(10)]
    fn an_accepted_archive_path_stays_inside_its_destination() {
        let checks = [
            component_check::<0>(),
            component_check::<1>(),
            component_check::<2>(),
            component_check::<3>(),
            component_check::<4>(),
            component_check::<5>(),
            component_check::<6>(),
            component_check::<7>(),
            component_check::<8>(),
        ];
        let mut held = true;
        for index in 0..checks.len() {
            held &= checks[index].held;
        }
        kani::assert(held, "an accepted path must stay inside its destination");
        kani::cover!(checks[2].notable);
        kani::cover!(checks[8].notable);
    }

    /// Whether a component of `N` arbitrary bytes stays inside its parent when it passes, which is notable when it passes.
    fn component_check<const N: usize>() -> Check {
        let component: [u8; N] = kani::any();
        let passed = portable_component(&component);
        let mut separator = false;
        for index in 0..N {
            separator |= component[index] == b'\\' || component[index] == b':';
        }
        let parent_or_self = component.as_slice() == b"." || component.as_slice() == b"..";
        Check {
            held: !passed || (N > 0 && !parent_or_self && !separator),
            notable: passed,
        }
    }

    /// The bytes that the path proofs build paths from: a portable component, a dot, and a slash, which meet a portable component, `.`, `..`, and an empty one in every place.
    const ALPHABET: [u8; 3] = *b"a./";

    /// A path passes exactly when every `/`-separated component of it is portable.
    ///
    /// Every path of three bytes over `a`, `.`, and `/`, split at its slashes by hand, which holds one to three components.
    /// The component harnesses decide what a portable component is for every byte, and symbolic bytes across a whole path exhaust the solver.
    #[kani::proof]
    #[kani::unwind(10)]
    fn a_path_passes_exactly_when_each_component_does() {
        let mut held = true;
        let mut notable = false;
        for first in ALPHABET {
            for second in ALPHABET {
                for third in ALPHABET {
                    check_path(&[first, second, third], &mut held, &mut notable);
                }
            }
        }
        kani::assert(held, "a path must pass exactly when each component does");
        kani::cover!(notable);
    }

    /// An archive entry names its path without the trailing slashes, when every component of that path is portable.
    ///
    /// Every path of up to two bytes over `a`, `.`, and `/`, trimmed by hand, and `archive_path` on fixed texts, a two-byte character among them.
    #[kani::proof]
    #[kani::unwind(10)]
    fn an_archive_path_is_its_text_without_trailing_slashes() {
        let mut held = true;
        let mut notable = false;
        check_path(&[], &mut held, &mut notable);
        for first in ALPHABET {
            check_path(&[first], &mut held, &mut notable);
            for second in ALPHABET {
                check_path(&[first, second], &mut held, &mut notable);
            }
        }
        held &= archive_path("a/b") == Some("a/b")
            && archive_path("a/b//") == Some("a/b")
            && archive_path("\u{e9}/") == Some("\u{e9}")
            && archive_path("a//b").is_none()
            && archive_path("a/../b").is_none()
            && archive_path("//").is_none()
            && archive_path("").is_none();
        kani::assert(
            held,
            "an archive path must be its text without the trailing slashes",
        );
        kani::cover!(archive_path("a/").is_some());
    }

    /// Whether `portable_path` decides `path` as splitting it at its slashes by hand does, and whether trimming finds where its trailing slashes start, which is notable when a path of two components or more passes.
    fn check_path(path: &[u8], held: &mut bool, notable: &mut bool) {
        let mut portable = true;
        let mut components = 0;
        let mut start = 0;
        for index in 0..=path.len() {
            if index == path.len() || path[index] == b'/' {
                portable &= portable_component(&path[start..index]);
                components += 1;
                start = index + 1;
            }
        }
        let mut end = path.len();
        while end > 0 && path[end - 1] == b'/' {
            end -= 1;
        }
        let passed = portable_path(path);
        *held &= passed == portable && without_trailing_slashes(path) == end;
        *notable |= passed && components > 1;
    }

    /// The directories that hold a folded path are exactly its prefixes before each `/`, in order.
    ///
    /// Every folded path of up to four arbitrary bytes.
    #[kani::proof]
    #[kani::unwind(6)]
    fn the_directories_above_a_path_are_its_prefixes_before_each_slash() {
        let bytes: [u8; 4] = kani::any();
        let length: usize = kani::any_where(|length| *length <= bytes.len());
        let folded = &bytes[..length];
        let mut found = directories_above(folded);
        let mut held = true;
        let mut directories = 0;
        for end in 0..length {
            if folded[end] == b'/' {
                held &= found
                    .next()
                    .is_some_and(|directory| directory == &folded[..end]);
                directories += 1;
            }
        }
        held &= found.next().is_none();
        kani::assert(
            held,
            "the directories above a path must be its prefixes before each slash",
        );
        kani::cover!(directories == 2);
    }

    /// A first claim records its folded path among the files and each of its prefixes before a `/` among the directories, and nothing else.
    /// A second claim is refused with the first entry exactly when the two folded paths collide, and then records nothing.
    /// A directory keeps the first entry that claimed it.
    ///
    /// Every pair of folded paths of one to three arbitrary bytes with no empty component, and fixed paths for the directory that two entries claim.
    #[kani::proof]
    #[kani::unwind(4)]
    fn claiming_records_each_entry_and_names_the_earlier_one() {
        let first_bytes: [u8; 3] = kani::any();
        let first = short_entry(&first_bytes);
        let second_bytes: [u8; 3] = kani::any();
        let second = short_entry(&second_bytes);
        let mut paths = FewClaims::default();
        let mut held = claim_path(&mut paths, first, 1).is_ok()
            && paths.files.count() == 1
            && paths.files.get(first) == Some(&1);
        let mut directories = 0;
        for end in 0..first.len() {
            if first[end] == b'/' {
                held &= paths.directories.get(&first[..end]) == Some(&1);
                directories += 1;
            }
        }
        held &= paths.directories.count() == directories;
        let collides = same(first, second) || inside(first, second) || inside(second, first);
        let refused = claim_path(&mut paths, second, 2).map_err(|collision| *collision.earlier());
        held &= match refused {
            Err(earlier) => {
                collides
                    && earlier == 1
                    && paths.files.count() == 1
                    && paths.directories.count() == directories
            }
            Ok(()) => !collides,
        };
        let mut shared = FewClaims::default();
        held &= claim_path(&mut shared, b"a/b", 1).is_ok()
            && claim_path(&mut shared, b"a/c", 2).is_ok()
            && claim_path(&mut shared, b"a", 3).is_err_and(|collision| *collision.earlier() == 1)
            && claim_path(&mut shared, b"a/c", 4).is_err_and(|collision| *collision.earlier() == 2);
        kani::assert(
            held,
            "claiming must record each entry and name the earlier one",
        );
        kani::cover!(refused.is_err() && directories == 1);
    }

    /// A folded path of one to three of `bytes`, as `archive_path` accepts it: no component is empty.
    fn short_entry(bytes: &[u8; 3]) -> &[u8] {
        let length: usize = kani::any_where(|length| (1..=3).contains(length));
        for index in 0..length {
            if bytes[index] == b'/' {
                kani::assume(index > 0 && index + 1 < length && bytes[index - 1] != b'/');
            }
        }
        &bytes[..length]
    }

    /// The claims of two folded paths of up to three bytes with no empty component, in arrays, because maps exhaust the solver.
    #[derive(Default)]
    struct FewClaims {
        files: Records<2>,
        directories: Records<2>,
    }

    impl ClaimedPaths for FewClaims {
        type Entry = u8;

        fn file(&self, folded: &[u8]) -> Option<&u8> {
            self.files.get(folded)
        }

        fn directory(&self, folded: &[u8]) -> Option<&u8> {
            self.directories.get(folded)
        }

        fn record_file(&mut self, folded: &[u8], entry: u8) {
            self.files.record(folded, entry);
        }

        fn record_directory(&mut self, folded: &[u8], entry: u8) {
            self.directories.record(folded, entry);
        }
    }

    /// Up to `N` keys of up to three bytes, each with an entry, which a later entry of the same key replaces, as in a map.
    struct Records<const N: usize> {
        slots: [Option<(u32, u8)>; N],
    }

    impl<const N: usize> Default for Records<N> {
        fn default() -> Self {
            Records { slots: [None; N] }
        }
    }

    impl<const N: usize> Records<N> {
        /// The entry kept under `key`.
        fn get(&self, key: &[u8]) -> Option<&u8> {
            let key = code(key);
            self.slots.iter().find_map(|slot| match slot {
                Some((code, entry)) if *code == key => Some(entry),
                _ => None,
            })
        }

        /// Keep `entry` under `key`, in place of an earlier entry of the same key.
        fn record(&mut self, key: &[u8], entry: u8) {
            let key = code(key);
            let kept = match self
                .slots
                .iter()
                .position(|slot| matches!(slot, Some((code, _)) if *code == key))
            {
                Some(index) => Some(index),
                None => self.slots.iter().position(Option::is_none),
            };
            kani::assert(kept.is_some(), "the records of a claim must fit");
            if let Some(index) = kept {
                self.slots[index] = Some((key, entry));
            }
        }

        /// How many keys the records keep.
        fn count(&self) -> usize {
            self.slots.iter().filter(|slot| slot.is_some()).count()
        }
    }

    /// A key of up to three bytes as one number: its length, then its bytes, a byte apiece.
    fn code(key: &[u8]) -> u32 {
        let mut code = key.len() as u32;
        for byte in key {
            code = code << 8 | u32::from(*byte);
        }
        code
    }

    /// What claiming a second folded path after a first one found.
    #[derive(Clone, Copy)]
    struct Claim {
        refused: bool,
        collides: bool,
    }

    /// A second entry is refused exactly when its folded path collides with the first one's.
    ///
    /// Every pair of folded paths of one to four arbitrary bytes with no empty component, which nests a path one directory deep.
    /// The claimed paths are taken to hold what `claim_path` records for the first entry: its folded path among the files, and each of its prefixes before a `/` among the directories.
    /// The claim harness above proves that record for every folded path of up to three bytes.
    #[kani::proof]
    #[kani::unwind(17)]
    fn two_accepted_entries_never_collide_once_case_no_longer_counts() {
        let claims = [
            claim::<1, 1>(),
            claim::<1, 2>(),
            claim::<1, 3>(),
            claim::<1, 4>(),
            claim::<2, 1>(),
            claim::<2, 2>(),
            claim::<2, 3>(),
            claim::<2, 4>(),
            claim::<3, 1>(),
            claim::<3, 2>(),
            claim::<3, 3>(),
            claim::<3, 4>(),
            claim::<4, 1>(),
            claim::<4, 2>(),
            claim::<4, 3>(),
            claim::<4, 4>(),
        ];
        let mut separate = true;
        let mut sound = true;
        for index in 0..claims.len() {
            separate &= claims[index].refused || !claims[index].collides;
            sound &= !claims[index].refused || claims[index].collides;
        }
        kani::assert(
            separate,
            "two accepted entries must not collide once letter case no longer counts",
        );
        kani::assert(sound, "a refused entry must collide with an earlier one");
        kani::cover!(claims[2].refused);
        kani::cover!(claims[8].refused);
    }

    /// The same as the harness above for every pair in which one folded path has five bytes, which nests a path two directories deep.
    ///
    /// Every pair of folded paths of one to five arbitrary bytes with no empty component, one of which has five bytes.
    #[kani::proof]
    #[kani::unwind(10)]
    fn entries_two_directories_deep_never_collide_once_case_no_longer_counts() {
        let claims = [
            claim::<1, 5>(),
            claim::<2, 5>(),
            claim::<3, 5>(),
            claim::<4, 5>(),
            claim::<5, 5>(),
            claim::<5, 1>(),
            claim::<5, 2>(),
            claim::<5, 3>(),
            claim::<5, 4>(),
        ];
        let mut separate = true;
        let mut sound = true;
        for index in 0..claims.len() {
            separate &= claims[index].refused || !claims[index].collides;
            sound &= !claims[index].refused || claims[index].collides;
        }
        kani::assert(
            separate,
            "two accepted entries must not collide once letter case no longer counts",
        );
        kani::assert(sound, "a refused entry must collide with an earlier one");
        kani::cover!(claims[2].refused);
        kani::cover!(claims[7].refused);
    }

    /// Claim a folded path of `M` arbitrary bytes after one of `N`.
    fn claim<const N: usize, const M: usize>() -> Claim {
        let first = folded_entry::<N>();
        let second = folded_entry::<M>();
        let earlier = ();
        let refused = collision(
            &second,
            |key| same(key, &first).then_some(&earlier),
            |key| {
                let mut recorded = false;
                for end in 0..N {
                    recorded |= first[end] == b'/' && same(key, &first[..end]);
                }
                recorded.then_some(&earlier)
            },
        )
        .is_some();
        Claim {
            refused,
            collides: same(&first, &second) || inside(&first, &second) || inside(&second, &first),
        }
    }

    /// Whether two byte strings are equal, compared one byte at a time.
    fn same(left: &[u8], right: &[u8]) -> bool {
        if left.len() != right.len() {
            return false;
        }
        let mut same = true;
        for index in 0..left.len() {
            same &= left[index] == right[index];
        }
        same
    }

    /// A folded path of `N` arbitrary bytes, as `archive_path` accepts it: no component is empty.
    fn folded_entry<const N: usize>() -> [u8; N] {
        let entry: [u8; N] = kani::any();
        for index in 0..N {
            if entry[index] == b'/' {
                kani::assume(index > 0 && index + 1 < N && entry[index - 1] != b'/');
            }
        }
        entry
    }

    /// Whether `inner` lies inside the directory `outer`.
    fn inside(outer: &[u8], inner: &[u8]) -> bool {
        inner.len() > outer.len()
            && same(&inner[..outer.len()], outer)
            && inner[outer.len()] == b'/'
    }
}
