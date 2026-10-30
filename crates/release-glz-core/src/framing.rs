//! The bytes that release-glz feeds to SHA-256 for the digests it defines itself.
//!
//! Each framing is injective, so two different inputs never give the hash the same bytes.
//! The hash itself is outside the proofs, and its collision resistance is an assumption.

/// The domain tag that starts the files digest of a Release PR commit.
pub const FILES_DOMAIN: &[u8] = b"release-glz release-pr-files\0";

/// The domain tag that starts the idempotency key of a notification.
pub const NOTIFICATION_DOMAIN: &[u8] = b"release-glz-notify-v1\0";

/// Feed `sink` the framing of one file of a Release PR commit, in the order the hash consumes it.
///
/// The length of the path as eight big-endian bytes comes first, then the path, the length of the contents, and the contents.
/// The files digest hashes [`FILES_DOMAIN`] and then every file in path order.
pub fn frame_file(path: &[u8], contents: &[u8], mut sink: impl FnMut(&[u8])) {
    #[cfg(feature = "negative-control-unframed-files")]
    if let Some(()) = negative_control_unframed_files(path, contents, &mut sink) {
        return;
    }
    for part in [path, contents] {
        sink(&(part.len() as u64).to_be_bytes());
        sink(part);
    }
}

/// Frames each file without the lengths of its path and contents.
#[cfg(feature = "negative-control-unframed-files")]
fn negative_control_unframed_files(
    path: &[u8],
    contents: &[u8],
    sink: &mut impl FnMut(&[u8]),
) -> Option<()> {
    sink(path);
    sink(contents);
    Some(())
}

/// The parts that the idempotency key of one notification hashes, in order.
///
/// A NUL byte ends the Candidate digest, so the framing is injective for every digest without one, which a lowercase hexadecimal digest never has.
pub fn notification_frame<'a>(candidate_digest: &'a [u8], hook_id: &'a [u8]) -> [&'a [u8]; 4] {
    #[cfg(feature = "negative-control-unframed-notification")]
    if let Some(frame) = negative_control_unframed_notification(candidate_digest, hook_id) {
        return frame;
    }
    [NOTIFICATION_DOMAIN, candidate_digest, b"\0", hook_id]
}

/// Frames a notification without the byte that ends its Candidate digest.
#[cfg(feature = "negative-control-unframed-notification")]
fn negative_control_unframed_notification<'a>(
    candidate_digest: &'a [u8],
    hook_id: &'a [u8],
) -> Option<[&'a [u8]; 4]> {
    Some([NOTIFICATION_DOMAIN, candidate_digest, b"", hook_id])
}

#[cfg(kani)]
mod proofs {
    use super::{NOTIFICATION_DOMAIN, frame_file, notification_frame};

    /// The longest part that a framing hands its sink at once, the eight bytes of a length.
    const PART: usize = 8;

    /// Bytes written in order into a buffer of `N`, with zeros after the last one.
    ///
    /// Every loop runs a fixed number of times, so the verifier never unrolls a loop past the bytes it can hold.
    struct Written<const N: usize> {
        bytes: [u8; N],
        length: usize,
    }

    impl<const N: usize> Written<N> {
        fn new() -> Self {
            Self {
                bytes: [0; N],
                length: 0,
            }
        }

        fn push(&mut self, part: &[u8]) {
            assert!(part.len() <= PART);
            for index in 0..PART {
                if index < part.len() {
                    self.bytes[self.length] = part[index];
                    self.length += 1;
                }
            }
        }

        /// Whether two writers hold the same bytes, which the zeros after each length make a comparison of whole buffers.
        fn same(&self, other: &Self) -> bool {
            self.length == other.length
                && (0..N).all(|index| self.bytes[index] == other.bytes[index])
        }
    }

    /// A symbolic byte string of at most `N` bytes.
    struct Bytes<const N: usize> {
        buffer: [u8; N],
        length: usize,
    }

    impl<const N: usize> Bytes<N> {
        fn any() -> Self {
            let bytes = Self {
                buffer: kani::any(),
                length: kani::any(),
            };
            kani::assume(bytes.length <= N);
            bytes
        }

        fn get(&self) -> &[u8] {
            &self.buffer[..self.length]
        }

        /// Whether both strings hold the same bytes, compared in a loop of fixed length.
        fn equals(&self, other: &Self) -> bool {
            self.length == other.length
                && (0..N)
                    .all(|index| index >= self.length || self.buffer[index] == other.buffer[index])
        }

        /// Whether the string holds `byte`, checked in a loop of fixed length.
        fn holds(&self, byte: u8) -> bool {
            (0..N).any(|index| index < self.length && self.buffer[index] == byte)
        }
    }

    /// The framing of one file followed by `rest`, the bytes of whatever the digest hashes after it.
    fn framed_file(path: &Bytes<2>, contents: &Bytes<2>, rest: &Bytes<2>) -> Written<22> {
        let mut written = Written::new();
        frame_file(path.get(), contents.get(), |part| written.push(part));
        written.push(rest.get());
        written
    }

    /// The framing of a file is never a prefix of the framing of another file, so the bytes split back into the same files.
    ///
    /// The digest hashes the domain tag and then the framings of all files in order, so this step carries injectivity from one file to a list of any length, which the Lean model proves.
    /// The proof covers paths, contents, and following bytes of at most two bytes of any value.
    #[kani::proof]
    #[kani::unwind(23)]
    fn the_files_framing_is_injective() {
        let (paths, contents, rests) = (
            [Bytes::<2>::any(), Bytes::<2>::any()],
            [Bytes::<2>::any(), Bytes::<2>::any()],
            [Bytes::<2>::any(), Bytes::<2>::any()],
        );
        let same = framed_file(&paths[0], &contents[0], &rests[0]).same(&framed_file(
            &paths[1],
            &contents[1],
            &rests[1],
        ));
        if same {
            kani::assert(
                paths[0].equals(&paths[1])
                    && contents[0].equals(&contents[1])
                    && rests[0].equals(&rests[1]),
                "the files framing must be injective",
            );
        }
        kani::cover!(same && paths[0].length > 0 && rests[0].length > 0);
    }

    /// The bytes the idempotency key hashes after its domain tag for one notification.
    fn notification_bytes(candidate_digest: &Bytes<3>, hook_id: &Bytes<3>) -> Written<8> {
        let parts = notification_frame(candidate_digest.get(), hook_id.get());
        assert!(parts[0] == NOTIFICATION_DOMAIN);
        let mut written = Written::new();
        for part in &parts[1..] {
            written.push(part);
        }
        written
    }

    /// Two notifications that the idempotency key frames into the same bytes have the same Candidate digest and hook.
    ///
    /// Every key starts with the same domain tag, so the proof compares the bytes after it.
    /// The proof covers digests and hook ids of at most three bytes of any value, with no NUL in a digest.
    #[kani::proof]
    #[kani::unwind(23)]
    fn the_notification_framing_is_injective() {
        let digests = [Bytes::<3>::any(), Bytes::<3>::any()];
        let hooks = [Bytes::<3>::any(), Bytes::<3>::any()];
        kani::assume(!digests[0].holds(0) && !digests[1].holds(0));
        let same = notification_bytes(&digests[0], &hooks[0])
            .same(&notification_bytes(&digests[1], &hooks[1]));
        if same {
            kani::assert(
                digests[0].equals(&digests[1]) && hooks[0].equals(&hooks[1]),
                "the notification framing must be injective",
            );
        }
        kani::cover!(same && hooks[0].holds(0));
    }
}
