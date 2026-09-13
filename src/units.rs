//! Byte-size units.
//!
//! Limits are written as a count of these rather than as a product of 1024s,
//! so a misplaced factor is visible at the point of definition.

/// Bytes in one kibibyte.
pub(crate) const KIB: u64 = 1024;

/// Bytes in one mebibyte.
pub(crate) const MIB: u64 = 1024 * KIB;

/// Bytes in one gibibyte.
pub(crate) const GIB: u64 = 1024 * MIB;
