//! Filtering support for generating TNIDs without blocklisted words.
//!
//! This module provides functionality to generate TNIDs that don't contain
//! specified substrings (e.g., profanity) in their string representation.
//!
//! # Example
//!
//! ```rust
//! use tnid::{Tnid, TnidName, NameStr};
//! use tnid::filter::Blocklist;
//!
//! struct User;
//! impl TnidName for User {
//!     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
//! }
//!
//! let blocklist = Blocklist::new(&["TACO", "FOO"]);
//! let id = Tnid::<User>::new_v0_filtered(&blocklist).unwrap();
//! // The data portion of id.to_tnid_string() won't contain "TACO" or "FOO"
//! ```

use aho_corasick::AhoCorasick;
use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum iterations before giving up on finding a clean ID.
///
/// With a reasonable blocklist, hitting this limit is extremely unlikely.
/// If reached, the blocklist may be too restrictive.
pub const MAX_V0_ITERATIONS: u32 = 1000;

/// Maximum iterations for V1 filtering.
pub const MAX_V1_ITERATIONS: u32 = 100;

/// Maximum iterations when filtering for both V0 and encrypted V1.
pub const MAX_ENCRYPTION_ITERATIONS: u32 = 10000;

/// Error returned when filtered ID generation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FilterError {
    /// Maximum iterations reached without finding a clean ID.
    ///
    /// This typically means the blocklist is too restrictive or contains
    /// patterns that match too frequently.
    MaxIterationsExceeded {
        /// Number of iterations attempted
        iterations: u32,
    },

    /// Encryption error when using filtered encryption functions.
    #[cfg(feature = "encryption")]
    EncryptionError(crate::encryption::EncryptionError),
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MaxIterationsExceeded { iterations } => {
                write!(
                    f,
                    "failed to generate clean ID after {iterations} iterations; \
                     blocklist may be too restrictive"
                )
            }
            #[cfg(feature = "encryption")]
            Self::EncryptionError(e) => write!(f, "encryption error: {e}"),
        }
    }
}

impl std::error::Error for FilterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "encryption")]
            Self::EncryptionError(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(feature = "encryption")]
impl From<crate::encryption::EncryptionError> for FilterError {
    fn from(e: crate::encryption::EncryptionError) -> Self {
        Self::EncryptionError(e)
    }
}

/// A compiled blocklist for efficient substring matching.
///
/// The blocklist performs case-insensitive matching against the TNID data
/// alphabet (`-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz`).
///
/// # Example
///
/// ```rust
/// use tnid::filter::Blocklist;
///
/// let blocklist = Blocklist::new(&["TACO", "FOO", "BAZZ"]);
///
/// assert!(blocklist.contains_match("xyzTACOxyz"));
/// assert!(blocklist.contains_match("xyztacoxyz")); // case-insensitive
/// assert!(!blocklist.contains_match("xyzHELLOxyz"));
/// ```
pub struct Blocklist {
    automaton: AhoCorasick,
    /// Tracks the last known safe timestamp to avoid re-discovering bad windows.
    ///
    /// When a bad word appears in the timestamp portion, we have to bump the timestamp
    /// until we escape that window. This field ensures subsequent calls don't have to
    /// rediscover the same bad window — they start from the last known safe timestamp.
    last_safe_timestamp: AtomicU64,
}

impl Blocklist {
    /// Creates a new blocklist from the given patterns.
    ///
    /// Patterns are matched case-insensitively. Empty patterns are ignored.
    ///
    /// # Panics
    ///
    /// Panics if the patterns cannot be compiled (e.g., invalid UTF-8).
    /// This should not happen with normal string slices.
    pub fn new<S: AsRef<str>>(patterns: &[S]) -> Self {
        let non_empty: Vec<&str> = patterns
            .iter()
            .map(|p| p.as_ref())
            .filter(|p| !p.is_empty())
            .collect();

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&non_empty)
            .expect("failed to build Aho-Corasick automaton");

        Self {
            automaton,
            last_safe_timestamp: AtomicU64::new(0),
        }
    }

    /// Returns `true` if the text contains any blocklisted word.
    ///
    /// Matching is case-insensitive.
    pub fn contains_match(&self, text: &str) -> bool {
        self.automaton.is_match(text)
    }

    /// Returns the starting timestamp for filtered V0 generation.
    ///
    /// This is the maximum of the current time and the last known safe timestamp,
    /// ensuring we don't waste iterations rediscovering bad timestamp windows.
    pub(crate) fn get_starting_timestamp(&self) -> u64 {
        let current = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as u64;
        let last_safe = self.last_safe_timestamp.load(Ordering::Relaxed);
        current.max(last_safe)
    }

    /// Records a safe timestamp after successfully generating a filtered ID.
    ///
    /// This allows future calls to skip past known-bad timestamp windows.
    pub(crate) fn record_safe_timestamp(&self, timestamp: u64) {
        self.last_safe_timestamp.fetch_max(timestamp, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for Blocklist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blocklist")
            .field("pattern_count", &self.automaton.patterns_len())
            .finish()
    }
}

/// The index of the first character in the data string that contains
/// any random bits.
///
/// For V0 TNIDs:
/// - Characters 0-6: pure timestamp bits
/// - Character 7: 1 timestamp bit + 2 variant bits + 3 random bits
/// - Characters 8-16: pure random bits
///
/// If a bad word touches char 7 or later, regenerating random bits may help.
/// If a bad word is entirely in chars 0-6, we must bump the timestamp.
pub const FIRST_CHAR_WITH_RANDOM: usize = 7;

/// Checks if a match touches any character that contains random bits.
///
/// Returns `true` if regenerating random bits might fix the match.
/// Returns `false` if the match is entirely in the timestamp portion and
/// requires bumping the timestamp.
pub fn match_touches_random_portion(match_start: usize, match_len: usize) -> bool {
    match_start + match_len > FIRST_CHAR_WITH_RANDOM
}

/// Calculates the minimum timestamp bump (in ms) needed to change a character.
///
/// Each character encodes 6 bits. Characters closer to 0 encode more significant
/// timestamp bits and require larger bumps:
/// - Char 6: 64ms
/// - Char 5: ~4 seconds
/// - Char 4: ~4 minutes
/// - Char 3: ~4.7 hours
/// - Char 2: ~12 days
/// - Char 1: ~2 years
/// - Char 0: ~139 years
///
/// The formula is 2^(42 - 6*char_pos) milliseconds.
pub fn timestamp_bump_for_char(char_pos: usize) -> u64 {
    debug_assert!(char_pos <= 6, "char_pos must be in timestamp portion (0-6)");
    1u64 << (42 - 6 * char_pos)
}

/// Finds the first blocklist match in the text and returns its position and length.
pub fn find_first_match(blocklist: &Blocklist, text: &str) -> Option<(usize, usize)> {
    blocklist
        .automaton
        .find(text)
        .map(|m| (m.start(), m.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocklist_matches_case_insensitive() {
        let blocklist = Blocklist::new(&["TACO", "FOO"]);

        assert!(blocklist.contains_match("TACO"));
        assert!(blocklist.contains_match("taco"));
        assert!(blocklist.contains_match("Taco"));
        assert!(blocklist.contains_match("xyzTACOxyz"));
        assert!(blocklist.contains_match("xyztacoxyz"));
        assert!(blocklist.contains_match("FOO"));
        assert!(blocklist.contains_match("foo"));

        assert!(!blocklist.contains_match("hello"));
        assert!(!blocklist.contains_match(""));
    }

    #[test]
    fn blocklist_empty() {
        let blocklist = Blocklist::new::<&str>(&[]);
        assert!(!blocklist.contains_match("anything"));
    }

    #[test]
    fn blocklist_ignores_empty_patterns() {
        let blocklist = Blocklist::new(&["", "TACO", ""]);
        assert!(blocklist.contains_match("TACO"));
        assert!(!blocklist.contains_match("FOO"));
    }

    #[test]
    fn find_first_match_returns_position() {
        let blocklist = Blocklist::new(&["TACO"]);

        let result = find_first_match(&blocklist, "xyzTACOxyz");
        assert_eq!(result, Some((3, 4)));

        let result = find_first_match(&blocklist, "hello");
        assert_eq!(result, None);
    }

    #[test]
    fn match_position_classification() {
        // Match entirely in pure timestamp portion (chars 0-6) - must bump timestamp
        assert!(!match_touches_random_portion(0, 3)); // chars 0-2
        assert!(!match_touches_random_portion(4, 3)); // chars 4-6
        assert!(!match_touches_random_portion(0, 7)); // chars 0-6, ends exactly at boundary

        // Match touching char 7+ (has random bits) - can try regenerating random
        assert!(match_touches_random_portion(5, 3)); // chars 5-7, touches char 7
        assert!(match_touches_random_portion(7, 3)); // chars 7-9
        assert!(match_touches_random_portion(8, 3)); // chars 8-10, pure random
        assert!(match_touches_random_portion(14, 3)); // chars 14-16
    }

    #[test]
    fn timestamp_bump_values() {
        // Char 6: 2^(42-36) = 2^6 = 64ms
        assert_eq!(timestamp_bump_for_char(6), 64);

        // Char 5: 2^(42-30) = 2^12 = 4096ms (~4 seconds)
        assert_eq!(timestamp_bump_for_char(5), 4096);

        // Char 4: 2^(42-24) = 2^18 = 262144ms (~4.4 minutes)
        assert_eq!(timestamp_bump_for_char(4), 262144);

        // Char 3: 2^(42-18) = 2^24 (~4.7 hours)
        assert_eq!(timestamp_bump_for_char(3), 1 << 24);

        // Char 0: 2^42 (max, ~139 years)
        assert_eq!(timestamp_bump_for_char(0), 1 << 42);
    }
}
