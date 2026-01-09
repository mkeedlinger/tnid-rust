//! TNID name encoding and validation.
//!
//! TNIDs include a name field (20 bits, 1-4 characters) that allows different kinds of IDs
//! to be differentiated at runtime and compile time. This module handles the encoding of
//! names into the TNID bit representation and validation of name strings.
//!
//! # Name Requirements
//!
//! Valid TNID names must:
//! - Be 1-4 characters long
//! - Contain only ASCII characters
//! - Use only characters from the allowed character set: digits (0-4) and lowercase letters (a-z)
//!
//! # Name Encoding
//!
//! Names are encoded using a 5-bit character encoding scheme (see [`CHAR_MAPPING`]). The encoding
//! is designed so that the bit representation ordering matches ASCII character ordering, making
//! TNIDs sortable in their string representation.
//!
//! If a name is shorter than 4 characters, it is null-padded to fill the 20-bit name field.
//!
//! # Examples
//!
//! ```rust
//! use tnid::NameStr;
//!
//! // Valid names
//! let name1 = NameStr::new("user").unwrap();
//! let name2 = NameStr::new("post").unwrap();
//! let name3 = NameStr::new("a").unwrap();     // Single character is ok
//! let name4 = NameStr::new("test").unwrap();  // 4 characters (max)
//!
//! // Invalid names
//! assert!(NameStr::new("").is_err());           // Too short
//! assert!(NameStr::new("toolong").is_err());    // Too long (>4 chars)
//! assert!(NameStr::new("User").is_err());       // Uppercase not allowed
//! assert!(NameStr::new("a-b").is_err());        // Dash not allowed
//! assert!(NameStr::new("test9").is_err());      // Digit 9 not in allowed set
//! ```

#[allow(clippy::indexing_slicing)] // panic is expected error path
pub const fn name_valid_check(name: &str) {
    if let NAME_MIN_CHARS..=NAME_MAX_CHARS = name.len() {
        if !name.is_ascii() {
            panic!("Id name must be ascii");
        }
    } else {
        panic!("Id name length must be within range")
    }

    let bytes = name.as_bytes();
    let mut i = 0;

    'check_loop: while i < bytes.len() {
        let mut j = 0;
        while j < CHAR_MAPPING.len() {
            if CHAR_MAPPING[j].1 == bytes[i] {
                i += 1;
                continue 'check_loop;
            }
            j += 1;
        }

        panic!("Invalid char in name");
    }
}

pub const NAME_MIN_CHARS: usize = 1;
pub const NAME_MAX_CHARS: usize = 4;

/// Result of validating the name bits in a TNID.
///
/// Used by [`validate_name_bits`] to indicate whether the name encoding
/// in a u128 ID is valid according to TNID rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameBitsValidation {
    /// The name encoding is valid (1-4 characters, properly null-padded).
    Valid,
    /// The name encoding is invalid (empty, improperly padded, or invalid encoding).
    Invalid,
}

pub const CHAR_BIT_LENGTH: u8 = 5;
pub const CHAR_MASK: u8 = 0x1F;
pub const NON_NAME_BITS: u8 = u128::BITS as u8 - (CHAR_BIT_LENGTH * NAME_MAX_CHARS as u8);

pub const CHAR_MAPPING: [(u8, u8); 31] = [
    // zero is a null terminator

    // nums
    (1, b'0'),
    (2, b'1'),
    (3, b'2'),
    (4, b'3'),
    (5, b'4'),
    // alpha
    (6, b'a'),
    (7, b'b'),
    (8, b'c'),
    (9, b'd'),
    (10, b'e'),
    (11, b'f'),
    (12, b'g'),
    (13, b'h'),
    (14, b'i'),
    (15, b'j'),
    (16, b'k'),
    (17, b'l'),
    (18, b'm'),
    (19, b'n'),
    (20, b'o'),
    (21, b'p'),
    (22, b'q'),
    (23, b'r'),
    (24, b's'),
    (25, b't'),
    (26, b'u'),
    (27, b'v'),
    (28, b'w'),
    (29, b'x'),
    (30, b'y'),
    (31, b'z'),
];

/// Error when creating a [`NameStr`] from a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// The name string is empty (must be at least 1 character).
    Empty,
    /// The name string exceeds the maximum length of 4 characters.
    /// Contains the actual length provided.
    TooLong(usize),
    /// The name contains non-ASCII characters.
    NonAscii,
    /// The name contains a character not in the allowed set (0-4, a-z).
    /// Contains the invalid byte value.
    InvalidChar(u8),
}

impl std::fmt::Display for NameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "name cannot be empty"),
            Self::TooLong(len) => {
                write!(f, "name length {len} exceeds maximum of 4 characters")
            }
            Self::NonAscii => write!(f, "name must contain only ASCII characters"),
            Self::InvalidChar(byte) => {
                write!(
                    f,
                    "invalid character '{}' (0x{byte:02x}) in name; only 0-4 and a-z are allowed",
                    char::from(*byte)
                )
            }
        }
    }
}

impl std::error::Error for NameError {}

/// A validated TNID name string.
///
/// This type wraps a string slice and ensures it meets all TNID name requirements:
/// - Length between 1-4 characters (inclusive)
/// - ASCII only
/// - Only characters from the allowed set: digits 0-4 and lowercase letters a-z
///
/// # Examples
///
/// ```rust
/// use tnid::NameStr;
///
/// // Runtime validation with new()
/// let name = NameStr::new("user").unwrap();
/// assert_eq!(name.as_str(), "user");
///
/// // Invalid names return Err
/// assert!(NameStr::new("").is_err());
/// assert!(NameStr::new("CAPS").is_err());
/// ```
pub struct NameStr<'a>(&'a str);
impl<'a> NameStr<'a> {
    /// Creates a new `NameStr` with compile-time validation when used in a const context.
    ///
    /// This method performs validation and will panic if the name is invalid. When used
    /// in a const context (like defining a [`TnidName`](crate::TnidName) implementation),
    /// the panic will occur at compile time. If used at runtime, it will panic the program.
    ///
    /// **Prefer using [`new()`](Self::new) for runtime validation** which returns an `Option`
    /// instead of panicking.
    ///
    /// # Panics
    ///
    /// Panics if the name:
    /// - Is not 1-4 characters long
    /// - Contains non-ASCII characters
    /// - Contains characters outside the allowed set (0-4, a-z)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{NameStr, TnidName};
    ///
    /// // Used in a const context for TNIDName (validated at compile time)
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    /// ```
    ///
    /// This will fail to compile:
    /// ```compile_fail
    /// use tnid::{NameStr, TNIDName, TNID};
    ///
    /// struct Invalid;
    /// impl TnidName for Invalid {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("INVALID");
    /// }
    ///
    /// // This actually uses the const and triggers the compile-time check
    /// let _ = Invalid::ID_NAME;
    /// ```
    pub const fn new_const(s: &'static str) -> Self {
        name_valid_check(s);
        Self(s)
    }

    /// Creates a new `NameStr` with runtime validation.
    ///
    /// Returns `Ok(NameStr)` if the string is a valid TNID name, or `Err(NameError)` if it's invalid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::NameStr;
    ///
    /// // Valid names (1-4 chars, digits 0-4 and lowercase a-z only)
    /// assert!(NameStr::new("user").is_ok());
    /// assert!(NameStr::new("post").is_ok());
    /// assert!(NameStr::new("a").is_ok());
    /// assert!(NameStr::new("test").is_ok());
    /// assert!(NameStr::new("id0").is_ok());
    ///
    /// // Too short or too long
    /// assert!(NameStr::new("").is_err());
    /// assert!(NameStr::new("toolong").is_err());
    ///
    /// // Invalid characters
    /// assert!(NameStr::new("User").is_err());    // uppercase not allowed
    /// assert!(NameStr::new("id5").is_err());     // digits 5-9 not allowed
    /// assert!(NameStr::new("a-b").is_err());     // special chars not allowed
    /// assert!(NameStr::new("café").is_err());    // non-ASCII not allowed
    /// ```
    pub fn new(s: &'a str) -> Result<Self, NameError> {
        if s.is_empty() {
            return Err(NameError::Empty);
        }

        if s.len() > NAME_MAX_CHARS {
            return Err(NameError::TooLong(s.len()));
        }

        if !s.is_ascii() {
            return Err(NameError::NonAscii);
        }

        // Check all characters are in CHAR_MAPPING
        let bytes = s.as_bytes();
        for &byte in bytes {
            let mut found = false;
            for &(_, valid_char) in &CHAR_MAPPING {
                if valid_char == byte {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(NameError::InvalidChar(byte));
            }
        }

        Ok(Self(s))
    }

    /// Returns the validated name as a string slice.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::NameStr;
    ///
    /// let name = NameStr::new("user").unwrap();
    /// assert_eq!(name.as_str(), "user");
    /// ```
    pub fn as_str(&self) -> &str {
        self.0
    }
}

pub fn name_mask(name: NameStr) -> u128 {
    let name = name.as_str();
    let name_bytes = name.as_bytes();

    let mut mask = 0u128;

    for &name_char in name_bytes {
        let encoding_mapping = CHAR_MAPPING
            .iter()
            .find(|(_encoded, from_char)| *from_char == name_char);

        let (encoded_byte, _) = encoding_mapping.expect("mapping must exist");

        debug_assert!(*encoded_byte < 32);

        mask <<= CHAR_BIT_LENGTH;
        mask |= *encoded_byte as u128;
    }

    let needed_padding_chars = NAME_MAX_CHARS - name.len();
    mask <<= CHAR_BIT_LENGTH * needed_padding_chars as u8;

    mask <<= NON_NAME_BITS;

    mask
}

pub fn validate_name_bits(id: u128) -> NameBitsValidation {
    // Extract the top 20 bits (bits 127-108)
    let name_bits = (id >> NON_NAME_BITS) as u32;

    let mut found_char = false;
    let mut found_null = false;

    // Extract 4 characters of 5 bits each
    for i in (0..NAME_MAX_CHARS).rev() {
        let shift = i * CHAR_BIT_LENGTH as usize;
        let encoded_byte = (name_bits >> shift) as u8 & CHAR_MASK;

        // 0 is null terminator
        if encoded_byte == 0 {
            found_null = true;
            continue;
        }

        // If we found a non-null after a null, that's invalid (no padding in middle)
        if found_null {
            return NameBitsValidation::Invalid;
        }

        found_char = true;
    }

    // Must have at least 1 character
    if found_char {
        NameBitsValidation::Valid
    } else {
        NameBitsValidation::Invalid
    }
}

pub fn name_bits_to_hex(id: u128) -> String {
    let name_bits = (id >> NON_NAME_BITS) as u32;
    let hex = format!("{:05x}", name_bits);

    debug_assert_eq!(hex.len(), 5);

    hex
}

pub fn extract_name_string(id: u128) -> Option<String> {
    let name_bits = (id >> NON_NAME_BITS) as u32;

    let expected_string_len = name_bits.trailing_zeros() / 5;

    let mut name_bytes = Vec::with_capacity(expected_string_len as usize);

    // Extract 4 characters of 5 bits each
    for i in (0..NAME_MAX_CHARS).rev() {
        let shift = i * CHAR_BIT_LENGTH as usize;
        let encoded_byte = ((name_bits >> shift) as u8 & CHAR_MASK) as u8;

        // 0 is null terminator - stop decoding
        if encoded_byte == 0 {
            break;
        }

        // Find the corresponding character in CHAR_MAPPING
        let decoded_char = CHAR_MAPPING
            .iter()
            .find(|(encoded, _)| *encoded == encoded_byte)
            .map(|(_, ascii_char)| *ascii_char)
            .expect("there must be a mapping"); // todo: make an exhaustive test for this

        name_bytes.push(decoded_char);
    }

    if name_bytes.is_empty() {
        return None;
    }

    Some(String::from_utf8(name_bytes).expect("name bytes must be valid ASCII"))
}

#[cfg(all(test, not(debug_assertions)))]
mod tests_release {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 100_000, .. ProptestConfig::default()
        })]
        #[test]
        fn name_mask_no_panic(name: String) {
            let Ok(name) = NameStr::new(name.as_str()) else {
                return Ok(());
            };

            name_mask(name);
        }
    }
}
