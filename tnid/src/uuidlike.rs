/// A wrapper for 128-bit values that may or may not be valid TNIDs.
///
/// This type provides a way to work with 128-bit UUID-like values without the strict
/// validation that [`Tnid`](crate::Tnid) requires. Unlike [`Tnid`](crate::Tnid), which
/// only accepts values that conform to the TNID specification (correct UUIDv8 version/variant
/// bits and valid name encoding), `UUIDLike` accepts any 128-bit value.
///
/// This makes `UUIDLike` useful for:
/// - Inspecting potentially invalid TNIDs to understand why they don't parse
/// - Converting between different UUID representations (u128, hex strings) without validation
/// - Working with UUIDs from external systems that may not be TNIDs
/// - Debugging and troubleshooting TNID-related issues
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// use tnid::UUIDLike;
///
/// // Create from any 128-bit value
/// let uuid_like = UUIDLike::new(0x12345678_1234_1234_1234_123456789abc);
///
/// // Convert to different representations
/// let as_u128 = uuid_like.as_u128();
/// let as_string = uuid_like.to_uuid_string(false);
/// ```
///
/// Inspecting potentially invalid TNIDs:
/// ```rust
/// use tnid::{UUIDLike, Tnid, TnidName, NameStr};
///
/// struct User;
/// impl TnidName for User {
///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
/// }
///
/// // Parse a UUID string that might not be a valid TNID
/// let uuid_str = "cab1952a-f09d-86d9-928e-96ea03dc6af3";
/// let uuid_like = UUIDLike::parse_uuid_string(uuid_str).unwrap();
///
/// // Try to convert to TNID - this performs validation
/// match Tnid::<User>::from_u128(uuid_like.as_u128()) {
///     Ok(tnid) => println!("Valid TNID: {}", tnid),
///     Err(e) => println!("Not a valid TNID: {}", e),
/// }
/// ```

/// Error when parsing a UUID string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseUuidStringError {
    /// The string is not 36 characters long.
    /// Contains the actual length.
    WrongLength(usize),
    /// A hyphen is missing at the expected position.
    /// Contains the position (8, 13, 18, or 23).
    MissingHyphen(usize),
    /// An invalid hexadecimal character was found.
    /// Contains the position and the invalid byte.
    InvalidHexChar { position: usize, byte: u8 },
}

impl std::fmt::Display for ParseUuidStringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLength(len) => {
                write!(f, "UUID string must be 36 characters, got {len}")
            }
            Self::MissingHyphen(pos) => {
                write!(f, "missing hyphen at position {pos}")
            }
            Self::InvalidHexChar { position, byte } => {
                write!(
                    f,
                    "invalid hex character '{}' (0x{byte:02x}) at position {position}",
                    char::from(*byte)
                )
            }
        }
    }
}

impl std::error::Error for ParseUuidStringError {}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UUIDLike(u128);

impl std::fmt::Debug for UUIDLike {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_uuid_string(false))
    }
}

impl UUIDLike {
    /// Returns the raw 128-bit value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::UUIDLike;
    ///
    /// let uuid_like = UUIDLike::new(0x12345678_1234_1234_1234_123456789abc);
    /// assert_eq!(uuid_like.as_u128(), 0x12345678_1234_1234_1234_123456789abc);
    /// ```
    pub fn as_u128(&self) -> u128 {
        self.0
    }

    /// Creates a new `UUIDLike` from a 128-bit value.
    ///
    /// Accepts any `u128` value without validation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::UUIDLike;
    ///
    /// let uuid_like = UUIDLike::new(0x12345678_1234_1234_1234_123456789abc);
    /// assert_eq!(uuid_like.as_u128(), 0x12345678_1234_1234_1234_123456789abc);
    /// ```
    pub fn new(id: u128) -> Self {
        Self(id)
    }

    /// Converts to UUID hex string format with specified case.
    ///
    /// Produces the standard UUID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
    ///
    /// # Parameters
    ///
    /// - `uppercase`: If `true`, uses uppercase hex digits (A-F). If `false`, uses lowercase (a-f).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::UUIDLike;
    ///
    /// let uuid_like = UUIDLike::new(0xCAB1952A_F09D_86D9_928E_96EA03DC6AF3);
    ///
    /// let lowercase = uuid_like.to_uuid_string(false);
    /// assert_eq!(lowercase, "cab1952a-f09d-86d9-928e-96ea03dc6af3");
    ///
    /// let uppercase = uuid_like.to_uuid_string(true);
    /// assert_eq!(uppercase, "CAB1952A-F09D-86D9-928E-96EA03DC6AF3");
    /// ```
    pub fn to_uuid_string(&self, uppercase: bool) -> String {
        crate::utils::u128_to_uuid_string(self.0, uppercase)
    }

    /// Parses a UUID hex string into a `UUIDLike`.
    ///
    /// Accepts the standard UUID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
    ///
    /// Accepts both uppercase and lowercase hex digits. Validates format but not TNID-specific requirements.
    ///
    /// Returns `Err` if the string is not a valid UUID hex string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::UUIDLike;
    ///
    /// // Parse lowercase
    /// let uuid = UUIDLike::parse_uuid_string("cab1952a-f09d-86d9-928e-96ea03dc6af3");
    /// assert!(uuid.is_ok());
    ///
    /// // Parse uppercase
    /// let uuid = UUIDLike::parse_uuid_string("CAB1952A-F09D-86D9-928E-96EA03DC6AF3");
    /// assert!(uuid.is_ok());
    ///
    /// // Parse mixed case
    /// let uuid = UUIDLike::parse_uuid_string("CaB1952a-F09D-86d9-928E-96ea03dc6af3");
    /// assert!(uuid.is_ok());
    ///
    /// // Invalid format
    /// assert!(UUIDLike::parse_uuid_string("not-a-uuid").is_err());
    /// ```
    pub fn parse_uuid_string(uuid_string: &str) -> Result<Self, ParseUuidStringError> {
        if uuid_string.len() != 36 {
            return Err(ParseUuidStringError::WrongLength(uuid_string.len()));
        }

        let bytes = uuid_string.as_bytes();

        // Check for hyphens at expected positions
        for &pos in &[8, 13, 18, 23] {
            if bytes.get(pos) != Some(&b'-') {
                return Err(ParseUuidStringError::MissingHyphen(pos));
            }
        }

        // the from_str_radix below should also check that chars are hex digits, so this is redundant, but included for easier debugging
        #[cfg(debug_assertions)]
        for (i, &byte) in bytes.iter().enumerate() {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                if byte != b'-' {
                    return Err(ParseUuidStringError::MissingHyphen(i));
                }
            } else if !byte.is_ascii_hexdigit() {
                return Err(ParseUuidStringError::InvalidHexChar {
                    position: i,
                    byte,
                });
            }
        }

        // parse 5 hyphen-separated sections as hex
        // If parsing fails, it means there's an invalid hex character somewhere
        // We need to find it since from_str_radix doesn't tell us which one
        let s1 = u32::from_str_radix(&uuid_string[0..8], 16).map_err(|_| {
            // Find the invalid character
            for (i, &byte) in bytes.get(0..8).unwrap_or(&[]).iter().enumerate() {
                if !byte.is_ascii_hexdigit() {
                    return ParseUuidStringError::InvalidHexChar { position: i, byte };
                }
            }
            // Shouldn't reach here, but if we do just use WrongLength as a fallback
            ParseUuidStringError::WrongLength(uuid_string.len())
        })?;
        let s2 = u16::from_str_radix(&uuid_string[9..13], 16).map_err(|_| {
            for (i, &byte) in bytes.get(9..13).unwrap_or(&[]).iter().enumerate() {
                if !byte.is_ascii_hexdigit() {
                    return ParseUuidStringError::InvalidHexChar { position: 9 + i, byte };
                }
            }
            ParseUuidStringError::WrongLength(uuid_string.len())
        })?;
        let s3 = u16::from_str_radix(&uuid_string[14..18], 16).map_err(|_| {
            for (i, &byte) in bytes.get(14..18).unwrap_or(&[]).iter().enumerate() {
                if !byte.is_ascii_hexdigit() {
                    return ParseUuidStringError::InvalidHexChar { position: 14 + i, byte };
                }
            }
            ParseUuidStringError::WrongLength(uuid_string.len())
        })?;
        let s4 = u16::from_str_radix(&uuid_string[19..23], 16).map_err(|_| {
            for (i, &byte) in bytes.get(19..23).unwrap_or(&[]).iter().enumerate() {
                if !byte.is_ascii_hexdigit() {
                    return ParseUuidStringError::InvalidHexChar { position: 19 + i, byte };
                }
            }
            ParseUuidStringError::WrongLength(uuid_string.len())
        })?;
        let s5 = u64::from_str_radix(&uuid_string[24..36], 16).map_err(|_| {
            for (i, &byte) in bytes.get(24..36).unwrap_or(&[]).iter().enumerate() {
                if !byte.is_ascii_hexdigit() {
                    return ParseUuidStringError::InvalidHexChar { position: 24 + i, byte };
                }
            }
            ParseUuidStringError::WrongLength(uuid_string.len())
        })?;

        // Combine sections into u128 (reverse of to_uuid_string)
        let id = ((s1 as u128) << 96)
            | ((s2 as u128) << 80)
            | ((s3 as u128) << 64)
            | ((s4 as u128) << 48)
            | (s5 as u128);

        Ok(Self(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lowercase() {
        let result = UUIDLike::parse_uuid_string("ffffffff-ffff-ffff-ffff-ffffffffffff");
        assert_eq!(result.unwrap().as_u128(), u128::MAX);
    }

    #[test]
    fn parse_uppercase() {
        let result = UUIDLike::parse_uuid_string("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF");
        assert_eq!(result.unwrap().as_u128(), u128::MAX);
    }

    #[test]
    fn parse_mixed_case() {
        let result = UUIDLike::parse_uuid_string("AaBbCcDd-1234-5678-90aB-cDeF01234567");
        assert!(result.is_ok());
    }

    #[test]
    fn parse_all_zeros() {
        let result = UUIDLike::parse_uuid_string("00000000-0000-0000-0000-000000000000");
        assert_eq!(result.unwrap().as_u128(), 0);
    }
}
