//! Runtime-determined TNIDs without compile-time type checking.
//!
//! This module provides [`DynamicTnid`], a TNID type where the name is determined at runtime
//! rather than at compile time. Unlike [`Tnid<Name>`](crate::Tnid), which uses the type system
//! to ensure name correctness, `DynamicTnid` accepts any valid TNID name string.
//!
//! # When to use DynamicTnid
//!
//! Use `DynamicTnid` when:
//! - You're parsing TNIDs from external sources (APIs, databases, user input)
//! - You need to work with TNIDs of different types in the same collection
//! - The TNID name isn't known until runtime
//!
//! Use [`Tnid<Name>`](crate::Tnid) when:
//! - You know the TNID type at compile time
//! - You want type-level guarantees about TNID names
//! - You want to prevent accidentally mixing different TNID types
//!
//! # Example
//!
//! ```rust
//! use tnid::{DynamicTnid, NameStr};
//!
//! // Create a TNID with a runtime-determined name
//! let name = NameStr::new("user").unwrap();
//! let id = DynamicTnid::new_v0(name).unwrap();
//!
//! // Parse from string
//! let parsed = DynamicTnid::parse_tnid_string("user.Br2flcNDfF6LYICnT").unwrap();
//!
//! // Extract the name at runtime
//! assert_eq!(parsed.name(), "user");
//! ```

#[cfg(feature = "encryption")]
use crate::EncryptionKey;
use crate::{data_encoding, name_encoding, utils, v0, v1, NameStr, Tnid, TnidName, TnidVariant, UUIDLike};
#[cfg(feature = "time")]
use time::OffsetDateTime;

/// A TNID with runtime-determined name.
///
/// Unlike [`Tnid<Name>`](crate::Tnid), which enforces name correctness at compile time,
/// `DynamicTnid` accepts any valid TNID name and validates it at runtime. This makes it
/// suitable for parsing TNIDs from external sources or working with mixed TNID types.
///
/// # Conversions
///
/// - Convert from [`Tnid<Name>`](crate::Tnid) using `From`
/// - Convert to [`Tnid<Name>`](crate::Tnid) using `TryFrom` (validates name matches)
/// - Convert from [`UUIDLike`] using `TryFrom` (validates TNID structure)
/// - Convert to [`UUIDLike`] using `From`
///
/// # Examples
///
/// ```rust
/// use tnid::{DynamicTnid, NameStr};
///
/// // Create a new TNID
/// let name = NameStr::new("user").unwrap();
/// let id = DynamicTnid::new_v0(name).unwrap();
///
/// // Parse from string
/// let parsed = DynamicTnid::parse_tnid_string("user.Br2flcNDfF6LYICnT").unwrap();
///
/// // Get the name
/// println!("Name: {}", parsed.name());
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DynamicTnid(u128);

impl DynamicTnid {
    /// Generates a new v0 TNID with the given name.
    ///
    /// This variant is time-ordered with millisecond precision, similar to UUIDv7.
    /// TNIDs created earlier will sort before those created later in all representations
    /// (u128, UUID hex, and TNID string). The remaining bits are filled with random data.
    ///
    /// Use this when you need time-based sorting and want IDs to be roughly chronological,
    /// similar to choosing UUIDv7 over UUIDv4.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    ///
    /// let name = NameStr::new("user").unwrap();
    /// let id = DynamicTnid::new_v0(name).unwrap();
    /// ```
    #[cfg(all(feature = "time", feature = "rand"))]
    pub fn new_v0(name: NameStr) -> Option<Self> {
        Self::new_v0_with_time(name, time::OffsetDateTime::now_utc())
    }

    /// Generates a new time-ordered TNID (alias for [`Self::new_v0`]).
    ///
    /// This variant is sortable by creation time, similar to UUIDv7. TNIDs created earlier
    /// will sort before those created later in all representations (u128, UUID hex, TNID string).
    ///
    /// Use this when you need time-based sorting, similar to choosing UUIDv7 over UUIDv4.
    #[cfg(all(feature = "time", feature = "rand"))]
    pub fn new_time_ordered(name: NameStr) -> Option<Self> {
        Self::new_v0(name)
    }

    /// Generates a new v0 TNID with a specific timestamp.
    ///
    /// This allows you to control the timestamp portion of the TNID, useful for testing
    /// or when you want IDs to reflect a specific point in time. The remaining bits are
    /// filled with random data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    /// use time::{OffsetDateTime, Duration};
    ///
    /// let name = NameStr::new("user").unwrap();
    /// let now = OffsetDateTime::now_utc();
    /// let id = DynamicTnid::new_v0_with_time(name, now).unwrap();
    /// ```
    #[cfg(all(feature = "time", feature = "rand"))]
    pub fn new_v0_with_time(name: NameStr, time: OffsetDateTime) -> Option<Self> {
        let epoch_millis = (time.unix_timestamp_nanos() / 1000 / 1000) as u64;
        let random_bits: u64 = rand::random();
        Some(Self(v0::make_from_parts(name, epoch_millis, random_bits)))
    }

    /// Generates a new v0 TNID with explicit timestamp and random components.
    ///
    /// This is the lowest-level constructor for v0 TNIDs, giving you full control over
    /// both the timestamp and random portions. Useful when you need reproducible IDs
    /// (e.g., for testing) or when integrating with external randomness sources.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    ///
    /// let name = NameStr::new("user").unwrap();
    /// let timestamp_ms = 1750118400000;
    /// let random_bits = 42;
    ///
    /// let id = DynamicTnid::new_v0_with_parts(name, timestamp_ms, random_bits).unwrap();
    /// ```
    pub fn new_v0_with_parts(name: NameStr, epoch_millis: u64, random: u64) -> Option<Self> {
        Some(Self(v0::make_from_parts(name, epoch_millis, random)))
    }

    /// Generates a new v1 TNID with the given name.
    ///
    /// This variant maximizes entropy with 100 bits of random data, similar to UUIDv4.
    /// This is almost certainly sufficient for most use cases.
    ///
    /// Use this when you don't need time-based sorting and want maximum randomness,
    /// similar to choosing UUIDv4 over UUIDv7.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    ///
    /// let name = NameStr::new("user").unwrap();
    /// let id = DynamicTnid::new_v1(name).unwrap();
    /// ```
    #[cfg(feature = "rand")]
    pub fn new_v1(name: NameStr) -> Option<Self> {
        Self::new_v1_with_random(name, rand::random())
    }

    /// Generates a new TNID with maximum randomness (alias for [`Self::new_v1`]).
    ///
    /// This variant provides the highest entropy, similar to UUIDv4. Use this when you
    /// don't need time-based sorting.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    ///
    /// let name = NameStr::new("user").unwrap();
    /// let id = DynamicTnid::new_high_entropy(name).unwrap();
    /// ```
    #[cfg(feature = "rand")]
    pub fn new_high_entropy(name: NameStr) -> Option<Self> {
        Self::new_v1(name)
    }

    /// Generates a new v1 TNID with explicit random bits.
    ///
    /// This allows you to provide your own source of randomness, useful for testing
    /// or when integrating with specific random number generators.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    ///
    /// let name = NameStr::new("user").unwrap();
    /// let random_bits = 0x0123456789ABCDEF0123456789ABCDEF;
    ///
    /// let id = DynamicTnid::new_v1_with_random(name, random_bits).unwrap();
    /// ```
    pub fn new_v1_with_random(name: NameStr, random_bits: u128) -> Option<Self> {
        Some(Self(v1::make_from_parts(name, random_bits)))
    }

    /// Creates a TNID from a raw 128-bit value.
    ///
    /// This is the inverse of [`Self::as_u128`] and is useful for loading TNIDs from
    /// databases that store UUIDs as u128/binary, interoperating with UUID-based systems,
    /// or deserializing.
    ///
    /// Returns `None` if the value is not a valid TNID. Validation includes:
    /// - Correct UUIDv8 version and variant bits
    /// - Valid name encoding (1-4 characters, properly encoded)
    ///
    /// # Endianness
    ///
    /// When loading from bytes, you'll almost certainly want to parse a `[u8; 16]` to a
    /// `u128` using big-endian byte order with [`u128::from_be_bytes()`], as per the
    /// UUID specification.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::DynamicTnid;
    ///
    /// let id = DynamicTnid::from_u128(0xCAB1952A_F09D_86D9_928E_96EA03DC6AF3).unwrap();
    /// assert_eq!(id.name(), "test");
    /// ```
    pub fn from_u128(id: u128) -> Option<Self> {
        // Validate UUIDv8 version and variant bits
        if (id & utils::UUID_V8_MASK) != utils::UUID_V8_MASK {
            return None;
        }

        // Validate name encoding
        if name_encoding::validate_name_bits(id) != name_encoding::NameBitsValidation::Valid {
            return None;
        }

        Some(Self(id))
    }

    /// Parses a TNID from its string representation.
    ///
    /// This is the inverse of [`Self::to_tnid_string`].
    ///
    /// Returns `None` if the string is invalid. Validation includes:
    /// - Correct format (`<name>.<encoded-data>`)
    /// - Valid name (1-4 characters, from allowed character set)
    /// - Valid TNID Data Encoding
    /// - Correct UUIDv8 version and variant bits
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::DynamicTnid;
    ///
    /// // Successful parsing
    /// let parsed = DynamicTnid::parse_tnid_string("user.Br2flcNDfF6LYICnT").unwrap();
    /// assert_eq!(parsed.name(), "user");
    ///
    /// // Failed parsing - invalid format
    /// assert!(DynamicTnid::parse_tnid_string("not-a-tnid").is_none());
    /// ```
    pub fn parse_tnid_string(s: &str) -> Option<Self> {
        // Split on dot separator
        let (name_str, data_str) = s.split_once('.')?;

        // Validate name is valid
        let name = NameStr::new(name_str)?;

        // Decode data string to compact 102 bits
        let compact_data = data_encoding::string_to_id_data(data_str)?;

        // Expand to proper bit positions
        let data_bits = data_encoding::expand_data_bits(compact_data);

        // Get name bits
        let name_bits = name_encoding::name_mask(name);

        // Combine: name + UUID metadata + data
        let id = name_bits | utils::UUID_V8_MASK | data_bits;

        Some(Self(id))
    }

    /// Parses a TNID from UUID hex string format.
    ///
    /// This is the inverse of [`Self::to_uuid_string`].
    ///
    /// The parser accepts both uppercase and lowercase hex digits (A-F or a-f).
    ///
    /// Returns `None` if:
    /// - The string is not a valid UUID format
    /// - The UUID is not a valid TNID (wrong version/variant bits or invalid name encoding)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    ///
    /// // Create a TNID and convert to UUID string
    /// let name = NameStr::new("user").unwrap();
    /// let original = DynamicTnid::new_v1(name).unwrap();
    /// let uuid_string = original.to_uuid_string(false);
    ///
    /// // Parse it back
    /// let parsed = DynamicTnid::parse_uuid_string(&uuid_string).unwrap();
    /// assert_eq!(parsed.as_u128(), original.as_u128());
    ///
    /// // Also accepts uppercase
    /// let uuid_upper = original.to_uuid_string(true);
    /// let parsed_upper = DynamicTnid::parse_uuid_string(&uuid_upper).unwrap();
    ///
    /// // Invalid: not a valid UUID format
    /// assert!(DynamicTnid::parse_uuid_string("not-a-uuid").is_none());
    /// ```
    pub fn parse_uuid_string(s: &str) -> Option<Self> {
        let id = crate::UUIDLike::parse_uuid_string(s)?.as_u128();

        Self::from_u128(id)
    }

    /// Returns the TNID's name as a string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    ///
    /// let name = NameStr::new("user").unwrap();
    /// let id = DynamicTnid::new_v0(name).unwrap();
    /// assert_eq!(id.name(), "user");
    /// ```
    pub fn name(&self) -> String {
        name_encoding::extract_name_string(self.0).expect("DynamicTnid must have valid name")
    }

    /// Returns the name encoded as a 5-character hex string.
    ///
    /// This is useful for debugging or when you need a compact representation of the name.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    ///
    /// let name = NameStr::new("test").unwrap();
    /// let id = DynamicTnid::new_v1(name).unwrap();
    /// assert_eq!(id.name_hex(), "cab19");
    /// ```
    pub fn name_hex(&self) -> String {
        name_encoding::name_bits_to_hex(self.0)
    }

    /// Returns the raw 128-bit UUIDv8-compatible representation of this TNID.
    ///
    /// This returns the complete bit representation including the name, UUID version/variant
    /// bits, and all data. This is the inverse of [`Self::from_u128`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    ///
    /// let name = NameStr::new("user").unwrap();
    /// let id = DynamicTnid::new_v0(name).unwrap();
    /// let as_u128 = id.as_u128();
    ///
    /// // Convert to big-endian bytes for storage/transmission
    /// let bytes = as_u128.to_be_bytes();
    /// ```
    pub fn as_u128(&self) -> u128 {
        self.0
    }

    /// Returns the TNID variant.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr, TnidVariant};
    ///
    /// let id_v0 = DynamicTnid::new_v0(NameStr::new("user").unwrap()).unwrap();
    /// assert_eq!(id_v0.variant(), TnidVariant::V0);
    ///
    /// let id_v1 = DynamicTnid::new_v1(NameStr::new("user").unwrap()).unwrap();
    /// assert_eq!(id_v1.variant(), TnidVariant::V1);
    /// ```
    pub fn variant(&self) -> TnidVariant {
        TnidVariant::from_id(self.0)
    }

    /// Converts the TNID to its string representation.
    ///
    /// This is the human-readable, sortable format: `<name>.<encoded-data>`.
    /// This is the inverse of [`Self::parse_tnid_string`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    ///
    /// let name = NameStr::new("user").unwrap();
    /// let id = DynamicTnid::new_v0(name).unwrap();
    /// let tnid_string = id.to_tnid_string();
    ///
    /// // Format: <name>.<encoded-data>
    /// // Example: "user.Br2flcNDfF6LYICnT"
    /// assert!(tnid_string.starts_with("user."));
    /// ```
    pub fn to_tnid_string(&self) -> String {
        format!("{}.{}", self.name(), data_encoding::id_data_to_string(self.0))
    }

    /// Converts the TNID to UUID hex string format.
    ///
    /// This is useful for UUID compatibility and interoperability with systems that expect
    /// UUID hex strings. This is the inverse of [`Self::parse_uuid_string`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    ///
    /// let name = NameStr::new("user").unwrap();
    /// let id = DynamicTnid::new_v1(name).unwrap();
    ///
    /// let uuid_lower = id.to_uuid_string(false);
    /// // "cab1952a-f09d-86d9-928e-96ea03dc6af3"
    ///
    /// let uuid_upper = id.to_uuid_string(true);
    /// // "CAB1952A-F09D-86D9-928E-96EA03DC6AF3"
    /// ```
    pub fn to_uuid_string(&self, uppercase: bool) -> String {
        utils::u128_to_uuid_string(self.0, uppercase)
    }

    /// Converts the TNID to its 16-byte big-endian representation.
    ///
    /// This is useful for storing TNIDs in binary format or transmitting over the wire.
    /// This is the inverse of [`Self::from_bytes`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    ///
    /// let name = NameStr::new("user").unwrap();
    /// let id = DynamicTnid::new_v1(name).unwrap();
    /// let bytes = id.to_bytes();
    /// assert_eq!(bytes.len(), 16);
    /// ```
    pub fn to_bytes(&self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    /// Creates a TNID from its 16-byte big-endian representation.
    ///
    /// This is the inverse of [`Self::to_bytes`] and validates that the bytes represent
    /// a valid TNID.
    ///
    /// Returns `None` if the bytes don't represent a valid TNID (invalid UUID version/variant
    /// bits or invalid name encoding).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{DynamicTnid, NameStr};
    ///
    /// let name = NameStr::new("user").unwrap();
    /// let original = DynamicTnid::new_v1(name).unwrap();
    /// let bytes = original.to_bytes();
    ///
    /// let parsed = DynamicTnid::from_bytes(bytes).unwrap();
    /// assert_eq!(parsed.as_u128(), original.as_u128());
    /// ```
    pub fn from_bytes(bytes: [u8; 16]) -> Option<Self> {
        Self::from_u128(u128::from_be_bytes(bytes))
    }

    #[cfg(feature = "encryption")]
    pub fn encrypt_v0_to_v1(&self, key: impl Into<EncryptionKey>) -> Option<Self> {
        let id = crate::encryption::encrypt_id_v0_to_v1(self.0, &key.into())?;
        Some(Self(id))
    }

    #[cfg(feature = "encryption")]
    pub fn decrypt_v1_to_v0(&self, key: impl Into<EncryptionKey>) -> Option<Self> {
        let id = crate::encryption::decrypt_id_v1_to_v0(self.0, &key.into())?;
        Some(Self(id))
    }
}

impl<Name: TnidName> From<Tnid<Name>> for DynamicTnid {
    fn from(tnid: Tnid<Name>) -> Self {
        Self(tnid.as_u128())
    }
}

impl TryFrom<UUIDLike> for DynamicTnid {
    type Error = ();

    fn try_from(uuid: UUIDLike) -> Result<Self, Self::Error> {
        Self::from_u128(uuid.as_u128()).ok_or(())
    }
}

impl<Name: TnidName> TryFrom<DynamicTnid> for Tnid<Name> {
    type Error = ();

    fn try_from(dynamic: DynamicTnid) -> Result<Self, Self::Error> {
        Tnid::<Name>::from_u128(dynamic.0).ok_or(())
    }
}

impl From<DynamicTnid> for UUIDLike {
    fn from(dynamic: DynamicTnid) -> Self {
        UUIDLike::new(dynamic.0)
    }
}

impl core::fmt::Display for DynamicTnid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_tnid_string())
    }
}

impl core::fmt::Debug for DynamicTnid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_tnid_string())
    }
}
