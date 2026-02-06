#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::indexing_slicing)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]

use std::marker::PhantomData;

mod data_encoding;
pub mod dynamic_tnid;
#[cfg(feature = "encryption")]
pub mod encryption;
#[cfg(feature = "filter")]
pub mod filter;
mod name_encoding;
#[cfg(feature = "serde")]
mod serde_impl;
#[cfg(any(
    feature = "sqlx-postgres",
    feature = "sqlx-mysql",
    feature = "sqlx-sqlite"
))]
mod sqlx_impl;
mod tnid_variant;
mod utils;
#[cfg(feature = "uuid")]
mod uuid;
mod uuidlike;
mod v0;
mod v1;

pub use data_encoding::DataEncodingError;
pub use dynamic_tnid::DynamicTnid;
pub use name_encoding::{NameBitsValidation, NameError, NameStr};
pub use tnid_variant::TnidVariant;
pub use uuidlike::Case;
pub use uuidlike::{ParseUuidStringError, UuidLike};

/// Error when parsing a TNID from a string or u128.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseTnidError {
    /// The TNID string has an invalid length (TNID string parsing only).
    /// Contains the actual length (expected 19-22 characters).
    InvalidLength(usize),
    /// The string does not contain a dot separator (TNID string parsing only).
    MissingSeparator,
    /// The name portion is invalid (TNID string parsing only).
    InvalidName(NameError),
    /// The name in the string/bytes does not match the expected type parameter name.
    /// Contains the expected name and the actual name found.
    NameMismatch {
        /// The expected name from the type parameter
        expected: &'static str,
        /// The actual name found in the data
        found: String,
    },
    /// The data portion has an invalid encoding (TNID string parsing only).
    InvalidDataEncoding(data_encoding::DataEncodingError),
    /// The UUID string format is invalid (UUID string parsing only).
    InvalidUuidFormat(ParseUuidStringError),
    /// The TNID structure has invalid UUID version/variant bits.
    InvalidUuidBits,
    /// The name encoding in the bits is invalid (empty or malformed).
    InvalidNameBits,
}

impl std::fmt::Display for ParseTnidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength(len) => {
                write!(
                    f,
                    "TNID string length {len} is invalid; expected 19-22 characters"
                )
            }
            Self::MissingSeparator => {
                write!(
                    f,
                    "TNID string missing dot separator; expected format: <name>.<data>"
                )
            }
            Self::InvalidName(e) => write!(f, "invalid TNID name: {e}"),
            Self::NameMismatch { expected, found } => {
                write!(f, "name mismatch: expected '{expected}', found '{found}'")
            }
            Self::InvalidDataEncoding(e) => write!(f, "invalid TNID data encoding: {e}"),
            Self::InvalidUuidFormat(e) => write!(f, "invalid UUID format: {e}"),
            Self::InvalidUuidBits => {
                write!(f, "invalid UUID version/variant bits; expected UUIDv8")
            }
            Self::InvalidNameBits => {
                write!(f, "invalid name encoding in bits (empty or malformed)")
            }
        }
    }
}

impl std::error::Error for ParseTnidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidName(e) => Some(e),
            Self::InvalidDataEncoding(e) => Some(e),
            Self::InvalidUuidFormat(e) => Some(e),
            _ => None,
        }
    }
}

/// Intended to be used on empty structs to create type checked TNID names.
///
/// ```rust
/// # use tnid::TnidName;
/// # use tnid::Tnid;
/// # use tnid::NameStr;
///
/// struct ExampleName;
/// impl TnidName for ExampleName {
///     const ID_NAME: NameStr<'static> = NameStr::new_const("exna");
/// }
///
/// # let _ = Tnid::<ExampleName>::new_v0();
/// ```
///
/// [`NameStr::new_const`] validates the name at compile time and is the only way to create
/// a `NameStr<'static>`, ensuring all [`Tnid`] names are valid.
/// ```rust,compile_fail
/// # use tnid::TnidName;
/// # use tnid::Tnid;
/// # use tnid::NameStr;
///
/// struct InvalidName;
/// impl TnidName for InvalidName {
///     const ID_NAME: NameStr<'static> = NameStr::new_const("2long");
/// }
///
/// # let _ = Tnid::<InvalidName>::new_v0();
/// ```
pub trait TnidName {
    /// Must be overridden with the name of your ID
    const ID_NAME: NameStr<'static>;
}

/// A type-safe TNID parameterized by name.
///
/// The type parameter uses the [`TnidName`] trait to enforce compile-time checking of names.
/// `Tnid<User>` and `Tnid<Post>` are distinct types that cannot be mixed.
///
/// All validation happens at construction time, so any `Tnid<Name>` instance is guaranteed
/// to be valid. If you need to work with potentially invalid 128-bit values, use [`UuidLike`]
/// for inspection without validation.
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tnid<Name: TnidName> {
    id_name: PhantomData<Name>,
    id: u128,
}

impl<Name: TnidName> Copy for Tnid<Name> {}

impl<Name: TnidName> Clone for Tnid<Name> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Name: TnidName> Tnid<Name> {
    /// Returns the name associated with this TNID type.
    ///
    /// The name comes from the [`TnidName`] implementation for this type and is
    /// used in the TNID string representation (`<name>.<data>`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let id = Tnid::<User>::new_v0();
    /// assert_eq!(id.name(), "user");
    /// ```
    pub fn name(&self) -> &'static str {
        Name::ID_NAME.as_str()
    }

    /// Returns the hex representation of the name field (20 bits as 5 hex characters).
    ///
    /// The ASCII representation of a name (like "test") is different from the hex
    /// representation of those bits when viewing a TNID in hex format. This method shows
    /// what the name looks like as hex, which is how it appears in TNID hex strings.
    ///
    /// This is useful for understanding what the name portion looks like in the hex
    /// representation without needing a specific TNID instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    ///
    /// struct Test;
    /// impl TnidName for Test {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("test");
    /// }
    ///
    /// // Check what "test" looks like in hex (any TNID instance works)
    /// let id = Tnid::<Test>::new_v1();
    /// assert_eq!(id.name_hex(), "cab19");
    /// ```
    pub fn name_hex(&self) -> String {
        name_encoding::name_bits_to_hex(self.id)
    }

    /// Returns the raw 128-bit UUIDv8-compatible representation of this TNID.
    ///
    /// This returns the complete bit representation including the name, UUID version/variant
    /// bits, TNID variant, and all data bits.
    ///
    /// # Endianness
    ///
    /// The UUID specification dictates that [UUIDs are stored in big-endian](https://datatracker.ietf.org/doc/html/rfc9562#name-uuid-format) byte order.
    /// When storing or transmitting this `u128` value as bytes, you may need to convert
    /// to big-endian format using methods like [`u128::to_be_bytes()`] since `u128` uses
    /// the platform's native endianness.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let id = Tnid::<User>::new_v0();
    /// let as_u128 = id.as_u128();
    ///
    /// // Convert to big-endian bytes for storage/transmission
    /// let bytes = as_u128.to_be_bytes();
    /// ```
    pub fn as_u128(&self) -> u128 {
        self.id
    }

    /// Generates a new time-ordered TNID (alias for [`Self::new_v0`]).
    ///
    /// This variant is sortable by creation time, similar to UUIDv7. TNIDs created earlier
    /// will sort before those created later in all representations (u128, UUID hex, TNID string).
    ///
    /// Use this when you need time-based sorting, similar to choosing UUIDv7 over UUIDv4.
    #[cfg(all(feature = "time", feature = "rand"))]
    pub fn new_time_ordered() -> Self {
        Self::new_v0()
    }

    /// Generates a new v0 TNID.
    ///
    /// This variant is time-ordered with millisecond precision, similar to UUIDv7.
    /// TNIDs created earlier will sort before those created later in all representations
    /// (u128, UUID hex, and TNID string). The remaining bits are filled with random data.
    ///
    /// Use this when you need time-based sorting and want IDs to be roughly chronological,
    /// similar to choosing UUIDv7 over UUIDv4.
    #[cfg(all(feature = "time", feature = "rand"))]
    pub fn new_v0() -> Self {
        Self::new_v0_with_time(time::OffsetDateTime::now_utc())
    }

    /// Generates a new TNID with maximum randomness (alias for [`Self::new_v1`]).
    ///
    /// This variant maximizes entropy with 100 bits of random data, similar to UUIDv4
    /// but with slightly less entropy due to the 20-bit name field. This is almost
    /// certainly sufficient for most use cases.
    ///
    /// Use this when you don't need time-based sorting and want maximum randomness,
    /// similar to choosing UUIDv4 over UUIDv7.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let id = Tnid::<User>::new_high_entropy();
    /// ```
    #[cfg(feature = "rand")]
    pub fn new_high_entropy() -> Self {
        Self::new_v1()
    }

    /// Generates a new v1 TNID.
    ///
    /// This variant maximizes entropy with 100 bits of random data, similar to UUIDv4.
    /// This is almost certainly sufficient for most use cases.
    ///
    /// Use this when you don't need time-based sorting and want maximum randomness,
    /// similar to choosing UUIDv4 over UUIDv7.
    #[cfg(feature = "rand")]
    pub fn new_v1() -> Self {
        Self::new_v1_with_random(rand::random())
    }

    /// Generates a new high-entropy TNID (v1) from explicit random bits.
    ///
    /// This creates a v1 TNID without requiring the `rand` feature dependency,
    /// allowing you to provide your own randomness source. This is useful in
    /// environments where the `rand` library may not be suitable (embedded systems,
    /// WASM, or when you need a custom random source).
    ///
    /// # Parameters
    ///
    /// - `random_bits`: Random bits for the TNID. Only 100 bits are used, but
    ///   accepting a `u128` makes it easier to provide randomness.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// // Provide your own randomness
    /// let random_bits = 0x0123456789ABCDEF0123456789ABCDEF;
    ///
    /// let id = Tnid::<User>::new_v1_with_random(random_bits);
    /// ```
    pub fn new_v1_with_random(random_bits: u128) -> Self {
        let id_name = Name::ID_NAME;

        let id = v1::make_from_parts(id_name, random_bits);

        Self {
            id_name: PhantomData,
            id,
        }
    }

    /// Generates a new time-ordered TNID (v0) with a specific timestamp.
    ///
    /// This creates the same time-sortable TNID as [`Self::new_v0`], but allows you to
    /// provide a specific timestamp instead of using the current time. The timestamp is
    /// converted to milliseconds since the Unix epoch and encoded into the TNID.
    ///
    /// TNIDs created with earlier timestamps will sort before those with later timestamps
    /// in all representations (u128, UUID hex, and TNID string).
    ///
    /// # Timestamp Range
    ///
    /// The timestamp field uses 43 bits to store milliseconds since the Unix epoch, which
    /// means TNIDv0 IDs can only represent times between 1970-01-01 and approximately
    /// the year 2248. Times outside this range will **wrap around**:
    ///
    /// - **Pre-epoch times** (before 1970-01-01): The negative milliseconds value wraps
    ///   to a large positive value, resulting in a timestamp that appears far in the future.
    /// - **Post-2248 times**: The milliseconds value overflows and wraps around, resulting
    ///   in a timestamp that appears in the past.
    ///
    /// This wrapping behavior is intentional and matches the spec's guidance for post-2248
    /// overflow. If your application requires pre-epoch timestamps, consider using a
    /// different ID scheme or storing the timestamp separately.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    /// use time::OffsetDateTime;
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let timestamp = OffsetDateTime::now_utc();
    /// let id = Tnid::<User>::new_v0_with_time(timestamp);
    /// ```
    ///
    /// Demonstrating time-based sorting:
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    /// use time::{OffsetDateTime, Duration};
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let now = OffsetDateTime::now_utc();
    /// let earlier = now - Duration::hours(1);
    /// let later = now + Duration::hours(1);
    ///
    /// let id1 = Tnid::<User>::new_v0_with_time(earlier);
    /// let id2 = Tnid::<User>::new_v0_with_time(now);
    /// let id3 = Tnid::<User>::new_v0_with_time(later);
    ///
    /// // Earlier times sort before later times
    /// assert!(id1.as_u128() < id2.as_u128());
    /// assert!(id2.as_u128() < id3.as_u128());
    /// ```
    #[cfg(all(feature = "rand", feature = "time"))]
    pub fn new_v0_with_time(time: time::OffsetDateTime) -> Self {
        let id_name = Name::ID_NAME;

        let epoch_millis = (time.unix_timestamp_nanos() / 1000 / 1000) as u64;

        let random_bits: u64 = rand::random();

        let id = v0::make_from_parts(id_name, epoch_millis, random_bits);

        Self {
            id_name: PhantomData,
            id,
        }
    }

    /// Generates a new time-ordered TNID (v0) from explicit components.
    ///
    /// This creates a v0 TNID without requiring the `time` or `rand` feature dependencies,
    /// allowing you to provide your own timestamp and randomness sources. This is useful
    /// in environments where those libraries may not be suitable (embedded systems, WASM,
    /// or when you need custom time/random sources).
    ///
    /// # Parameters
    ///
    /// - `epoch_millis`: Milliseconds since the Unix epoch (January 1, 1970 UTC)
    /// - `random`: Random bits for the TNID (57 bits will be used)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// // Provide your own timestamp and randomness
    /// let timestamp_ms = 1750118400000;
    /// let random_bits = 42;
    ///
    /// let id = Tnid::<User>::new_v0_with_parts(timestamp_ms, random_bits);
    /// ```
    pub fn new_v0_with_parts(epoch_millis: u64, random: u64) -> Self {
        Self {
            id_name: PhantomData,
            id: v0::make_from_parts(Name::ID_NAME, epoch_millis, random),
        }
    }

    /// Returns the TNID string representation.
    ///
    /// This representation has several advantages over the UUID hex format:
    /// - **Unambiguous**: Unlike UUID hex strings which are case-insensitive, TNID strings
    ///   are case-sensitive with exactly one valid representation
    /// - **Sortable**: For v0 TNIDs, the string representation maintains time-ordering
    /// - **Human-readable name**: The name prefix makes it easy to identify the ID type
    ///
    /// The format is `<name>.<encoded-data>`, where the data is encoded using the TNID
    /// Data Encoding that preserves these sortability and uniqueness properties.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let id = Tnid::<User>::new_v0();
    /// let tnid_string = id.to_tnid_string();
    ///
    /// // Format: <name>.<encoded-data>
    /// // Example: "user.Br2flcNDfF6LYICnT"
    /// assert!(tnid_string.starts_with("user."));
    /// ```
    pub fn to_tnid_string(&self) -> String {
        format!(
            "{}.{}",
            self.name(),
            data_encoding::id_data_to_string(self.id)
        )
    }

    /// Returns just the data portion of the TNID string (17 characters).
    ///
    /// This is the encoded data after the dot in the full TNID string format.
    /// Useful for inspecting or filtering the data portion independently.
    pub fn data_string(&self) -> String {
        data_encoding::id_data_to_string(self.id)
    }

    /// Returns the TNID variant.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr, TnidVariant};
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let id_v0 = Tnid::<User>::new_v0();
    /// assert_eq!(id_v0.variant(), TnidVariant::V0);
    ///
    /// let id_v1 = Tnid::<User>::new_v1();
    /// assert_eq!(id_v1.variant(), TnidVariant::V1);
    /// ```
    pub fn variant(&self) -> TnidVariant {
        TnidVariant::from_id(self.id)
    }

    /// Converts the TNID to UUID hex string format.
    ///
    /// This is useful for UUID compatibility and interoperability with systems that expect
    /// standard UUID format, or any other case where you need the common UUID hex representation.
    ///
    /// # Parameters
    ///
    /// - `case`: Whether to use uppercase (`A-F`) or lowercase (`a-f`) hex digits.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let id = Tnid::<User>::new_v1();
    ///
    /// use tnid::Case;
    ///
    /// let uuid_lower = id.to_uuid_string(Case::Lower);
    /// // "cab1952a-f09d-86d9-928e-96ea03dc6af3"
    ///
    /// let uuid_upper = id.to_uuid_string(Case::Upper);
    /// // "CAB1952A-F09D-86D9-928E-96EA03DC6AF3"
    /// ```
    pub fn to_uuid_string(&self, case: Case) -> String {
        utils::u128_to_uuid_string(self.id, case)
    }

    /// Parses a TNID from UUID hex string format.
    ///
    /// This is the inverse of [`Self::to_uuid_string`].
    ///
    /// The parser accepts both uppercase and lowercase hex digits (A-F or a-f).
    ///
    /// Returns `Err` if:
    /// - The string is not valid UUID format
    /// - The UUID is not a valid TNID (wrong version/variant bits or name mismatch)
    ///
    /// For inspecting why a UUID might not be a valid TNID, see [`UuidLike`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// // Create a TNID and convert to UUID string
    /// let original = Tnid::<User>::new_v1();
    /// use tnid::Case;
    ///
    /// let uuid_string = original.to_uuid_string(Case::Lower);
    ///
    /// // Parse it back
    /// let parsed = Tnid::<User>::parse_uuid_string(&uuid_string);
    /// assert!(parsed.is_ok());
    /// assert_eq!(parsed.unwrap().as_u128(), original.as_u128());
    ///
    /// // Also accepts uppercase
    /// let uuid_upper = original.to_uuid_string(Case::Upper);
    /// let parsed_upper = Tnid::<User>::parse_uuid_string(&uuid_upper);
    /// assert!(parsed_upper.is_ok());
    ///
    /// // Invalid: not a valid UUID format
    /// assert!(Tnid::<User>::parse_uuid_string("not-a-uuid").is_err());
    /// ```
    pub fn parse_uuid_string(uuid_string: &str) -> Result<Self, ParseTnidError> {
        let id = UuidLike::parse_uuid_string(uuid_string)
            .map_err(ParseTnidError::InvalidUuidFormat)?
            .as_u128();

        Self::from_u128(id)
    }

    /// Parses a TNID from its string representation.
    ///
    /// This is the inverse of [`Self::to_tnid_string`]. See that method for details
    /// on the TNID string format.
    ///
    /// Returns `Err` if the string is invalid. Validation includes:
    /// - Correct format (`<name>.<encoded-data>`)
    /// - Name matches the expected name for this TNID type
    /// - Valid TNID Data Encoding
    /// - Correct UUIDv8 version and variant bits
    ///
    /// If you need to inspect non-compliant IDs or understand why parsing failed,
    /// consider using [`UuidLike`] which provides lower-level access.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// // Successful parsing
    /// let parsed = Tnid::<User>::parse_tnid_string("user.Br2flcNDfF6LYICnT");
    /// assert!(parsed.is_ok());
    ///
    /// // Failed parsing - wrong name
    /// assert!(Tnid::<User>::parse_tnid_string("post.Br2flcNDfF6LYICnT").is_err());
    ///
    /// // Failed parsing - invalid format
    /// assert!(Tnid::<User>::parse_tnid_string("not-a-tnid").is_err());
    /// ```
    pub fn parse_tnid_string(tnid_string: &str) -> Result<Self, ParseTnidError> {
        // Quick length check - valid TNIDs are 19-22 chars (name 1-4 + '.' + data 17)
        const MIN_LEN: usize =
            name_encoding::NAME_MIN_CHARS + 1 + data_encoding::DATA_CHAR_ENCODING_LEN as usize;
        const MAX_LEN: usize =
            name_encoding::NAME_MAX_CHARS + 1 + data_encoding::DATA_CHAR_ENCODING_LEN as usize;

        if tnid_string.len() < MIN_LEN || tnid_string.len() > MAX_LEN {
            return Err(ParseTnidError::InvalidLength(tnid_string.len()));
        }

        // Split on dot separator
        let (name, data_str) = tnid_string
            .split_once('.')
            .ok_or(ParseTnidError::MissingSeparator)?;

        // Validate name matches expected name
        if name != Name::ID_NAME.as_str() {
            return Err(ParseTnidError::NameMismatch {
                expected: Name::ID_NAME.as_str(),
                found: name.to_string(),
            });
        }

        // Decode data string to compact 102 bits
        let compact_data = data_encoding::string_to_id_data(data_str)
            .map_err(ParseTnidError::InvalidDataEncoding)?;

        // Expand to proper bit positions
        let data_bits = data_encoding::expand_data_bits(compact_data);

        // Get name bits
        let name_bits = name_encoding::name_mask(Name::ID_NAME);

        // Combine: name + UUID metadata + data
        let id = name_bits | utils::UUID_V8_MASK | data_bits;

        // Validate and construct (this checks UUID bits and name encoding)
        Self::from_u128(id)
    }

    /// Creates a TNID from a raw 128-bit value.
    ///
    /// This is the inverse of [`Self::as_u128`] and is useful for loading TNIDs from
    /// databases that store UUIDs as u128/binary, interoperating with UUID-based systems,
    /// or deserializing.
    ///
    /// Returns `Err` if the value is not a valid TNID. Validation includes:
    /// - Correct UUIDv8 version and variant bits
    /// - Name encoding matches the expected name for this TNID type
    ///
    /// # Endianness
    ///
    /// When loading from bytes, you'll almost certainly want to parse a `[u8; 16]` to a
    /// `u128` using big-endian byte order with [`u128::from_be_bytes()`], as per the
    /// UUID specification.
    pub fn from_u128(id: u128) -> Result<Self, ParseTnidError> {
        // check UUIDv8 version and variant bits
        if (id & utils::UUID_V8_MASK) != utils::UUID_V8_MASK {
            return Err(ParseTnidError::InvalidUuidBits);
        }

        // Validate name bits are well-formed before checking for match
        if name_encoding::validate_name_bits(id) == name_encoding::NameBitsValidation::Invalid {
            return Err(ParseTnidError::InvalidNameBits);
        }

        // check name encoding matches expected name
        let name_bits_mask = 0xFFFFF_u128 << 108; // top 20 bits
        let actual_name_bits = id & name_bits_mask;
        let expected_name_bits = name_encoding::name_mask(Name::ID_NAME);
        if actual_name_bits != expected_name_bits {
            // Extract the actual name string for error reporting
            // This should always succeed since we validated the bits above
            let found = name_encoding::extract_name_string(id)
                .expect("name bits validated, extraction should succeed");
            return Err(ParseTnidError::NameMismatch {
                expected: Name::ID_NAME.as_str(),
                found,
            });
        }

        Ok(Self {
            id,
            id_name: PhantomData,
        })
    }

    /// Encrypts a V0 TNID to a V1 TNID, hiding timestamp information.
    ///
    /// V0 TNIDs contain a timestamp (like UUIDv7), which may leak information when exposed
    /// publicly. This method encrypts the data bits to produce a valid V1 TNID that hides
    /// the timestamp while remaining decryptable with [`Self::decrypt_v1_to_v0`].
    ///
    /// See the [`encryption`] module for more details on why and how this works.
    ///
    /// # Parameters
    ///
    /// - `secret`: 128-bit (16 bytes) encryption key
    ///
    /// # Returns
    ///
    /// - `Ok(encrypted)` for V0 input (encrypts and converts to V1)
    /// - `Ok(self)` for V1 input (already encrypted, returns unchanged)
    /// - `Err(())` for V2/V3 input (unsupported variants)
    ///
    /// # Example
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr, TnidVariant};
    /// use tnid::encryption::EncryptionKey;
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let key = EncryptionKey::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    ///
    /// let original = Tnid::<User>::new_v0();
    /// let encrypted = original.encrypt_v0_to_v1(&key).unwrap();
    /// assert_eq!(encrypted.variant(), TnidVariant::V1);
    ///
    /// let decrypted = encrypted.decrypt_v1_to_v0(&key).unwrap();
    /// assert_eq!(decrypted.as_u128(), original.as_u128());
    /// ```
    #[cfg(feature = "encryption")]
    pub fn encrypt_v0_to_v1(
        &self,
        key: &encryption::EncryptionKey,
    ) -> Result<Self, encryption::EncryptionError> {
        let id = encryption::encrypt_id_v0_to_v1(self.id, key)?;

        Ok(Self {
            id_name: PhantomData,
            id,
        })
    }

    /// Decrypts a V1 TNID back to a V0 TNID, recovering timestamp information.
    ///
    /// This is the inverse of [`Self::encrypt_v0_to_v1`]. See the [`encryption`] module
    /// for more details.
    ///
    /// # Parameters
    ///
    /// - `secret`: 128-bit (16 bytes) encryption key (must match the key used for encryption)
    ///
    /// # Returns
    ///
    /// - `Ok(decrypted)` for V1 input (decrypts and converts to V0)
    /// - `Ok(self)` for V0 input (already decrypted, returns unchanged)
    /// - `Err(EncryptionError)` for V2/V3 input (unsupported variants)
    ///
    /// # Example
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr, TnidVariant};
    /// use tnid::encryption::EncryptionKey;
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let key = EncryptionKey::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    ///
    /// let original = Tnid::<User>::new_v0();
    /// let encrypted = original.encrypt_v0_to_v1(&key).unwrap();
    ///
    /// let decrypted = encrypted.decrypt_v1_to_v0(&key).unwrap();
    /// assert_eq!(decrypted.variant(), TnidVariant::V0);
    /// assert_eq!(decrypted.as_u128(), original.as_u128());
    /// ```
    #[cfg(feature = "encryption")]
    pub fn decrypt_v1_to_v0(
        &self,
        key: &encryption::EncryptionKey,
    ) -> Result<Self, encryption::EncryptionError> {
        let id = encryption::decrypt_id_v1_to_v0(self.id, key)?;

        Ok(Self {
            id_name: PhantomData,
            id,
        })
    }

    /// Generates a new V0 TNID with no blocklist matches in its data string.
    ///
    /// This function generates time-ordered TNIDs (like [`Self::new_v0`]) while ensuring
    /// the encoded data portion doesn't contain any words from the blocklist.
    ///
    /// # Algorithm
    ///
    /// 1. Generate a V0 TNID with the current timestamp and random bits
    /// 2. Check the data string for blocklist matches
    /// 3. If a match is found:
    ///    - If it touches the random portion (char 7+): regenerate random bits
    ///    - If it's entirely in the timestamp portion (chars 0-6): bump timestamp by 1ms
    /// 4. Repeat until clean or max iterations reached
    ///
    /// # Errors
    ///
    /// Returns [`FilterError::MaxIterationsExceeded`] if unable to generate a clean ID
    /// after many attempts. This typically indicates the blocklist is too restrictive.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    /// use tnid::filter::Blocklist;
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let blocklist = Blocklist::new(&["TACO", "FOO"]);
    /// let id = Tnid::<User>::new_v0_filtered(&blocklist).unwrap();
    ///
    /// // The data portion won't contain "TACO" or "FOO"
    /// assert!(!blocklist.contains_match(&id.data_string()));
    /// ```
    #[cfg(feature = "filter")]
    pub fn new_v0_filtered(blocklist: &filter::Blocklist) -> Result<Self, filter::FilterError> {
        // Start from max(current_time, last_safe_timestamp) to avoid re-discovering bad windows
        let mut timestamp = blocklist.get_starting_timestamp();

        for _ in 0..filter::MAX_V0_ITERATIONS {
            let random: u64 = rand::random();
            let id = Self::new_v0_with_parts(timestamp, random);
            let data = id.data_string();

            match filter::find_first_match(blocklist, &data) {
                None => {
                    // Record this timestamp so future calls can skip past any bad windows we found
                    blocklist.record_safe_timestamp(timestamp);
                    return Ok(id);
                }
                Some((start, len)) => {
                    if !filter::match_touches_random_portion(start, len) {
                        // Match is entirely in timestamp portion
                        // Bump enough to change the rightmost char of the match
                        let rightmost_char = start + len - 1;
                        timestamp += filter::timestamp_bump_for_char(rightmost_char);
                    }
                    // Otherwise just loop to regenerate random
                }
            }
        }

        Err(filter::FilterError::MaxIterationsExceeded {
            iterations: filter::MAX_V0_ITERATIONS,
        })
    }

    /// Generates a new V1 TNID with no blocklist matches in its data string.
    ///
    /// This function generates high-entropy TNIDs (like [`Self::new_v1`]) while ensuring
    /// the encoded data portion doesn't contain any words from the blocklist.
    ///
    /// Since V1 TNIDs are entirely random (100 bits of entropy), the algorithm simply
    /// regenerates until a clean ID is found.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError::MaxIterationsExceeded`] if unable to generate a clean ID
    /// after many attempts. This is extremely unlikely with a reasonable blocklist.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    /// use tnid::filter::Blocklist;
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let blocklist = Blocklist::new(&["TACO", "FOO"]);
    /// let id = Tnid::<User>::new_v1_filtered(&blocklist).unwrap();
    ///
    /// // The data portion won't contain "TACO" or "FOO"
    /// assert!(!blocklist.contains_match(&id.data_string()));
    /// ```
    #[cfg(feature = "filter")]
    pub fn new_v1_filtered(blocklist: &filter::Blocklist) -> Result<Self, filter::FilterError> {
        for _ in 0..filter::MAX_V1_ITERATIONS {
            let id = Self::new_v1();
            let data = id.data_string();

            if !blocklist.contains_match(&data) {
                return Ok(id);
            }
        }

        Err(filter::FilterError::MaxIterationsExceeded {
            iterations: filter::MAX_V1_ITERATIONS,
        })
    }

    /// Generates a V0 TNID where both the V0 and its encrypted V1 are clean.
    ///
    /// This is useful when you store V0 TNIDs internally (for time-ordering benefits)
    /// but expose encrypted V1 TNIDs externally (to hide timestamps). This function
    /// ensures neither form contains blocklisted words.
    ///
    /// # Algorithm
    ///
    /// 1. Generate a V0 TNID with the current timestamp and random bits
    /// 2. Encrypt to V1
    /// 3. Check both data strings for blocklist matches
    /// 4. If V0 has a match in the timestamp portion: bump timestamp
    /// 5. If either has a match in the random portion: regenerate random
    /// 6. Repeat until both are clean or max iterations reached
    ///
    /// # Errors
    ///
    /// Returns [`FilterError::MaxIterationsExceeded`] if unable to generate a clean ID
    /// after many attempts, or [`FilterError::EncryptionError`] if encryption fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    /// use tnid::encryption::EncryptionKey;
    /// use tnid::filter::Blocklist;
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let key = EncryptionKey::new([1u8; 16]);
    /// let blocklist = Blocklist::new(&["TACO", "FOO"]);
    /// let v0 = Tnid::<User>::new_v0_filtered_for_encryption(&key, &blocklist).unwrap();
    ///
    /// // Both V0 and encrypted V1 are clean
    /// assert!(!blocklist.contains_match(&v0.data_string()));
    /// let v1 = v0.encrypt_v0_to_v1(&key).unwrap();
    /// assert!(!blocklist.contains_match(&v1.data_string()));
    /// ```
    #[cfg(all(feature = "filter", feature = "encryption"))]
    pub fn new_v0_filtered_for_encryption(
        key: &encryption::EncryptionKey,
        blocklist: &filter::Blocklist,
    ) -> Result<Self, filter::FilterError> {
        // Start from max(current_time, last_safe_timestamp) to avoid re-discovering bad windows
        let mut timestamp = blocklist.get_starting_timestamp();

        for _ in 0..filter::MAX_ENCRYPTION_ITERATIONS {
            let random: u64 = rand::random();
            let v0 = Self::new_v0_with_parts(timestamp, random);
            let v0_data = v0.data_string();

            // Check V0 first
            if let Some((start, len)) = filter::find_first_match(blocklist, &v0_data) {
                if !filter::match_touches_random_portion(start, len) {
                    // Match is entirely in V0's timestamp portion, must bump
                    let rightmost_char = start + len - 1;
                    timestamp += filter::timestamp_bump_for_char(rightmost_char);
                }
                // Otherwise regenerate random (continue loop)
                continue;
            }

            // V0 is clean, now check encrypted V1
            let v1 = v0.encrypt_v0_to_v1(key)?;
            let v1_data = v1.data_string();

            if !blocklist.contains_match(&v1_data) {
                // Both are clean!
                blocklist.record_safe_timestamp(timestamp);
                return Ok(v0);
            }
            // V1 has a match - since V1 is all random-looking after encryption,
            // regenerating the V0's random bits will produce a completely different V1
            // (continue loop)
        }

        Err(filter::FilterError::MaxIterationsExceeded {
            iterations: filter::MAX_ENCRYPTION_ITERATIONS,
        })
    }
}

/// Internal functions exposed for advanced usage behind the `internals` feature.
///
/// These functions are not part of the stable public API and provide low-level access
/// to TNID bit manipulation and encoding.
#[cfg(feature = "internals")]
#[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
pub mod internals {
    pub use crate::data_encoding::{
        expand_data_bits, extract_data_bits, id_data_to_string, string_to_id_data,
        CHAR_BIT_LENGTH as DATA_CHAR_BIT_LENGTH, CHAR_MAPPING as DATA_CHAR_MAPPING, DATA_BIT_NUM,
        DATA_CHAR_ENCODING_LEN, LEFT_DATA_SECTION_MASK, MIDDLE_DATA_SECTION_MASK,
        RIGHT_DATA_SECTION_MASK,
    };
    #[cfg(feature = "encryption")]
    pub use crate::encryption::{
        decrypt, decrypt_id_v1_to_v0, encrypt, encrypt_id_v0_to_v1, expand_secret_data_bits,
        extract_secret_data_bits, COMPLETE_SECRET_DATA_MASK, LEFT_SECRET_DATA_SECTION_MASK,
        MIDDLE_SECRET_DATA_SECTION_MASK, RIGHT_SECRET_DATA_SECTION_MASK,
    };
    pub use crate::name_encoding::{
        extract_name_string, name_bits_to_hex, name_mask, validate_name_bits,
        CHAR_BIT_LENGTH as NAME_CHAR_BIT_LENGTH, CHAR_MAPPING as NAME_CHAR_MAPPING,
        CHAR_MASK as NAME_CHAR_MASK, NAME_MAX_CHARS, NAME_MIN_CHARS, NON_NAME_BITS,
    };
    pub use crate::utils::{
        change_variant, hex_char_to_nibble, u128_to_uuid_string, uuid_and_variant_mask,
        UUID_V8_MASK,
    };
    pub use crate::v0::{
        make_from_parts as v0_make_from_parts, millis_mask as v0_millis_mask,
        random_bits_mask as v0_random_bits_mask, RANDOM_MASK as V0_RANDOM_MASK,
        TIMESTAMP_FIRST_28_MASK as V0_TIMESTAMP_FIRST_28_MASK,
        TIMESTAMP_LAST_3_MASK as V0_TIMESTAMP_LAST_3_MASK,
        TIMESTAMP_SECOND_12_MASK as V0_TIMESTAMP_SECOND_12_MASK,
    };
    pub use crate::v1::{
        make_from_parts as v1_make_from_parts, random_bits_mask as v1_random_bits_mask,
        RANDOM_MASK as V1_RANDOM_MASK,
    };
}

impl<Name: TnidName> std::fmt::Display for Tnid<Name> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_tnid_string())
    }
}

impl<Name: TnidName> std::fmt::Debug for Tnid<Name> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_tnid_string())
    }
}

impl<Name: TnidName> std::str::FromStr for Tnid<Name> {
    type Err = ParseTnidError;

    /// Parses a TNID from either TNID string format or UUID hex format (auto-detected).
    ///
    /// # Format Detection
    ///
    /// - Strings of 19-22 characters containing a `.` are parsed as TNID strings
    /// - Strings of exactly 36 characters are parsed as UUID hex strings
    /// - Other lengths return an error
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{Tnid, TnidName, NameStr};
    ///
    /// struct User;
    /// impl TnidName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// // Parse TNID string format
    /// let id: Tnid<User> = "user.Br2flcNDfF6LYICnT".parse().unwrap();
    ///
    /// // Parse UUID hex format
    /// let id: Tnid<User> = "d6157329-4640-8e30-9f8a-b5c7d2e1f0a3".parse().unwrap();
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const MIN_TNID_LEN: usize =
            name_encoding::NAME_MIN_CHARS + 1 + data_encoding::DATA_CHAR_ENCODING_LEN as usize;
        const MAX_TNID_LEN: usize =
            name_encoding::NAME_MAX_CHARS + 1 + data_encoding::DATA_CHAR_ENCODING_LEN as usize;
        const UUID_LEN: usize = 36;

        match s.len() {
            MIN_TNID_LEN..=MAX_TNID_LEN if s.contains('.') => Self::parse_tnid_string(s),
            UUID_LEN => Self::parse_uuid_string(s),
            len => Err(ParseTnidError::InvalidLength(len)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestId;
    impl TnidName for TestId {
        const ID_NAME: NameStr<'static> = NameStr::new_const("test");
    }

    #[test]
    fn variant0_is_k_sortable() {
        let mut epoch_ms: u64 = 1_700_000_000_000;
        let random: u64 = 42;

        let mut last_id: Tnid<TestId> = Tnid::new_v0_with_parts(epoch_ms, random);

        for _ in 1..10_000 {
            epoch_ms += 1;
            let id: Tnid<TestId> = Tnid::new_v0_with_parts(epoch_ms, random);

            assert!(last_id.as_u128() < id.as_u128());
            assert!(last_id.to_tnid_string() < id.to_tnid_string());

            last_id = id;
        }
    }

    #[test]
    fn tnid_variant_returns_v0() {
        let id: Tnid<TestId> = Tnid::new_v0_with_parts(1_700_000_000_000, 42);
        assert_eq!(id.variant(), TnidVariant::V0);
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn encryption_bidirectional() {
        let key = encryption::EncryptionKey::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Use the featureless constructor so this test doesn't require `time`/`rand`.
        let original: Tnid<TestId> = Tnid::new_v0_with_parts(1_700_000_000_000, 42);
        assert_eq!(original.variant(), TnidVariant::V0);

        let encrypted = original
            .encrypt_v0_to_v1(&key)
            .expect("encryption should succeed");
        assert_eq!(encrypted.variant(), TnidVariant::V1);

        dbg!(encrypted, original);

        let decrypted = encrypted
            .decrypt_v1_to_v0(&key)
            .expect("decryption should succeed");
        assert_eq!(decrypted.variant(), TnidVariant::V0);

        assert_eq!(decrypted.as_u128(), original.as_u128());
    }

    #[test]
    fn parse_tnid_string_roundtrip() {
        let original: Tnid<TestId> = Tnid::new_v0_with_parts(1_700_000_000_000, 42);
        let tnid_string = original.to_tnid_string();
        let parsed = Tnid::<TestId>::parse_tnid_string(&tnid_string)
            .expect("generated TNID string should parse");
        assert_eq!(parsed.as_u128(), original.as_u128());
    }

    #[test]
    fn parse_tnid_string_invalid_name() {
        let result = Tnid::<TestId>::parse_tnid_string("wrong.abc123xyz");
        assert!(result.is_err());
    }

    #[test]
    fn parse_tnid_string_no_separator() {
        let result = Tnid::<TestId>::parse_tnid_string("testabc123xyz");
        assert!(result.is_err());
    }

    #[test]
    fn from_u128_malformed_name_bits_returns_invalid_name_bits() {
        // Construct a u128 with malformed name bits: non-null after null
        // Name encoding: each char is 5 bits in top 20 bits (bits 127-108)
        // Pattern: [a, 0, b, c] where a=6, 0=null, b=7, c=8
        // This is invalid because there's a non-null after a null
        let a: u128 = 6; // 'a' encoding
        let b: u128 = 7; // 'b' encoding
        let c: u128 = 8; // 'c' encoding

        // Build name bits: [a, 0, b, c] from high to low
        // Bit positions: char0 at bits 127-123, char1 at 122-118, char2 at 117-113, char3 at 112-108
        // Note: char1 is 0 (null), so we omit it from the OR expression
        let name_bits = (a << 123) | (b << 113) | (c << 108);

        // Add valid UUIDv8 bits
        let id = name_bits | utils::UUID_V8_MASK;

        let result = Tnid::<TestId>::from_u128(id);
        assert!(
            matches!(result, Err(ParseTnidError::InvalidNameBits)),
            "expected InvalidNameBits, got {:?}",
            result
        );
    }

    #[test]
    fn from_u128_name_mismatch_returns_name_mismatch() {
        // Construct a u128 with well-formed name bits that don't match TestId ("test")
        // Use name "user" which encodes as: u=26, s=24, e=10, r=23
        let u: u128 = 26; // 'u' encoding
        let s: u128 = 24; // 's' encoding
        let e: u128 = 10; // 'e' encoding
        let r: u128 = 23; // 'r' encoding

        // Build name bits for "user"
        let name_bits = (u << 123) | (s << 118) | (e << 113) | (r << 108);

        // Add valid UUIDv8 bits
        let id = name_bits | utils::UUID_V8_MASK;

        let result = Tnid::<TestId>::from_u128(id);
        match result {
            Err(ParseTnidError::NameMismatch { expected, found }) => {
                assert_eq!(expected, "test");
                assert_eq!(found, "user");
            }
            other => panic!("expected NameMismatch, got {:?}", other),
        }
    }

    #[test]
    fn from_u128_empty_name_bits_returns_invalid_name_bits() {
        // Construct a u128 with empty name bits (all nulls in name area)
        // This is invalid because names must have at least 1 character
        let name_bits: u128 = 0; // All zeros = all nulls

        // Add valid UUIDv8 bits
        let id = name_bits | utils::UUID_V8_MASK;

        let result = Tnid::<TestId>::from_u128(id);
        assert!(
            matches!(result, Err(ParseTnidError::InvalidNameBits)),
            "expected InvalidNameBits, got {:?}",
            result
        );
    }

    #[cfg(all(feature = "time", feature = "rand"))]
    #[test]
    fn new_v0_with_time_pre_epoch_wraps() {
        use time::OffsetDateTime;

        // A date before the Unix epoch (1969-07-20, Apollo 11 landing)
        // -14182980 seconds = July 20, 1969 20:17:00 UTC
        let pre_epoch =
            OffsetDateTime::from_unix_timestamp(-14182980).expect("valid unix timestamp");

        // This should not panic - it wraps the negative value
        let id: Tnid<TestId> = Tnid::new_v0_with_time(pre_epoch);

        // The ID should be valid and have the correct name
        assert_eq!(id.name(), "test");

        // The wrapped timestamp will produce a large value, making this ID
        // sort after IDs with normal timestamps (this is the documented behavior)
        let normal_time =
            OffsetDateTime::from_unix_timestamp(1704067200).expect("valid unix timestamp"); // 2024-01-01
        let normal_id: Tnid<TestId> = Tnid::new_v0_with_time(normal_time);

        // Pre-epoch wraps to a large positive value, so it sorts AFTER normal times
        assert!(
            id.as_u128() > normal_id.as_u128(),
            "pre-epoch ID should sort after normal ID due to wrapping"
        );
    }

    #[cfg(feature = "filter")]
    #[test]
    fn new_v0_filtered_produces_clean_ids() {
        let blocklist = filter::Blocklist::new(&["TACO", "FOO", "BAR"]);

        for _ in 0..100 {
            let id = Tnid::<TestId>::new_v0_filtered(&blocklist).unwrap();
            let data = id.data_string();
            assert!(
                !blocklist.contains_match(&data),
                "filtered ID should not contain blocklist words: {data}"
            );
        }
    }

    #[cfg(feature = "filter")]
    #[test]
    fn new_v1_filtered_produces_clean_ids() {
        let blocklist = filter::Blocklist::new(&["TACO", "FOO", "BAR"]);

        for _ in 0..100 {
            let id = Tnid::<TestId>::new_v1_filtered(&blocklist).unwrap();
            let data = id.data_string();
            assert!(
                !blocklist.contains_match(&data),
                "filtered ID should not contain blocklist words: {data}"
            );
        }
    }

    #[cfg(all(feature = "filter", feature = "encryption"))]
    #[test]
    fn new_v0_filtered_for_encryption_produces_clean_ids() {
        let key = encryption::EncryptionKey::new([1u8; 16]);
        let blocklist = filter::Blocklist::new(&["TACO", "FOO", "BAR"]);

        for _ in 0..50 {
            let v0 = Tnid::<TestId>::new_v0_filtered_for_encryption(&key, &blocklist).unwrap();
            let v0_data = v0.data_string();
            assert!(
                !blocklist.contains_match(&v0_data),
                "V0 should not contain blocklist words: {v0_data}"
            );

            let v1 = v0.encrypt_v0_to_v1(&key).unwrap();
            let v1_data = v1.data_string();
            assert!(
                !blocklist.contains_match(&v1_data),
                "encrypted V1 should not contain blocklist words: {v1_data}"
            );
        }
    }

    #[cfg(feature = "filter")]
    #[test]
    fn filtered_with_empty_blocklist_succeeds() {
        let blocklist = filter::Blocklist::new::<&str>(&[]);

        let v0 = Tnid::<TestId>::new_v0_filtered(&blocklist);
        assert!(v0.is_ok());

        let v1 = Tnid::<TestId>::new_v1_filtered(&blocklist);
        assert!(v1.is_ok());
    }

    #[cfg(feature = "filter")]
    #[test]
    fn data_string_returns_17_chars() {
        let id: Tnid<TestId> = Tnid::new_v0_with_parts(1_700_000_000_000, 42);
        let data = id.data_string();
        assert_eq!(data.len(), 17);
    }
}
