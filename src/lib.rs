#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::indexing_slicing)]
#![deny(rustdoc::broken_intra_doc_links)]

// todo
// #![warn(missing_docs)]

use std::marker::PhantomData;

mod data_encoding;
#[cfg(feature = "encryption")]
mod encryption;
mod name_encoding;
mod tnid_variant;
mod utils;
#[cfg(feature = "uuid")]
mod uuid;
mod uuidlike;
mod v0;
mod v1;

pub use name_encoding::NameStr;
pub use tnid_variant::TNIDVariant;
pub use uuidlike::UUIDLike;

/// Intended to be used on empty structs to create type checked TNID names.
///
/// ```rust
/// # use tnid::TNIDName;
/// # use tnid::TNID;
/// # use tnid::NameStr;
///
/// struct ExampleName;
/// impl TNIDName for ExampleName {
///     const ID_NAME: NameStr<'static> = NameStr::new_const("exna");
/// }
///
/// # let _ = TNID::<ExampleName>::new_v0();
/// ```
///
/// [`NameStr::new_const`] validates the name at compile time and is the only way to create
/// a `NameStr<'static>`, ensuring all [`TNID`] names are valid.
/// ```rust,compile_fail
/// # use tnid::TNIDName;
/// # use tnid::TNID;
/// # use tnid::NameStr;
///
/// struct InvalidName;
/// impl TNIDName for InvalidName {
///     const ID_NAME: NameStr<'static> = NameStr::new_const("2long");
/// }
///
/// # let _ = TNID::<InvalidName>::new_v0();
/// ```
pub trait TNIDName {
    /// Must be overridden with the name of your ID
    const ID_NAME: NameStr<'static>;
}

/// A type-safe TNID parameterized by name.
///
/// The type parameter uses the [`TNIDName`] trait to enforce compile-time checking of names.
/// `TNID<User>` and `TNID<Post>` are distinct types that cannot be mixed.
///
/// All validation happens at construction time, so any `TNID<Name>` instance is guaranteed
/// to be valid. If you need to work with potentially invalid 128-bit values, use [`UUIDLike`]
/// for inspection without validation.
#[derive(PartialEq, Eq)]
pub struct TNID<Name: TNIDName> {
    id_name: PhantomData<Name>,
    id: u128,
}

impl<Name: TNIDName> Copy for TNID<Name> {}

impl<Name: TNIDName> Clone for TNID<Name> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Name: TNIDName> TNID<Name> {
    /// Returns the name associated with this TNID type.
    ///
    /// The name comes from the [`TNIDName`] implementation for this type and is
    /// used in the TNID string representation (`<name>.<data>`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{TNID, TNIDName, NameStr};
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let id = TNID::<User>::new_v0();
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
    /// use tnid::{TNID, TNIDName, NameStr};
    ///
    /// struct Test;
    /// impl TNIDName for Test {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("test");
    /// }
    ///
    /// // Check what "test" looks like in hex (any TNID instance works)
    /// let id = TNID::<Test>::new_v1();
    /// assert_eq!(id.name_hex(), "cab19");
    /// ```
    pub fn name_hex(&self) -> String {
        let hex = format!("{:05x}", self.id >> 108);

        debug_assert_eq!(hex.len(), 5);

        hex
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
    /// use tnid::{TNID, TNIDName, NameStr};
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let id = TNID::<User>::new_v0();
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
    #[cfg(feature = "time")]
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
    /// use tnid::{TNID, TNIDName, NameStr};
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let id = TNID::<User>::new_high_entropy();
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
    /// use tnid::{TNID, TNIDName, NameStr};
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// // Provide your own randomness
    /// let random_bits = 0x0123456789ABCDEF0123456789ABCDEF;
    ///
    /// let id = TNID::<User>::new_v1_with_random(random_bits);
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
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{TNID, TNIDName, NameStr};
    /// use time::OffsetDateTime;
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let timestamp = OffsetDateTime::now_utc();
    /// let id = TNID::<User>::new_v0_with_time(timestamp);
    /// ```
    ///
    /// Demonstrating time-based sorting:
    /// ```rust
    /// use tnid::{TNID, TNIDName, NameStr};
    /// use time::{OffsetDateTime, Duration};
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let now = OffsetDateTime::now_utc();
    /// let earlier = now - Duration::hours(1);
    /// let later = now + Duration::hours(1);
    ///
    /// let id1 = TNID::<User>::new_v0_with_time(earlier);
    /// let id2 = TNID::<User>::new_v0_with_time(now);
    /// let id3 = TNID::<User>::new_v0_with_time(later);
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
    /// use tnid::{TNID, TNIDName, NameStr};
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// // Provide your own timestamp and randomness
    /// let timestamp_ms = 1750118400000;
    /// let random_bits = 42;
    ///
    /// let id = TNID::<User>::new_v0_with_parts(timestamp_ms, random_bits);
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
    /// use tnid::{TNID, TNIDName, NameStr};
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let id = TNID::<User>::new_v0();
    /// let tnid_string = id.as_tnid_string();
    ///
    /// // Format: <name>.<encoded-data>
    /// // Example: "user.Br2flcNDfF6LYICnT"
    /// assert!(tnid_string.starts_with("user."));
    /// ```
    pub fn as_tnid_string(&self) -> String {
        format!(
            "{}.{}",
            self.name(),
            data_encoding::id_data_to_string(self.id)
        )
    }

    /// Returns the TNID variant.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{TNID, TNIDName, NameStr, TNIDVariant};
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let id_v0 = TNID::<User>::new_v0();
    /// assert_eq!(id_v0.variant(), TNIDVariant::V0);
    ///
    /// let id_v1 = TNID::<User>::new_v1();
    /// assert_eq!(id_v1.variant(), TNIDVariant::V1);
    /// ```
    pub fn variant(&self) -> TNIDVariant {
        let variant_bits = (self.id >> 60) as u8;

        TNIDVariant::from_u8(variant_bits)
    }

    /// Converts the TNID to UUID hex string format.
    ///
    /// This is useful for UUID compatibility and interoperability with systems that expect
    /// standard UUID format, or any other case where you need the common UUID hex representation.
    ///
    /// # Parameters
    ///
    /// - `uppercase`: If `true`, uses uppercase hex digits (A-F). If `false`, uses lowercase (a-f).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{TNID, TNIDName, NameStr};
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let id = TNID::<User>::new_v1();
    ///
    /// let uuid_lower = id.to_uuid_string_cased(false);
    /// // "cab1952a-f09d-86d9-928e-96ea03dc6af3"
    ///
    /// let uuid_upper = id.to_uuid_string_cased(true);
    /// // "CAB1952A-F09D-86D9-928E-96EA03DC6AF3"
    /// ```
    pub fn to_uuid_string_cased(&self, uppercase: bool) -> String {
        UUIDLike::new(self.id).to_uuid_string_cased(uppercase)
    }

    /// Parses a TNID from UUID hex string format.
    ///
    /// This is the inverse of [`Self::to_uuid_string_cased`].
    ///
    /// The parser accepts both uppercase and lowercase hex digits (A-F or a-f).
    ///
    /// Returns `None` if:
    /// - The string is not valid UUID format
    /// - The UUID is not a valid TNID (wrong version/variant bits or name mismatch)
    ///
    /// For inspecting why a UUID might not be a valid TNID, see [`UUIDLike`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{TNID, TNIDName, NameStr};
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// // Create a TNID and convert to UUID string
    /// let original = TNID::<User>::new_v1();
    /// let uuid_string = original.to_uuid_string_cased(false);
    ///
    /// // Parse it back
    /// let parsed = TNID::<User>::parse_uuid_string(&uuid_string);
    /// assert!(parsed.is_some());
    /// assert_eq!(parsed.unwrap().as_u128(), original.as_u128());
    ///
    /// // Also accepts uppercase
    /// let uuid_upper = original.to_uuid_string_cased(true);
    /// let parsed_upper = TNID::<User>::parse_uuid_string(&uuid_upper);
    /// assert!(parsed_upper.is_some());
    ///
    /// // Invalid: not a valid UUID format
    /// assert!(TNID::<User>::parse_uuid_string("not-a-uuid").is_none());
    /// ```
    pub fn parse_uuid_string(uuid_string: &str) -> Option<Self> {
        let id = UUIDLike::parse_uuid_string(uuid_string)?.as_u128();

        Self::from_u128(id)
    }

    /// Parses a TNID from its string representation.
    ///
    /// This is the inverse of [`Self::as_tnid_string`]. See that method for details
    /// on the TNID string format.
    ///
    /// Returns `None` if the string is invalid. Validation includes:
    /// - Correct format (`<name>.<encoded-data>`)
    /// - Name matches the expected name for this TNID type
    /// - Valid TNID Data Encoding
    /// - Correct UUIDv8 version and variant bits
    ///
    /// If you need to inspect non-compliant IDs or understand why parsing failed,
    /// consider using [`UUIDLike`] which provides lower-level access.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{TNID, TNIDName, NameStr};
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// // Successful parsing
    /// let parsed = TNID::<User>::parse_tnid_string("user.Br2flcNDfF6LYICnT");
    /// assert!(parsed.is_some());
    ///
    /// // Failed parsing - wrong name
    /// assert!(TNID::<User>::parse_tnid_string("post.Br2flcNDfF6LYICnT").is_none());
    ///
    /// // Failed parsing - invalid format
    /// assert!(TNID::<User>::parse_tnid_string("not-a-tnid").is_none());
    /// ```
    pub fn parse_tnid_string(tnid_string: &str) -> Option<Self> {
        // Split on dot separator
        let (name, data_str) = tnid_string.split_once('.')?;

        // Validate name matches expected name
        if name != Name::ID_NAME.as_str() {
            return None;
        }

        // Decode data string to compact 102 bits
        let compact_data = data_encoding::string_to_id_data(data_str)?;

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
    /// Returns `None` if the value is not a valid TNID. Validation includes:
    /// - Correct UUIDv8 version and variant bits
    /// - Name encoding matches the expected name for this TNID type
    ///
    /// # Endianness
    ///
    /// When loading from bytes, you'll almost certainly want to parse a `[u8; 16]` to a
    /// `u128` using big-endian byte order with [`u128::from_be_bytes()`], as per the
    /// UUID specification.
    pub fn from_u128(id: u128) -> Option<Self> {
        // check UUIDv8 version and variant bits
        if (id & utils::UUID_V8_MASK) != utils::UUID_V8_MASK {
            return None;
        }

        // check name encoding matches expected name
        let name_bits_mask = 0xFFFFF_u128 << 108; // top 20 bits
        let actual_name_bits = id & name_bits_mask;
        let expected_name_bits = name_encoding::name_mask(Name::ID_NAME);
        if actual_name_bits != expected_name_bits {
            return None;
        }

        Some(Self {
            id,
            id_name: PhantomData,
        })
    }

    /// Encrypts a V0 TNID to a V1 TNID using AES-128.
    ///
    /// This encrypts the data bits while preserving the name. The encrypted TNID will be
    /// a valid V1 variant, hiding the timestamp information present in V0. The encryption
    /// is reversible with [`Self::decrypt_v1_to_v0`] using the same secret.
    ///
    /// V0 TNIDs expose when they were created (like UUIDv7), which may not be desirable
    /// when TNIDs are public. Encrypting to V1 produces a valid high-entropy V1 TNID
    /// while remaining decryptable on the backend.
    ///
    /// # Parameters
    ///
    /// - `secret`: 128-bit (16 bytes) encryption key
    ///
    /// # Behavior by Input TNID Variant
    ///
    /// - **V0**: Encrypts data bits and converts to V1
    /// - **V1**: Returns the TNID unchanged (already V1)
    /// - **V2/V3**: Returns `Err(())` (unsupported variants)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{TNID, TNIDName, NameStr, TNIDVariant};
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let secret = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    ///
    /// let original = TNID::<User>::new_v0();
    /// assert_eq!(original.variant(), TNIDVariant::V0);
    ///
    /// // Encrypt V0 to V1
    /// let encrypted = original.encrypt_v0_to_v1(secret).unwrap();
    /// assert_eq!(encrypted.variant(), TNIDVariant::V1);
    ///
    /// // Decrypt back to V0
    /// let decrypted = encrypted.decrypt_v1_to_v0(secret).unwrap();
    /// assert_eq!(decrypted.variant(), TNIDVariant::V0);
    /// assert_eq!(decrypted.as_u128(), original.as_u128());
    /// ```
    #[cfg(feature = "encryption")]
    pub fn encrypt_v0_to_v1(&self, secret: [u8; 16]) -> Result<Self, ()> {
        match self.variant() {
            TNIDVariant::V0 => {}
            TNIDVariant::V1 => return Ok(*self),
            TNIDVariant::V2 => return Err(()),
            TNIDVariant::V3 => return Err(()),
        }

        // Extract only the secret data bits (100 bits, excludes TNID variant)
        let secret_data = encryption::extract_secret_data_bits(self.id);

        // Encrypt the secret data
        let encrypted_data = encryption::encrypt(secret_data, &secret);

        // Expand back to proper bit positions
        let expanded = encryption::expand_secret_data_bits(encrypted_data);

        // Preserve name and UUID metadata, replace data bits with encrypted version
        let id = (self.id & !encryption::COMPLETE_SECRET_DATA_MASK) | expanded;

        // Change variant from V0 to V1
        let id = utils::change_variant(id, TNIDVariant::V1);

        Ok(Self {
            id_name: PhantomData,
            id,
        })
    }

    /// Decrypts a V1 TNID to a V0 TNID using AES-128.
    ///
    /// This is the inverse of [`Self::encrypt_v0_to_v1`]. It decrypts the data bits while
    /// preserving the name, converting a V1 TNID back to V0 to recover the original ID.
    ///
    /// # Parameters
    ///
    /// - `secret`: 128-bit (16 bytes) encryption key (must match the key used for encryption)
    ///
    /// # Behavior by Input TNID Variant
    ///
    /// - **V0**: Returns the TNID unchanged (already V0)
    /// - **V1**: Decrypts data bits and converts to V0
    /// - **V2/V3**: Returns `Err(())` (unsupported variants)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::{TNID, TNIDName, NameStr, TNIDVariant};
    ///
    /// struct User;
    /// impl TNIDName for User {
    ///     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    /// }
    ///
    /// let secret = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    ///
    /// let original = TNID::<User>::new_v0();
    /// let encrypted = original.encrypt_v0_to_v1(secret).unwrap();
    ///
    /// // Decrypt back to V0
    /// let decrypted = encrypted.decrypt_v1_to_v0(secret).unwrap();
    /// assert_eq!(decrypted.variant(), TNIDVariant::V0);
    /// assert_eq!(decrypted.as_u128(), original.as_u128());
    /// ```
    #[cfg(feature = "encryption")]
    pub fn decrypt_v1_to_v0(&self, secret: [u8; 16]) -> Result<Self, ()> {
        match self.variant() {
            TNIDVariant::V0 => return Ok(*self),
            TNIDVariant::V1 => {}
            TNIDVariant::V2 => return Err(()),
            TNIDVariant::V3 => return Err(()),
        }

        // Extract only the secret data bits (100 bits, excludes TNID variant)
        let encrypted_data = encryption::extract_secret_data_bits(self.id);

        // Decrypt the secret data
        let decrypted_data = encryption::decrypt(encrypted_data, &secret);

        // Expand back to proper bit positions
        let expanded = encryption::expand_secret_data_bits(decrypted_data);

        // Preserve name and UUID metadata, replace data bits with decrypted version
        let id = (self.id & !encryption::COMPLETE_SECRET_DATA_MASK) | expanded;

        // Change variant from V1 to V0
        let id = utils::change_variant(id, TNIDVariant::V0);

        Ok(Self {
            id_name: PhantomData,
            id,
        })
    }
}

impl<Name: TNIDName> std::fmt::Display for TNID<Name> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_tnid_string())
    }
}

impl<Name: TNIDName> std::fmt::Debug for TNID<Name> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_tnid_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestId;
    impl TNIDName for TestId {
        const ID_NAME: NameStr<'static> = NameStr::new_const("test");
    }

    #[test]
    fn variant0_is_k_sortable() {
        use time::Duration;

        let mut test_time = time::OffsetDateTime::now_utc();
        let mut last_id: TNID<TestId> = TNID::new_v0_with_time(test_time);

        for _ in 1..10_000 {
            test_time += Duration::milliseconds(1);
            let id: TNID<TestId> = TNID::new_v0_with_time(test_time);

            assert!(last_id.as_u128() < id.as_u128());
            assert!(last_id.as_tnid_string() < id.as_tnid_string());

            last_id = id;
        }
    }

    #[test]
    fn tnid_variant_returns_v0() {
        let id: TNID<TestId> = TNID::new_v0();
        assert_eq!(id.variant(), TNIDVariant::V0);
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn encryption_bidirectional() {
        let secret = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let original: TNID<TestId> = TNID::new_v0();
        assert_eq!(original.variant(), TNIDVariant::V0);

        let encrypted = original.encrypt_v0_to_v1(secret).unwrap();
        assert_eq!(encrypted.variant(), TNIDVariant::V1);

        dbg!(encrypted, original);

        let decrypted = encrypted.decrypt_v1_to_v0(secret).unwrap();
        assert_eq!(decrypted.variant(), TNIDVariant::V0);

        assert_eq!(decrypted.as_u128(), original.as_u128());
    }

    #[test]
    fn parse_tnid_string_roundtrip() {
        let original: TNID<TestId> = TNID::new_v0();
        let tnid_string = original.as_tnid_string();
        let parsed = TNID::<TestId>::parse_tnid_string(&tnid_string).unwrap();
        assert_eq!(parsed.as_u128(), original.as_u128());
    }

    #[test]
    fn parse_tnid_string_invalid_name() {
        let result = TNID::<TestId>::parse_tnid_string("wrong.abc123xyz");
        assert!(result.is_none());
    }

    #[test]
    fn parse_tnid_string_no_separator() {
        let result = TNID::<TestId>::parse_tnid_string("testabc123xyz");
        assert!(result.is_none());
    }
}
