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
/// The string you set as `ID_NAME` is checked to be a valid TNID name at compile time (as long as you actually use the )
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

/// The base TNID type
///
/// Makes use of the [`TNIDName`] trait for static checking of the different names
///
/// In general, TNIDs try to be relatively strict about how they can be used and represented at compile time. That means that any given instance of a TNID *should* be valid. In cases where you want to work with or inspect potentially invalid TNIDs, use a [`UUIDLike`].
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
    pub fn name(&self) -> &'static str {
        Name::ID_NAME.as_str()
    }

    /// The TNID name when the
    /// bytes are encoded using hex, like they commonly are for UUIDs.
    pub fn name_hex(&self) -> String {
        let hex = format!("{:05x}", self.id >> 108);

        debug_assert_eq!(hex.len(), 5);

        hex
    }

    pub fn as_u128(&self) -> u128 {
        self.id
    }

    /// Same as [`Self::new_v0`], just a more friendly name
    pub fn new_time_ordered() -> Self {
        Self::new_v0()
    }

    /// Generates a new v0 TNID
    ///
    /// This variant focuses on time sortability, similar to UUIDv7
    #[cfg(feature = "time")]
    pub fn new_v0() -> Self {
        Self::new_v0_with_time(time::OffsetDateTime::now_utc())
    }

    /// Same as [`Self::new_v1`], just a more friendly name
    #[cfg(feature = "rand")]
    pub fn new_high_entropy() -> Self {
        Self::new_v1()
    }

    /// Generates a new v1 TNID
    ///
    /// This variant focuses on maximizing entropy, similar to UUIDv4
    #[cfg(feature = "rand")]
    pub fn new_v1() -> Self {
        Self::new_v1_with_random(rand::random())
    }

    /// Generates a new v1 TNID with provided randomness
    ///
    /// This really only needs 100 random bits, but getting a whole 128 is easier
    pub fn new_v1_with_random(random_bits: u128) -> Self {
        let id_name = Name::ID_NAME;

        let id = v1::make_from_parts(id_name, random_bits);

        Self {
            id_name: PhantomData,
            id,
        }
    }

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

    pub fn new_v0_with_parts(epoch_millis: u64, random: u64) -> Self {
        Self {
            id_name: PhantomData,
            id: v0::make_from_parts(Name::ID_NAME, epoch_millis, random),
        }
    }

    pub fn as_tnid_string(&self) -> String {
        format!(
            "{}.{}",
            self.name(),
            data_encoding::id_data_to_string(self.id)
        )
    }

    /// Gets the TNID variant
    pub fn variant(&self) -> TNIDVariant {
        let variant_bits = (self.id >> 60) as u8;

        TNIDVariant::from_u8(variant_bits)
    }

    /// Convert to UUID hex string format with specified case
    pub fn to_uuid_string_cased(&self, uppercase: bool) -> String {
        UUIDLike::new(self.id).to_uuid_string_cased(uppercase)
    }

    /// Parse a UUID hex string into a TNID
    pub fn parse_uuid_string(uuid_string: &str) -> Option<Self> {
        let id = UUIDLike::parse_uuid_string(uuid_string)?.as_u128();

        Self::from_u128(id)
    }

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

    pub fn from_u128(num: u128) -> Option<Self> {
        // check UUIDv8 version and variant bits
        if (num & utils::UUID_V8_MASK) != utils::UUID_V8_MASK {
            return None;
        }

        // check name encoding matches expected name
        let name_bits_mask = 0xFFFFF_u128 << 108; // top 20 bits
        let actual_name_bits = num & name_bits_mask;
        let expected_name_bits = name_encoding::name_mask(Name::ID_NAME);
        if actual_name_bits != expected_name_bits {
            return None;
        }

        Some(Self {
            id: num,
            id_name: PhantomData,
        })
    }

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
