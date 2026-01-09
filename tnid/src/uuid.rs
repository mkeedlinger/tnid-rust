//! UUID interoperability for Tnid.
//!
//! This module provides conversions between Tnid and the `uuid` crate's `Uuid` type.
//! Since Tnids are UUIDv8-compatible by design, they can be freely converted to standard
//! UUIDs. Converting from UUID to Tnid is fallible since not all UUIDs are valid Tnids.
//!
//! # Examples
//!
//! ```rust
//! use tnid::{Tnid, TnidName, NameStr};
//!
//! struct User;
//! impl TnidName for User {
//!     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
//! }
//!
//! // Tnid to UUID (always succeeds)
//! let tnid = Tnid::<User>::new_v0();
//! let uuid: uuid::Uuid = tnid.into();
//!
//! // UUID to Tnid (may fail)
//! let tnid_back = Tnid::<User>::try_from(uuid).expect("should convert back");
//! assert_eq!(tnid.as_u128(), tnid_back.as_u128());
//! ```

use crate::{TnidName, Tnid};

/// Error type for conversion from `uuid::Uuid` to `Tnid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TnidFromUuidError {
    /// The UUID is not a valid Tnid (wrong version/variant or name encoding doesn't match).
    InvalidTnid,
}

impl std::fmt::Display for TnidFromUuidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TnidFromUuidError::InvalidTnid => {
                write!(f, "UUID is not a valid Tnid (wrong version/variant or name mismatch)")
            }
        }
    }
}

impl std::error::Error for TnidFromUuidError {}

/// Convert a Tnid to a `uuid::Uuid`.
///
/// This conversion is infallible because all Tnids are valid UUIDv8 identifiers by design.
impl<Name: TnidName> From<Tnid<Name>> for uuid::Uuid {
    fn from(tnid: Tnid<Name>) -> Self {
        uuid::Uuid::from_u128(tnid.as_u128())
    }
}

/// Attempt to convert a `uuid::Uuid` to a Tnid.
///
/// This conversion is fallible because not all UUIDs are valid Tnids:
/// - The UUID must be UUIDv8 (version 8)
/// - The UUID must have the correct variant bits (RFC4122)
/// - The name encoding in the top 20 bits must match the expected Tnid name type
impl<Name: TnidName> TryFrom<uuid::Uuid> for Tnid<Name> {
    type Error = TnidFromUuidError;

    fn try_from(uuid: uuid::Uuid) -> Result<Self, Self::Error> {
        let u128_val = uuid.as_u128();
        Tnid::<Name>::from_u128(u128_val).map_err(|_| TnidFromUuidError::InvalidTnid)
    }
}

#[cfg(all(test, feature = "time", feature = "rand"))]
mod tests {
    use super::*;
    use crate::NameStr;

    // Test helper types
    struct TestId;
    impl TnidName for TestId {
        const ID_NAME: NameStr<'static> = NameStr::new_const("test");
    }

    struct UserId;
    impl TnidName for UserId {
        const ID_NAME: NameStr<'static> = NameStr::new_const("user");
    }

    struct A;
    impl TnidName for A {
        const ID_NAME: NameStr<'static> = NameStr::new_const("a");
    }

    struct Zzzz;
    impl TnidName for Zzzz {
        const ID_NAME: NameStr<'static> = NameStr::new_const("zzzz");
    }

    // Round-trip conversion tests

    #[test]
    fn test_roundtrip_via_uuid_type_v0() {
        let tnid = Tnid::<TestId>::new_v0();
        let uuid: uuid::Uuid = tnid.into();
        let tnid_back: Tnid<TestId> = uuid.try_into().expect("should convert back");
        assert_eq!(tnid.as_u128(), tnid_back.as_u128());
    }

    #[test]
    fn test_roundtrip_via_uuid_type_v1() {
        let tnid = Tnid::<TestId>::new_v1();
        let uuid: uuid::Uuid = tnid.into();
        let tnid_back: Tnid<TestId> = uuid.try_into().expect("should convert back");
        assert_eq!(tnid.as_u128(), tnid_back.as_u128());
    }

    #[test]
    fn test_roundtrip_via_u128_v0() {
        let tnid = Tnid::<TestId>::new_v0();
        let uuid: uuid::Uuid = tnid.into();
        let u128_val = uuid.as_u128();
        let uuid2 = uuid::Uuid::from_u128(u128_val);
        let tnid_back: Tnid<TestId> = uuid2.try_into().expect("should convert back");
        assert_eq!(tnid.as_u128(), tnid_back.as_u128());
    }

    #[test]
    fn test_roundtrip_via_u128_v1() {
        let tnid = Tnid::<TestId>::new_v1();
        let uuid: uuid::Uuid = tnid.into();
        let u128_val = uuid.as_u128();
        let uuid2 = uuid::Uuid::from_u128(u128_val);
        let tnid_back: Tnid<TestId> = uuid2.try_into().expect("should convert back");
        assert_eq!(tnid.as_u128(), tnid_back.as_u128());
    }

    #[test]
    fn test_roundtrip_via_uuid_string_v0() {
        let tnid = Tnid::<TestId>::new_v0();
        let uuid: uuid::Uuid = tnid.into();
        let uuid_str = uuid.to_string();
        let uuid2: uuid::Uuid = uuid_str.parse().expect("should parse UUID string");
        let tnid_back: Tnid<TestId> = uuid2.try_into().expect("should convert back");
        assert_eq!(tnid.as_u128(), tnid_back.as_u128());
    }

    #[test]
    fn test_roundtrip_via_uuid_string_v1() {
        let tnid = Tnid::<TestId>::new_v1();
        let uuid: uuid::Uuid = tnid.into();
        let uuid_str = uuid.to_string();
        let uuid2: uuid::Uuid = uuid_str.parse().expect("should parse UUID string");
        let tnid_back: Tnid<TestId> = uuid2.try_into().expect("should convert back");
        assert_eq!(tnid.as_u128(), tnid_back.as_u128());
    }

    #[test]
    fn test_roundtrip_via_bytes_v0() {
        let tnid = Tnid::<TestId>::new_v0();
        let uuid: uuid::Uuid = tnid.into();
        let bytes = uuid.as_bytes();
        let uuid2 = uuid::Uuid::from_bytes(*bytes);
        let tnid_back: Tnid<TestId> = uuid2.try_into().expect("should convert back");
        assert_eq!(tnid.as_u128(), tnid_back.as_u128());
    }

    #[test]
    fn test_roundtrip_via_bytes_v1() {
        let tnid = Tnid::<TestId>::new_v1();
        let uuid: uuid::Uuid = tnid.into();
        let bytes = uuid.as_bytes();
        let uuid2 = uuid::Uuid::from_bytes(*bytes);
        let tnid_back: Tnid<TestId> = uuid2.try_into().expect("should convert back");
        assert_eq!(tnid.as_u128(), tnid_back.as_u128());
    }

    // UUIDv8 compliance tests

    #[test]
    fn test_tnid_converts_to_uuid_v8() {
        let tnid = Tnid::<TestId>::new_v0();
        let uuid: uuid::Uuid = tnid.into();
        // UUIDv8 has version number 8
        assert_eq!(uuid.get_version_num(), 8);
    }

    #[test]
    fn test_tnid_converts_to_rfc4122_variant() {
        let tnid = Tnid::<TestId>::new_v0();
        let uuid: uuid::Uuid = tnid.into();
        assert_eq!(uuid.get_variant(), uuid::Variant::RFC4122);
    }

    #[test]
    fn test_uuid_string_representation() {
        let tnid = Tnid::<TestId>::new_v0();
        let uuid: uuid::Uuid = tnid.into();

        // uuid crate produces lowercase hex by default
        let uuid_str = uuid.to_string();
        let tnid_uuid_str = tnid.to_uuid_string(false);

        assert_eq!(uuid_str, tnid_uuid_str);
    }

    // Failure case tests

    #[test]
    fn test_wrong_uuid_version_rejected() {
        // Create a UUIDv4 (random UUID)
        let uuid_v4 = uuid::Uuid::new_v4();

        // Verify it's actually v4
        assert_eq!(uuid_v4.get_version_num(), 4);

        // Should fail to convert to Tnid (wrong version)
        let result = Tnid::<TestId>::try_from(uuid_v4);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TnidFromUuidError::InvalidTnid);
    }

    #[test]
    fn test_invalid_name_encoding_rejected() {
        // Create a Tnid with "user" name
        let tnid_user = Tnid::<UserId>::new_v0();
        let uuid: uuid::Uuid = tnid_user.into();

        // Try to convert to Tnid with "test" name - should fail
        let result = Tnid::<TestId>::try_from(uuid);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TnidFromUuidError::InvalidTnid);
    }

    // Edge case tests

    #[test]
    fn test_different_name_lengths() {
        // Test 1-character name
        let tnid_a = Tnid::<A>::new_v0();
        let uuid_a: uuid::Uuid = tnid_a.into();
        let tnid_a_back: Tnid<A> = uuid_a.try_into().expect("1-char name should work");
        assert_eq!(tnid_a.as_u128(), tnid_a_back.as_u128());

        // Test 4-character name
        let tnid_zzzz = Tnid::<Zzzz>::new_v0();
        let uuid_zzzz: uuid::Uuid = tnid_zzzz.into();
        let tnid_zzzz_back: Tnid<Zzzz> =
            uuid_zzzz.try_into().expect("4-char name should work");
        assert_eq!(tnid_zzzz.as_u128(), tnid_zzzz_back.as_u128());

        // Test 4-character name (UserId = "user")
        let tnid_user = Tnid::<UserId>::new_v0();
        let uuid_user: uuid::Uuid = tnid_user.into();
        let tnid_user_back: Tnid<UserId> =
            uuid_user.try_into().expect("4-char name should work");
        assert_eq!(tnid_user.as_u128(), tnid_user_back.as_u128());
    }

    #[test]
    fn test_known_tnid_value() {
        // Create a Tnid from a known u128 value and verify uuid conversion works
        let test_u128 = Tnid::<TestId>::new_v0().as_u128();
        let tnid = Tnid::<TestId>::from_u128(test_u128).expect("should create from u128");

        let uuid: uuid::Uuid = tnid.into();
        assert_eq!(uuid.as_u128(), test_u128);

        let tnid_back: Tnid<TestId> = uuid.try_into().expect("should convert back");
        assert_eq!(tnid_back.as_u128(), test_u128);
    }
}
