//! `serde` integration for TNID types.
//!
//! This module is enabled by the `serde` feature and implements:
//! - `serde::Serialize` / `serde::Deserialize` for [`crate::Tnid`]
//! - `serde::Serialize` / `serde::Deserialize` for [`crate::DynamicTnid`]
//! - `serde::Serialize` / `serde::Deserialize` for [`crate::UuidLike`]
//!
//! ## Representation
//!
//! - **Human-readable serializers** (e.g., JSON): serialize as a string
//!   - `Tnid<Name>` / `DynamicTnid`: TNID string (`name.data`)
//!   - `UuidLike`: UUID string (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
//! - **Non-human-readable serializers** (e.g., bincode): serialize as 16 UUID bytes (big-endian)
//!
//! Deserialization accepts the corresponding representation.

use crate::{Case, DynamicTnid, ParseTnidError, Tnid, TnidName, UuidLike};

fn parse_tnid_or_uuid_str_for_typed<Name: TnidName>(s: &str) -> Result<Tnid<Name>, ParseTnidError> {
    // TNID strings always contain exactly one '.' separator.
    if s.as_bytes().contains(&b'.') {
        Tnid::<Name>::parse_tnid_string(s)
    } else {
        Tnid::<Name>::parse_uuid_string(s)
    }
}

fn parse_tnid_or_uuid_str_for_dynamic(s: &str) -> Result<DynamicTnid, ParseTnidError> {
    if s.as_bytes().contains(&b'.') {
        DynamicTnid::parse_tnid_string(s)
    } else {
        DynamicTnid::parse_uuid_string(s)
    }
}

fn parse_uuid_like_str(s: &str) -> Result<UuidLike, crate::ParseUuidStringError> {
    UuidLike::parse_uuid_string(s)
}

fn bytes_to_u128<E>(bytes: &[u8]) -> Result<u128, E>
where
    E: serde::de::Error,
{
    if bytes.len() != 16 {
        return Err(E::invalid_length(bytes.len(), &"16 bytes"));
    }

    let mut arr = [0_u8; 16];
    arr.copy_from_slice(bytes);
    Ok(u128::from_be_bytes(arr))
}

// ---- Tnid<Name> ----

impl<Name: TnidName> serde::Serialize for Tnid<Name> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_tnid_string())
        } else {
            let bytes = self.as_u128().to_be_bytes();
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de, Name: TnidName> serde::Deserialize<'de> for Tnid<Name> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <&str as serde::Deserialize>::deserialize(deserializer)?;
            parse_tnid_or_uuid_str_for_typed::<Name>(s).map_err(serde::de::Error::custom)
        } else {
            struct BytesVisitor<Name: TnidName>(core::marker::PhantomData<Name>);

            impl<'de, Name: TnidName> serde::de::Visitor<'de> for BytesVisitor<Name> {
                type Value = Tnid<Name>;

                fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_str("16 bytes (UUID big-endian)")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let id = u128::from_be_bytes(
                        <[u8; 16]>::try_from(v)
                            .map_err(|_| E::invalid_length(v.len(), &"16 bytes"))?,
                    );
                    Tnid::<Name>::from_u128(id).map_err(E::custom)
                }

                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    self.visit_bytes(&v)
                }
            }

            deserializer.deserialize_bytes(BytesVisitor::<Name>(core::marker::PhantomData))
        }
    }
}

// ---- DynamicTnid ----

impl serde::Serialize for DynamicTnid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_tnid_string())
        } else {
            serializer.serialize_bytes(&self.to_bytes())
        }
    }
}

impl<'de> serde::Deserialize<'de> for DynamicTnid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <&str as serde::Deserialize>::deserialize(deserializer)?;
            parse_tnid_or_uuid_str_for_dynamic(s).map_err(serde::de::Error::custom)
        } else {
            struct BytesVisitor;

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                type Value = DynamicTnid;

                fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_str("16 bytes (UUID big-endian)")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let id = bytes_to_u128::<E>(v)?;
                    DynamicTnid::from_u128(id).map_err(E::custom)
                }

                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    self.visit_bytes(&v)
                }
            }

            deserializer.deserialize_bytes(BytesVisitor)
        }
    }
}

// ---- UuidLike ----

impl serde::Serialize for UuidLike {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_uuid_string(Case::Lower))
        } else {
            let bytes = self.as_u128().to_be_bytes();
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> serde::Deserialize<'de> for UuidLike {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <&str as serde::Deserialize>::deserialize(deserializer)?;
            parse_uuid_like_str(s).map_err(serde::de::Error::custom)
        } else {
            struct BytesVisitor;

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                type Value = UuidLike;

                fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_str("16 bytes (UUID big-endian)")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let id = bytes_to_u128::<E>(v)?;
                    Ok(UuidLike::new(id))
                }

                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    self.visit_bytes(&v)
                }
            }

            deserializer.deserialize_bytes(BytesVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Test;
    impl TnidName for Test {
        const ID_NAME: crate::NameStr<'static> = crate::NameStr::new_const("test");
    }

    #[test]
    fn serde_json_tnid_string_roundtrip_typed() {
        let id = Tnid::<Test>::new_v1_with_random(0x0123456789ABCDEF0123456789ABCDEF);

        let json = serde_json::to_string(&id).expect("serialize JSON");
        assert_eq!(json, format!("{:?}", id.to_tnid_string()));

        let parsed: Tnid<Test> = serde_json::from_str(&json).expect("deserialize JSON");
        assert_eq!(parsed.as_u128(), id.as_u128());
    }

    #[test]
    fn serde_json_accepts_uuid_string_for_typed() {
        let id = Tnid::<Test>::new_v1_with_random(0x0123456789ABCDEF0123456789ABCDEF);
        let uuid_json = format!("{:?}", id.to_uuid_string(Case::Lower));

        let parsed: Tnid<Test> = serde_json::from_str(&uuid_json).expect("deserialize UUID JSON");
        assert_eq!(parsed.as_u128(), id.as_u128());
    }

    #[test]
    fn bincode_binary_roundtrip_typed() {
        let id = Tnid::<Test>::new_v1_with_random(0x0123456789ABCDEF0123456789ABCDEF);

        let bytes = bincode::serialize(&id).expect("serialize bincode");
        let parsed: Tnid<Test> = bincode::deserialize(&bytes).expect("deserialize bincode");
        assert_eq!(parsed.as_u128(), id.as_u128());
    }

    #[test]
    fn serde_json_tnid_string_roundtrip_dynamic() {
        let id = DynamicTnid::from(Tnid::<Test>::new_v1_with_random(
            0x0123456789ABCDEF0123456789ABCDEF,
        ));

        let json = serde_json::to_string(&id).expect("serialize JSON");
        assert_eq!(json, format!("{:?}", id.to_tnid_string()));

        let parsed: DynamicTnid = serde_json::from_str(&json).expect("deserialize JSON");
        assert_eq!(parsed.as_u128(), id.as_u128());
    }

    #[test]
    fn bincode_binary_roundtrip_dynamic() {
        let id = DynamicTnid::from(Tnid::<Test>::new_v1_with_random(
            0x0123456789ABCDEF0123456789ABCDEF,
        ));

        let bytes = bincode::serialize(&id).expect("serialize bincode");
        let parsed: DynamicTnid = bincode::deserialize(&bytes).expect("deserialize bincode");
        assert_eq!(parsed.as_u128(), id.as_u128());
    }

    #[test]
    fn serde_uuidlike_roundtrip() {
        let uuid_like = UuidLike::new(0x12345678_1234_1234_1234_123456789abc);

        let json = serde_json::to_string(&uuid_like).expect("serialize JSON");
        let parsed: UuidLike = serde_json::from_str(&json).expect("deserialize JSON");
        assert_eq!(parsed.as_u128(), uuid_like.as_u128());

        let bytes = bincode::serialize(&uuid_like).expect("serialize bincode");
        let parsed_bin: UuidLike = bincode::deserialize(&bytes).expect("deserialize bincode");
        assert_eq!(parsed_bin.as_u128(), uuid_like.as_u128());
    }
}
