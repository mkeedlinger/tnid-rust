//! `sqlx` integration for TNID types.
//!
//! Enabled by one of:
//! - `sqlx-postgres`
//! - `sqlx-mysql`
//! - `sqlx-sqlite`
//!
//! ## Representation
//!
//! TNIDs are encoded/decoded as **UUID bytes** by default (16 bytes, big-endian).
//! This matches typical `UUID`/`BINARY(16)`/`BLOB` storage and avoids inflating storage with text.

use crate::{DynamicTnid, Tnid, TnidName};

fn u128_to_be_bytes(id: u128) -> [u8; 16] {
    id.to_be_bytes()
}

fn be_bytes_to_u128(bytes: &[u8]) -> Result<u128, sqlx::error::BoxDynError> {
    if bytes.len() != 16 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected 16 bytes, got {}", bytes.len()),
        )));
    }

    let mut arr = [0_u8; 16];
    arr.copy_from_slice(bytes);
    Ok(u128::from_be_bytes(arr))
}

#[cfg(feature = "sqlx-postgres")]
mod postgres {
    use super::*;
    use sqlx::Postgres;
    use sqlx::encode::{Encode, IsNull};
    use sqlx::types::Type;

    impl<Name: TnidName> Type<Postgres> for Tnid<Name> {
        fn type_info() -> sqlx::postgres::PgTypeInfo {
            // Use `with_name` because `PgTypeInfo::UUID` is not public in sqlx.
            sqlx::postgres::PgTypeInfo::with_name("UUID")
        }
    }

    impl<Name: TnidName> sqlx::postgres::PgHasArrayType for Tnid<Name> {
        fn array_type_info() -> sqlx::postgres::PgTypeInfo {
            sqlx::postgres::PgTypeInfo::array_of("UUID")
        }
    }

    impl<'q, Name: TnidName> Encode<'q, Postgres> for Tnid<Name> {
        fn encode_by_ref(
            &self,
            buf: &mut sqlx::postgres::PgArgumentBuffer,
        ) -> Result<IsNull, sqlx::error::BoxDynError> {
            let bytes = u128_to_be_bytes(self.as_u128());
            buf.extend_from_slice(&bytes);
            Ok(IsNull::No)
        }
    }

    impl<'r, Name: TnidName> sqlx::decode::Decode<'r, Postgres> for Tnid<Name> {
        fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
            let id = match value.format() {
                sqlx::postgres::PgValueFormat::Binary => be_bytes_to_u128(value.as_bytes()?)?,
                sqlx::postgres::PgValueFormat::Text => {
                    let s = value.as_str()?;
                    crate::UUIDLike::parse_uuid_string(s)
                        .map_err(|e| Box::new(e) as sqlx::error::BoxDynError)?
                        .as_u128()
                }
            };

            Tnid::<Name>::from_u128(id).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
        }
    }

    impl Type<Postgres> for DynamicTnid {
        fn type_info() -> sqlx::postgres::PgTypeInfo {
            sqlx::postgres::PgTypeInfo::with_name("UUID")
        }
    }

    impl sqlx::postgres::PgHasArrayType for DynamicTnid {
        fn array_type_info() -> sqlx::postgres::PgTypeInfo {
            sqlx::postgres::PgTypeInfo::array_of("UUID")
        }
    }

    impl<'q> Encode<'q, Postgres> for DynamicTnid {
        fn encode_by_ref(
            &self,
            buf: &mut sqlx::postgres::PgArgumentBuffer,
        ) -> Result<IsNull, sqlx::error::BoxDynError> {
            let bytes = u128_to_be_bytes(self.as_u128());
            buf.extend_from_slice(&bytes);
            Ok(IsNull::No)
        }
    }

    impl<'r> sqlx::decode::Decode<'r, Postgres> for DynamicTnid {
        fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
            let id = match value.format() {
                sqlx::postgres::PgValueFormat::Binary => be_bytes_to_u128(value.as_bytes()?)?,
                sqlx::postgres::PgValueFormat::Text => {
                    let s = value.as_str()?;
                    crate::UUIDLike::parse_uuid_string(s)
                        .map_err(|e| Box::new(e) as sqlx::error::BoxDynError)?
                        .as_u128()
                }
            };

            DynamicTnid::from_u128(id).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
        }
    }
}

#[cfg(feature = "sqlx-mysql")]
mod mysql {
    use super::*;
    use sqlx::MySql;
    use sqlx::decode::Decode;
    use sqlx::encode::{Encode, IsNull};
    use sqlx::types::Type;

    impl<Name: TnidName> Type<MySql> for Tnid<Name> {
        fn type_info() -> sqlx::mysql::MySqlTypeInfo {
            <&[u8] as Type<MySql>>::type_info()
        }

        fn compatible(ty: &sqlx::mysql::MySqlTypeInfo) -> bool {
            <&[u8] as Type<MySql>>::compatible(ty)
        }
    }

    impl<'q, Name: TnidName> Encode<'q, MySql> for Tnid<Name> {
        fn encode_by_ref(&self, buf: &mut Vec<u8>) -> Result<IsNull, sqlx::error::BoxDynError> {
            let bytes = u128_to_be_bytes(self.as_u128());
            <&[u8] as Encode<MySql>>::encode_by_ref(&bytes.as_slice(), buf)
        }
    }

    impl<'r, Name: TnidName> Decode<'r, MySql> for Tnid<Name> {
        fn decode(value: sqlx::mysql::MySqlValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
            let bytes = <&[u8] as Decode<MySql>>::decode(value)?;
            let id = be_bytes_to_u128(bytes)?;
            Tnid::<Name>::from_u128(id).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
        }
    }

    impl Type<MySql> for DynamicTnid {
        fn type_info() -> sqlx::mysql::MySqlTypeInfo {
            <&[u8] as Type<MySql>>::type_info()
        }

        fn compatible(ty: &sqlx::mysql::MySqlTypeInfo) -> bool {
            <&[u8] as Type<MySql>>::compatible(ty)
        }
    }

    impl<'q> Encode<'q, MySql> for DynamicTnid {
        fn encode_by_ref(&self, buf: &mut Vec<u8>) -> Result<IsNull, sqlx::error::BoxDynError> {
            let bytes = u128_to_be_bytes(self.as_u128());
            <&[u8] as Encode<MySql>>::encode_by_ref(&bytes.as_slice(), buf)
        }
    }

    impl<'r> Decode<'r, MySql> for DynamicTnid {
        fn decode(value: sqlx::mysql::MySqlValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
            let bytes = <&[u8] as Decode<MySql>>::decode(value)?;
            let id = be_bytes_to_u128(bytes)?;
            DynamicTnid::from_u128(id).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
        }
    }
}

#[cfg(feature = "sqlx-sqlite")]
mod sqlite {
    use super::*;
    use sqlx::Sqlite;
    use sqlx::TypeInfo;
    use sqlx::ValueRef;
    use sqlx::decode::Decode;
    use sqlx::encode::{Encode, IsNull};
    use sqlx::types::Type;
    use std::borrow::Cow;

    impl<Name: TnidName> Type<Sqlite> for Tnid<Name> {
        fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
            <&[u8] as Type<Sqlite>>::type_info()
        }

        fn compatible(ty: &sqlx::sqlite::SqliteTypeInfo) -> bool {
            <&[u8] as Type<Sqlite>>::compatible(ty)
        }
    }

    impl<'q, Name: TnidName> Encode<'q, Sqlite> for Tnid<Name> {
        fn encode_by_ref(
            &self,
            args: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'q>>,
        ) -> Result<IsNull, sqlx::error::BoxDynError> {
            let bytes = u128_to_be_bytes(self.as_u128());
            args.push(sqlx::sqlite::SqliteArgumentValue::Blob(Cow::Owned(
                bytes.to_vec(),
            )));
            Ok(IsNull::No)
        }
    }

    impl<'r, Name: TnidName> Decode<'r, Sqlite> for Tnid<Name> {
        fn decode(
            value: sqlx::sqlite::SqliteValueRef<'r>,
        ) -> Result<Self, sqlx::error::BoxDynError> {
            let ty_name = value.type_info().name().to_ascii_uppercase();

            let id = if ty_name == "TEXT" {
                let s = <&str as Decode<Sqlite>>::decode(value)?;
                if s.as_bytes().contains(&b'.') {
                    Tnid::<Name>::parse_tnid_string(s)
                        .map_err(|e| Box::new(e) as sqlx::error::BoxDynError)?
                        .as_u128()
                } else {
                    Tnid::<Name>::parse_uuid_string(s)
                        .map_err(|e| Box::new(e) as sqlx::error::BoxDynError)?
                        .as_u128()
                }
            } else {
                let bytes = <&[u8] as Decode<Sqlite>>::decode(value)?;
                be_bytes_to_u128(bytes)?
            };

            Tnid::<Name>::from_u128(id).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
        }
    }

    impl Type<Sqlite> for DynamicTnid {
        fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
            <&[u8] as Type<Sqlite>>::type_info()
        }

        fn compatible(ty: &sqlx::sqlite::SqliteTypeInfo) -> bool {
            <&[u8] as Type<Sqlite>>::compatible(ty)
        }
    }

    impl<'q> Encode<'q, Sqlite> for DynamicTnid {
        fn encode_by_ref(
            &self,
            args: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'q>>,
        ) -> Result<IsNull, sqlx::error::BoxDynError> {
            let bytes = u128_to_be_bytes(self.as_u128());
            args.push(sqlx::sqlite::SqliteArgumentValue::Blob(Cow::Owned(
                bytes.to_vec(),
            )));
            Ok(IsNull::No)
        }
    }

    impl<'r> Decode<'r, Sqlite> for DynamicTnid {
        fn decode(
            value: sqlx::sqlite::SqliteValueRef<'r>,
        ) -> Result<Self, sqlx::error::BoxDynError> {
            let ty_name = value.type_info().name().to_ascii_uppercase();

            let id = if ty_name == "TEXT" {
                let s = <&str as Decode<Sqlite>>::decode(value)?;
                if s.as_bytes().contains(&b'.') {
                    DynamicTnid::parse_tnid_string(s)
                        .map_err(|e| Box::new(e) as sqlx::error::BoxDynError)?
                        .as_u128()
                } else {
                    crate::UUIDLike::parse_uuid_string(s)
                        .map_err(|e| Box::new(e) as sqlx::error::BoxDynError)?
                        .as_u128()
                }
            } else {
                let bytes = <&[u8] as Decode<Sqlite>>::decode(value)?;
                be_bytes_to_u128(bytes)?
            };

            DynamicTnid::from_u128(id).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
        }
    }
}
