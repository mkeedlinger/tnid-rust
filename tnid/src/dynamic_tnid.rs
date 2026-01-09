#[cfg(feature = "encryption")]
use crate::EncryptionKey;
use crate::{data_encoding, name_encoding, utils, v0, v1, NameStr, Tnid, TnidName, TnidVariant, UUIDLike};
#[cfg(feature = "time")]
use time::OffsetDateTime;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DynamicTnid(u128);

impl DynamicTnid {
    #[cfg(all(feature = "time", feature = "rand"))]
    pub fn new_v0(name: NameStr) -> Option<Self> {
        Self::new_v0_with_time(name, time::OffsetDateTime::now_utc())
    }

    #[cfg(all(feature = "time", feature = "rand"))]
    pub fn new_time_ordered(name: NameStr) -> Option<Self> {
        Self::new_v0(name)
    }

    #[cfg(all(feature = "time", feature = "rand"))]
    pub fn new_v0_with_time(name: NameStr, time: OffsetDateTime) -> Option<Self> {
        let epoch_millis = (time.unix_timestamp_nanos() / 1000 / 1000) as u64;
        let random_bits: u64 = rand::random();
        Some(Self(v0::make_from_parts(name, epoch_millis, random_bits)))
    }

    pub fn new_v0_with_parts(name: NameStr, epoch_millis: u64, random: u64) -> Option<Self> {
        Some(Self(v0::make_from_parts(name, epoch_millis, random)))
    }

    #[cfg(feature = "rand")]
    pub fn new_v1(name: NameStr) -> Option<Self> {
        Self::new_v1_with_random(name, rand::random())
    }

    #[cfg(feature = "rand")]
    pub fn new_high_entropy(name: NameStr) -> Option<Self> {
        Self::new_v1(name)
    }

    pub fn new_v1_with_random(name: NameStr, random_bits: u128) -> Option<Self> {
        Some(Self(v1::make_from_parts(name, random_bits)))
    }

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

    pub fn parse_uuid_string(s: &str) -> Option<Self> {
        let id = crate::UUIDLike::parse_uuid_string(s)?.as_u128();

        Self::from_u128(id)
    }

    pub fn name(&self) -> String {
        name_encoding::extract_name_string(self.0).expect("DynamicTnid must have valid name")
    }

    pub fn name_hex(&self) -> String {
        name_encoding::name_bits_to_hex(self.0)
    }

    pub fn as_u128(&self) -> u128 {
        self.0
    }

    pub fn variant(&self) -> TnidVariant {
        TnidVariant::from_id(self.0)
    }

    pub fn to_tnid_string(&self) -> String {
        format!("{}.{}", self.name(), data_encoding::id_data_to_string(self.0))
    }

    pub fn to_uuid_string(&self, uppercase: bool) -> String {
        utils::u128_to_uuid_string(self.0, uppercase)
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

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
