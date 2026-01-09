#[cfg(feature = "encryption")]
use crate::EncryptionKey;
use crate::{v0, NameStr, Tnid, TnidName, TnidVariant};
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
        todo!()
    }

    #[cfg(feature = "rand")]
    pub fn new_high_entropy(name: NameStr) -> Option<Self> {
        todo!()
    }

    pub fn new_v1_with_random(name: NameStr, random_bits: u128) -> Option<Self> {
        todo!()
    }

    pub fn from_u128(id: u128) -> Option<Self> {
        todo!()
    }

    pub fn parse_tnid_string(s: &str) -> Option<Self> {
        todo!()
    }

    pub fn parse_uuid_string(s: &str) -> Option<Self> {
        todo!()
    }

    pub fn name(&self) -> String {
        todo!()
    }

    pub fn name_hex(&self) -> String {
        todo!()
    }

    pub fn as_u128(&self) -> u128 {
        self.0
    }

    pub fn variant(&self) -> TnidVariant {
        todo!()
    }

    pub fn to_tnid_string(&self) -> String {
        todo!()
    }

    pub fn to_uuid_string(&self, uppercase: bool) -> String {
        todo!()
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Option<Self> {
        Self::from_u128(u128::from_be_bytes(bytes))
    }

    #[cfg(feature = "encryption")]
    pub fn encrypt_v0_to_v1(&self, key: impl Into<EncryptionKey>) -> Option<Self> {
        todo!()
    }

    #[cfg(feature = "encryption")]
    pub fn decrypt_v1_to_v0(&self, key: impl Into<EncryptionKey>) -> Option<Self> {
        todo!()
    }
}

impl<Name: TnidName> From<Tnid<Name>> for DynamicTnid {
    fn from(tnid: Tnid<Name>) -> Self {
        todo!()
    }
}

impl<Name: TnidName> TryFrom<DynamicTnid> for Tnid<Name> {
    type Error = ();

    fn try_from(dynamic: DynamicTnid) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl core::fmt::Display for DynamicTnid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

impl core::fmt::Debug for DynamicTnid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}
