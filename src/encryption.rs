//! TNID encryption utilities.
//!
//! This module provides format-preserving encryption for TNIDs, allowing you to hide
//! timestamp information in V0 TNIDs by encrypting them to V1 TNIDs.
//!
//! # Note
//!
//! The encryption functionality is not part of the TNID specification.
//! Encrypted TNIDs are standard V1 TNIDs
//! and remain fully compatible with any TNID implementation.
//!
//! # Why Encrypt TNIDs?
//!
//! V0 TNIDs contain a timestamp (like UUIDv7), which reveals when the ID was created.
//! This can leak information you may not want to expose publicly, such as:
//! - When a user account was created
//! - The order in which records were created
//! - Approximate creation rates
//!
//! By encrypting V0 to V1, you get a valid high-entropy V1 TNID that hides this
//! information while remaining decryptable on the backend.
//!
//! # How It Works
//!
//! The encryption uses [Format-Preserving Encryption (FPE)](https://en.wikipedia.org/wiki/Format-preserving_encryption)
//! with AES-128 in FF1 mode. This encrypts the data bits while preserving:
//! - The TNID name (unchanged)
//! - The UUID version/variant bits (valid UUIDv8)
//! - The overall 128-bit structure
//!
//! The TNID variant changes from V0 to V1, making the encrypted ID indistinguishable
//! from a randomly generated V1 TNID.
//!
//! # Example
//!
//! ```rust
//! use tnid::{TNID, TNIDName, NameStr, TNIDVariant};
//!
//! struct User;
//! impl TNIDName for User {
//!     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
//! }
//!
//! let secret = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
//!
//! // Create a time-ordered V0 TNID
//! let original = TNID::<User>::new_v0();
//! assert_eq!(original.variant(), TNIDVariant::V0);
//!
//! // Encrypt to V1 before sending to client
//! let encrypted = original.encrypt_v0_to_v1(secret).unwrap();
//! assert_eq!(encrypted.variant(), TNIDVariant::V1);
//!
//! // Decrypt on the backend to recover the original
//! let decrypted = encrypted.decrypt_v1_to_v0(secret).unwrap();
//! assert_eq!(decrypted.as_u128(), original.as_u128());
//! ```

use aes::Aes128;
use fpe::ff1::{FF1, FlexibleNumeralString};

/// A 128-bit (16 byte) encryption key for TNID encryption.
///
/// This is a simple wrapper around `[u8; 16]` with helper methods for
/// constructing keys from various formats.
///
/// The key is 128 bits to match the AES-128 cipher used in the FF1
/// format-preserving encryption scheme.
///
/// # Example
///
/// ```rust
/// use tnid::encryption::EncryptionKey;
///
/// // From raw bytes
/// let key = EncryptionKey::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
///
/// // From a hex string
/// let key = EncryptionKey::from_hex("0102030405060708090a0b0c0d0e0f10").unwrap();
///
/// // From a slice
/// let bytes: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
/// let key = EncryptionKey::from_slice(bytes).unwrap();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionKey([u8; 16]);

impl EncryptionKey {
    /// Creates a new encryption key from raw bytes.
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Creates an encryption key from a 32-character hex string.
    ///
    /// Returns `None` if the string is not exactly 32 hex characters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tnid::encryption::EncryptionKey;
    ///
    /// let key = EncryptionKey::from_hex("0102030405060708090a0b0c0d0e0f10").unwrap();
    /// assert_eq!(key.as_bytes()[0], 0x01);
    /// assert_eq!(key.as_bytes()[15], 0x10);
    ///
    /// // Case insensitive
    /// let key = EncryptionKey::from_hex("0102030405060708090A0B0C0D0E0F10").unwrap();
    ///
    /// // Invalid length
    /// assert!(EncryptionKey::from_hex("0102").is_none());
    /// ```
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 32 {
            return None;
        }

        let mut bytes = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let high = hex_char_to_nibble(*chunk.first()?)?;
            let low = hex_char_to_nibble(*chunk.get(1)?)?;
            *bytes.get_mut(i)? = (high << 4) | low;
        }

        Some(Self(bytes))
    }

    /// Creates an encryption key from a byte slice.
    ///
    /// Returns `None` if the slice is not exactly 16 bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tnid::encryption::EncryptionKey;
    ///
    /// let bytes: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    /// let key = EncryptionKey::from_slice(bytes).unwrap();
    ///
    /// // Wrong length
    /// assert!(EncryptionKey::from_slice(&[1, 2, 3]).is_none());
    /// ```
    pub fn from_slice(s: &[u8]) -> Option<Self> {
        let bytes: [u8; 16] = s.try_into().ok()?;
        Some(Self(bytes))
    }

    /// Returns the key as a byte array reference.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for EncryptionKey {
    fn from(bytes: [u8; 16]) -> Self {
        Self::new(bytes)
    }
}

fn hex_char_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const RIGHT_SECRET_DATA_SECTION_MASK: u128 = 0x00000000_0000_0000_0fff_ffffffffffff;
const MIDDLE_SECRET_DATA_SECTION_MASK: u128 = 0x00000000_0000_0fff_0000_000000000000;
const LEFT_SECRET_DATA_SECTION_MASK: u128 = 0x00000fff_ffff_0000_0000_000000000000;

pub(crate) const COMPLETE_SECRET_DATA_MASK: u128 = RIGHT_SECRET_DATA_SECTION_MASK
    | MIDDLE_SECRET_DATA_SECTION_MASK
    | LEFT_SECRET_DATA_SECTION_MASK;

/// Extract secret data bits (excludes name, UUID version/variant, and TNID variant)
pub(crate) fn extract_secret_data_bits(id: u128) -> u128 {
    let extracted = id & RIGHT_SECRET_DATA_SECTION_MASK;

    const BETWEEN_MIDDLE_RIGHT: i32 = 4;
    let extracted = extracted | ((id & MIDDLE_SECRET_DATA_SECTION_MASK) >> BETWEEN_MIDDLE_RIGHT);

    const BETWEEN_LEFT_MIDDLE: i32 = BETWEEN_MIDDLE_RIGHT + 4;
    let extracted = extracted | ((id & LEFT_SECRET_DATA_SECTION_MASK) >> BETWEEN_LEFT_MIDDLE);

    extracted
}

/// Expand compacted secret data bits back into their positions (inverse of extract_secret_data_bits)
pub(crate) fn expand_secret_data_bits(bits: u128) -> u128 {
    // Right section stays in place
    let expanded = bits & RIGHT_SECRET_DATA_SECTION_MASK;

    // Middle section shifts left
    const BETWEEN_MIDDLE_RIGHT: i32 = 4;
    let middle_mask = MIDDLE_SECRET_DATA_SECTION_MASK >> BETWEEN_MIDDLE_RIGHT;
    let expanded = expanded | ((bits & middle_mask) << BETWEEN_MIDDLE_RIGHT);

    // Left section shifts left
    const BETWEEN_LEFT_MIDDLE: i32 = BETWEEN_MIDDLE_RIGHT + 4;
    let left_mask = LEFT_SECRET_DATA_SECTION_MASK >> BETWEEN_LEFT_MIDDLE;
    let expanded = expanded | ((bits & left_mask) << BETWEEN_LEFT_MIDDLE);

    expanded
}

const SECRET_DATA_BIT_NUM: u8 = COMPLETE_SECRET_DATA_MASK.count_ones() as u8;
const HEX_DIGIT_COUNT: usize = 25; // 100 bits / 4 bits per hex digit = 25

fn u128_to_hex_digits(data: u128) -> Vec<u16> {
    let mut hex_digits = Vec::with_capacity(HEX_DIGIT_COUNT);
    for i in 0..HEX_DIGIT_COUNT {
        let shift = (HEX_DIGIT_COUNT - 1 - i) * 4;
        hex_digits.push(((data >> shift) & 0xF) as u16);
    }
    hex_digits
}

fn hex_digits_to_u128(digits: Vec<u16>) -> u128 {
    let mut result = 0u128;
    for digit in digits {
        result = (result << 4) | (digit as u128);
    }
    result
}

pub(crate) fn encrypt(id_secret_data: u128, key: &EncryptionKey) -> u128 {
    // Mask to only encrypt the lower 100 bits
    let mask = (1u128 << SECRET_DATA_BIT_NUM) - 1;
    let data = id_secret_data & mask;

    let hex_digits = u128_to_hex_digits(data);
    let numeral_string = FlexibleNumeralString::from(hex_digits);
    let ff1 = FF1::<Aes128>::new(key.as_bytes(), 16).expect("16 is valid radix");

    let encrypted = ff1
        .encrypt(&[], &numeral_string)
        .expect("string is in required radix");

    hex_digits_to_u128(encrypted.into())
}

pub(crate) fn decrypt(id_secret_data: u128, key: &EncryptionKey) -> u128 {
    // Mask to only decrypt the lower 100 bits
    let mask = (1u128 << SECRET_DATA_BIT_NUM) - 1;
    let data = id_secret_data & mask;

    let hex_digits = u128_to_hex_digits(data);
    let numeral_string = FlexibleNumeralString::from(hex_digits);
    let ff1 = FF1::<Aes128>::new(key.as_bytes(), 16).expect("16 is valid radix");

    let decrypted = ff1
        .decrypt(&[], &numeral_string)
        .expect("string is in required radix");

    hex_digits_to_u128(decrypted.into())
}

#[cfg(all(test, not(debug_assertions)))]
mod tests_release {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 100_000, .. ProptestConfig::default()
        })]
        #[test]
        fn decrypt_no_panic(id_secret_data: u128, secret: u128) {
            decrypt(id_secret_data, &secret.to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::u128;

    #[test]
    fn secret_data_extract_correctly() {
        let extract = extract_secret_data_bits(u128::MAX);
        assert_eq!(extract.leading_zeros(), 28);
        assert_eq!(extract.count_ones(), SECRET_DATA_BIT_NUM.into());

        assert_eq!(
            COMPLETE_SECRET_DATA_MASK.count_ones(),
            SECRET_DATA_BIT_NUM.into()
        );

        let extract = extract_secret_data_bits(COMPLETE_SECRET_DATA_MASK);
        assert_eq!(extract.leading_zeros(), 28);
        assert_eq!(extract.count_ones(), SECRET_DATA_BIT_NUM.into());
    }

    #[test]
    fn secret_data_expand_correctly() {
        // Expand should produce the mask when given all 100 bits set
        let expanded = expand_secret_data_bits(u128::MAX);
        assert_eq!(expanded, COMPLETE_SECRET_DATA_MASK);
        assert_eq!(expanded.count_ones(), SECRET_DATA_BIT_NUM.into());
    }

    #[test]
    fn secret_data_roundtrip() {
        // Extract then expand should give back the original (masked)
        let original = COMPLETE_SECRET_DATA_MASK;
        let extracted = extract_secret_data_bits(original);
        let expanded = expand_secret_data_bits(extracted);
        assert_eq!(expanded, original);

        // Test with arbitrary pattern
        let pattern = 0x00000aaa_aaaa_0000_0555_555555555555u128;
        let extracted = extract_secret_data_bits(pattern);
        let expanded = expand_secret_data_bits(extracted);
        assert_eq!(
            expanded & COMPLETE_SECRET_DATA_MASK,
            pattern & COMPLETE_SECRET_DATA_MASK
        );
    }

    #[test]
    fn encryption_round_trip() {
        let key = EncryptionKey::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let id_secret_data = extract_secret_data_bits(u128::MAX);
        let encrypted = encrypt(id_secret_data, &key);

        let decrypted = decrypt(encrypted, &key);

        dbg!(id_secret_data, encrypted, decrypted);

        assert_eq!(decrypted, id_secret_data);
    }
}
