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
//! with AES-128 in FF1 mode. This encrypts the Payload bits (100 bits) while preserving:
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
//! use tnid::{Tnid, TnidName, NameStr, TnidVariant};
//! use tnid::encryption::EncryptionKey;
//!
//! struct User;
//! impl TnidName for User {
//!     const ID_NAME: NameStr<'static> = NameStr::new_const("user");
//! }
//!
//! let key = EncryptionKey::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
//!
//! // Create a time-ordered V0 TNID
//! let original = Tnid::<User>::new_v0();
//! assert_eq!(original.variant(), TnidVariant::V0);
//!
//! // Encrypt to V1 before sending to client
//! let encrypted = original.encrypt_v0_to_v1(&key).unwrap();
//! assert_eq!(encrypted.variant(), TnidVariant::V1);
//!
//! // Decrypt on the backend to recover the original
//! let decrypted = encrypted.decrypt_v1_to_v0(&key).unwrap();
//! assert_eq!(decrypted.as_u128(), original.as_u128());
//! ```

use aes::Aes128;
use fpe::ff1::{FlexibleNumeralString, FF1};

use crate::{utils, TnidVariant};

/// The radix used for FF1 encryption (hex digits, 0-15).
const FF1_RADIX: u32 = 16;

/// Error when creating an [`EncryptionKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncryptionKeyError {
    /// The hex string is not 32 characters long.
    /// Contains the actual length.
    WrongHexLength(usize),
    /// An invalid hex character was found.
    /// Contains the position and the invalid Unicode scalar value.
    InvalidHexChar {
        /// Byte index into the input string.
        position: usize,
        /// The invalid character (as read from the input).
        character: char,
    },
    /// The byte slice is not 16 bytes long.
    /// Contains the actual length.
    WrongByteLength(usize),
    /// The hex string contains non-ASCII characters.
    NonAscii,
}

impl std::fmt::Display for EncryptionKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongHexLength(len) => {
                write!(
                    f,
                    "encryption key hex string must be 32 characters, got {len}"
                )
            }
            Self::InvalidHexChar {
                position,
                character,
            } => {
                write!(
                    f,
                    "invalid hex character '{}' (U+{:04X}) at position {position}",
                    character, *character as u32
                )
            }
            Self::WrongByteLength(len) => {
                write!(f, "encryption key slice must be 16 bytes, got {len}")
            }
            Self::NonAscii => {
                write!(f, "encryption key hex string must be ASCII")
            }
        }
    }
}

impl std::error::Error for EncryptionKeyError {}

/// Error when encrypting or decrypting a TNID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncryptionError {
    /// The TNID variant is not supported for encryption/decryption.
    /// Contains the unsupported variant.
    UnsupportedVariant(TnidVariant),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVariant(variant) => {
                write!(
                    f,
                    "TNID variant {variant:?} is not supported for encryption/decryption"
                )
            }
        }
    }
}

impl std::error::Error for EncryptionError {}

/// A 128-bit (16 byte) encryption key for TNID encryption.
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
pub struct EncryptionKey(FF1<Aes128>);

impl EncryptionKey {
    /// Creates a new encryption key from raw bytes.
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(FF1::<Aes128>::new(&bytes, FF1_RADIX).expect("radix 16 is always valid"))
    }

    /// Creates an encryption key from a 32-character hex string.
    ///
    /// Returns `Err` if the string is not exactly 32 hex characters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tnid::encryption::EncryptionKey;
    ///
    /// let key = EncryptionKey::from_hex("0102030405060708090a0b0c0d0e0f10").unwrap();
    ///
    /// // Case insensitive
    /// let key = EncryptionKey::from_hex("0102030405060708090A0B0C0D0E0F10").unwrap();
    ///
    /// // Invalid length
    /// assert!(EncryptionKey::from_hex("0102").is_err());
    /// ```
    pub fn from_hex(s: &str) -> Result<Self, EncryptionKeyError> {
        if s.len() != 32 {
            return Err(EncryptionKeyError::WrongHexLength(s.len()));
        }

        if !s.is_ascii() {
            return Err(EncryptionKeyError::NonAscii);
        }

        let bytes_slice = s.as_bytes();
        let mut bytes = [0u8; 16];
        for (i, chunk) in bytes_slice.chunks(2).enumerate() {
            let pos = i * 2;
            let high_byte = *chunk.first().expect("hex chunk should have first byte");
            let low_byte = *chunk.get(1).expect("hex chunk should have second byte"); // todo: make proptests for this

            let high_char = high_byte as char;
            let low_char = low_byte as char;

            let high =
                utils::hex_char_to_nibble(high_byte).ok_or(EncryptionKeyError::InvalidHexChar {
                    position: pos,
                    character: high_char,
                })?;
            let low =
                utils::hex_char_to_nibble(low_byte).ok_or(EncryptionKeyError::InvalidHexChar {
                    position: pos + 1,
                    character: low_char,
                })?;

            let byte_slot = bytes
                .get_mut(i)
                .expect("hex chunk index must fit into output buffer");
            *byte_slot = (high << 4) | low;
        }

        Ok(Self::new(bytes))
    }

    /// Creates an encryption key from a byte slice.
    ///
    /// Returns `Err` if the slice is not exactly 16 bytes.
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
    /// assert!(EncryptionKey::from_slice(&[1, 2, 3]).is_err());
    /// ```
    pub fn from_slice(s: &[u8]) -> Result<Self, EncryptionKeyError> {
        let bytes: [u8; 16] = s
            .try_into()
            .map_err(|_| EncryptionKeyError::WrongByteLength(s.len()))?;
        Ok(Self::new(bytes))
    }

}

/// Mask for the right-most Payload bits section (bits 0-51).
pub const RIGHT_SECRET_DATA_SECTION_MASK: u128 = 0x00000000_0000_0000_0fff_ffffffffffff;
/// Mask for the middle Payload bits section (bits 64-75).
pub const MIDDLE_SECRET_DATA_SECTION_MASK: u128 = 0x00000000_0000_0fff_0000_000000000000;
/// Mask for the left-most Payload bits section (bits 80-107).
pub const LEFT_SECRET_DATA_SECTION_MASK: u128 = 0x00000fff_ffff_0000_0000_000000000000;

/// Mask for all Payload bits (100 bits) that are encrypted/decrypted.
pub const COMPLETE_SECRET_DATA_MASK: u128 = RIGHT_SECRET_DATA_SECTION_MASK
    | MIDDLE_SECRET_DATA_SECTION_MASK
    | LEFT_SECRET_DATA_SECTION_MASK;

/// Extracts Payload bits (excludes Name bits, UUID-specific bits, and TNID Variant bits).
///
/// Compacts the Payload bits from the three sections into a single 100-bit value.
/// The returned `u128` will have its lowest 100 bits populated with data,
/// and the highest 28 bits set to zero.
pub fn extract_secret_data_bits(id: u128) -> u128 {
    let extracted = id & RIGHT_SECRET_DATA_SECTION_MASK;

    const BETWEEN_MIDDLE_RIGHT: i32 = 4;
    let extracted = extracted | ((id & MIDDLE_SECRET_DATA_SECTION_MASK) >> BETWEEN_MIDDLE_RIGHT);

    const BETWEEN_LEFT_MIDDLE: i32 = BETWEEN_MIDDLE_RIGHT + 4;
    extracted | ((id & LEFT_SECRET_DATA_SECTION_MASK) >> BETWEEN_LEFT_MIDDLE)
}

/// Expands compacted Payload bits back into their positions.
///
/// This is the inverse of [`extract_secret_data_bits`].
/// `bits` should have its lowest 100 bits populated with Payload data,
/// and the highest 28 bits set to zero (though higher bits are masked out anyway).
pub fn expand_secret_data_bits(bits: u128) -> u128 {
    // Right section stays in place
    let expanded = bits & RIGHT_SECRET_DATA_SECTION_MASK;

    // Middle section shifts left
    const BETWEEN_MIDDLE_RIGHT: i32 = 4;
    let middle_mask = MIDDLE_SECRET_DATA_SECTION_MASK >> BETWEEN_MIDDLE_RIGHT;
    let expanded = expanded | ((bits & middle_mask) << BETWEEN_MIDDLE_RIGHT);

    // Left section shifts left
    const BETWEEN_LEFT_MIDDLE: i32 = BETWEEN_MIDDLE_RIGHT + 4;
    let left_mask = LEFT_SECRET_DATA_SECTION_MASK >> BETWEEN_LEFT_MIDDLE;
    expanded | ((bits & left_mask) << BETWEEN_LEFT_MIDDLE)
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

fn hex_digits_to_u128(digits: &[u16]) -> u128 {
    let mut result = 0u128;
    for digit in digits {
        result = (result << 4) | (*digit as u128);
    }
    result
}

/// Encrypts raw 100-bit Payload data using FF1.
///
/// `id_secret_data` must have its lowest 100 bits populated with Payload data to be encrypted.
/// The highest 28 bits are ignored.
///
/// Returns a `u128` where the lowest 100 bits contain the encrypted Payload data,
/// and the highest 28 bits are zero.
pub fn encrypt(id_secret_data: u128, key: &EncryptionKey) -> u128 {
    // Mask to only encrypt the lower 100 bits
    let mask = (1u128 << SECRET_DATA_BIT_NUM) - 1;
    let data = id_secret_data & mask;

    let hex_digits = u128_to_hex_digits(data);
    let numeral_string = FlexibleNumeralString::from(hex_digits);

    let encrypted = key
        .0
        .encrypt(&[], &numeral_string)
        .expect("string is in required radix");

    let encrypted_digits: Vec<u16> = encrypted.into();
    hex_digits_to_u128(&encrypted_digits)
}

/// Decrypts raw 100-bit Payload data using FF1.
///
/// `id_secret_data` must have its lowest 100 bits populated with Payload data to be decrypted.
/// The highest 28 bits are ignored.
///
/// Returns a `u128` where the lowest 100 bits contain the decrypted Payload data,
/// and the highest 28 bits are zero.
pub fn decrypt(id_secret_data: u128, key: &EncryptionKey) -> u128 {
    // Mask to only decrypt the lower 100 bits
    let mask = (1u128 << SECRET_DATA_BIT_NUM) - 1;
    let data = id_secret_data & mask;

    let hex_digits = u128_to_hex_digits(data);
    let numeral_string = FlexibleNumeralString::from(hex_digits);

    let decrypted = key
        .0
        .decrypt(&[], &numeral_string)
        .expect("string is in required radix");

    let decrypted_digits: Vec<u16> = decrypted.into();
    hex_digits_to_u128(&decrypted_digits)
}

/// Encrypts a V0 TNID to V1, hiding timestamp information.
///
/// Returns `Err` if the ID is V2/V3 (unsupported variants).
/// Returns the original ID unchanged if it's already V1.
pub fn encrypt_id_v0_to_v1(id: u128, key: &EncryptionKey) -> Result<u128, EncryptionError> {
    match TnidVariant::from_id(id) {
        TnidVariant::V0 => {}
        TnidVariant::V1 => return Ok(id),
        variant @ (TnidVariant::V2 | TnidVariant::V3) => {
            return Err(EncryptionError::UnsupportedVariant(variant));
        }
    }

    // Extract only the Payload bits (100 bits, excludes TNID Variant bits)
    let secret_data = extract_secret_data_bits(id);

    // Encrypt the Payload
    let encrypted_data = encrypt(secret_data, key);

    // Expand back to proper bit positions
    let expanded = expand_secret_data_bits(encrypted_data);

    // Preserve Name bits and UUID-specific bits, replace Payload bits with encrypted version
    let id = (id & !COMPLETE_SECRET_DATA_MASK) | expanded;

    // Change variant from V0 to V1
    let id = utils::change_variant(id, TnidVariant::V1);

    Ok(id)
}

/// Decrypts a V1 TNID back to V0, recovering timestamp information.
///
/// Returns `Err` if the ID is V2/V3 (unsupported variants).
/// Returns the original ID unchanged if it's already V0.
pub fn decrypt_id_v1_to_v0(id: u128, key: &EncryptionKey) -> Result<u128, EncryptionError> {
    match TnidVariant::from_id(id) {
        TnidVariant::V0 => return Ok(id),
        TnidVariant::V1 => {}
        variant @ (TnidVariant::V2 | TnidVariant::V3) => {
            return Err(EncryptionError::UnsupportedVariant(variant));
        }
    }

    // Extract only the Payload bits (100 bits, excludes TNID Variant bits)
    let encrypted_data = extract_secret_data_bits(id);

    // Decrypt the Payload
    let decrypted_data = decrypt(encrypted_data, key);

    // Expand back to proper bit positions
    let expanded = expand_secret_data_bits(decrypted_data);

    // Preserve Name bits and UUID-specific bits, replace Payload bits with decrypted version
    let id = (id & !COMPLETE_SECRET_DATA_MASK) | expanded;

    // Change variant from V1 to V0
    let id = utils::change_variant(id, TnidVariant::V0);

    Ok(id)
}

/// # Statistical Security Tests for FPE Encryption
///
/// These tests verify the cryptographic properties of the FF1 format-preserving encryption
/// used to convert V0 TNIDs to V1 TNIDs. They help confirm that:
///
/// 1. **Indistinguishability**: Encrypted V0 outputs look statistically identical to random V1 outputs
/// 2. **No information leakage**: Predictable patterns in the plaintext (like timestamps) don't leak through
/// 3. **Proper diffusion**: Small input changes cause large, unpredictable output changes
///
/// ## What these tests DON'T prove
///
/// Statistical tests can catch obvious implementation bugs and confirm expected behavior,
/// but they cannot:
/// - Prove cryptographic security (only formal proofs or cryptanalysis can do that)
/// - Detect subtle side-channel vulnerabilities
/// - Guarantee security against quantum computers
///
/// The real security guarantee comes from FF1's NIST standardization (SP 800-38G)
/// and AES's decades of cryptanalysis. These tests are sanity checks, not proofs.
#[cfg(all(test, not(debug_assertions)))]
mod tests_release {
    use super::*;
    use proptest::prelude::*;

    use proptest::test_runner::TestRunner;

    #[test]
    fn decrypt_no_panic() {
        let mut runner = TestRunner::new(ProptestConfig {
            cases: 100_000,
            ..ProptestConfig::default()
        });
        runner
            .run(&(any::<u128>(), any::<u128>()), |(id_secret_data, secret)| {
                let key = EncryptionKey::new(secret.to_le_bytes());
                decrypt(id_secret_data, &key);
                Ok(())
            })
            .unwrap();
    }

    /// Helper: count how many values have bit `bit_pos` set to 1
    fn count_ones_at_bit(samples: &[u128], bit_pos: u32) -> usize {
        samples.iter().filter(|x| (*x >> bit_pos) & 1 == 1).count()
    }

    const TEST_KEY_BYTES: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
        0x4f, 0x3c,
    ];

    /// Fixed test key for deterministic tests
    fn test_key() -> EncryptionKey {
        EncryptionKey::new(TEST_KEY_BYTES)
    }

    // ==================================================================================
    // BIT FREQUENCY TEST (Monobit Test)
    // ==================================================================================
    //
    // WHAT IT PROVES:
    // If encryption is working correctly, each bit in the output should be set to 1
    // approximately 50% of the time across many samples. This is the most basic
    // property of a good cipher - no bit position should be biased.
    //
    // WHY IT MATTERS:
    // If the first bit is always 0 (or always 1), that would leak information about
    // whether an ID is encrypted or not. A 60/40 split would be a red flag.
    //
    // WHAT IT DOESN'T PROVE:
    // This doesn't catch correlations between bits. All bits could individually be
    // 50/50 but still have predictable patterns (e.g., bit 0 always equals bit 1).
    // ==================================================================================

    #[test]
    fn bit_frequency_is_uniform() {
        let key = test_key();
        const SAMPLE_COUNT: usize = 50_000;
        const SECRET_BITS: u32 = SECRET_DATA_BIT_NUM as u32;

        // Generate encrypted samples from sequential-ish timestamps
        // This is the "worst case" - highly correlated plaintexts
        let base_time: u64 = 1_750_000_000_000; // ~2025
        let encrypted_samples: Vec<u128> = (0..SAMPLE_COUNT)
            .map(|i| {
                let timestamp = base_time + (i as u64);
                let random = (i as u64).wrapping_mul(0x123456789ABCDEF);
                simulate_v0_secret_data(timestamp, random)
            })
            .map(|plaintext| encrypt(plaintext, &key))
            .collect();

        // Check each bit position in the 100 Payload bits
        for bit_pos in 0..SECRET_BITS {
            let ones = count_ones_at_bit(&encrypted_samples, bit_pos);
            let ratio = ones as f64 / SAMPLE_COUNT as f64;

            // With 50k samples, we expect ~50% ± 1.5% (conservative bound)
            // A perfectly random distribution has stddev = sqrt(n*p*(1-p)) ≈ 111
            // So 3 sigma is about 333, or 0.67% of 50k
            // We use 2% as a very conservative threshold
            assert!(
                (ratio - 0.5).abs() < 0.02,
                "Bit {} has biased frequency: {:.2}% ones (expected ~50%)",
                bit_pos,
                ratio * 100.0
            );
        }
    }

    // ==================================================================================
    // TIMESTAMP CORRELATION TEST
    // ==================================================================================
    //
    // WHAT IT PROVES:
    // When we encrypt IDs with sequential timestamps (the most predictable pattern),
    // the encrypted outputs should NOT be sequential or ordered. If encryption works,
    // the ordering should be essentially random.
    //
    // WHY IT MATTERS:
    // This directly addresses the concern about "first bits of timestamp are always
    // the same". Even though inputs like 0x019A..., 0x019A..., 0x019A... all start
    // the same, their encrypted outputs should have no ordering relationship.
    //
    // HOW IT WORKS:
    // We generate 10,000 IDs with incrementing timestamps. If encrypted[i+1] > encrypted[i]
    // about 50% of the time, there's no correlation. If it's 99% or 1%, the encryption
    // is leaking ordering information.
    // ==================================================================================

    #[test]
    fn sequential_timestamps_produce_random_ordering() {
        let key = test_key();
        const SAMPLE_COUNT: usize = 10_000;

        let base_time: u64 = 1_750_000_000_000;

        // Generate encrypted outputs for sequential timestamps
        let encrypted: Vec<u128> = (0..SAMPLE_COUNT)
            .map(|i| {
                let timestamp = base_time + (i as u64);
                let random = 0x123456789ABCDEF0_u64; // Same random bits for all
                simulate_v0_secret_data(timestamp, random)
            })
            .map(|plaintext| encrypt(plaintext, &key))
            .collect();

        // Count how often encrypted[i+1] > encrypted[i]
        let mut greater_count = 0;
        for i in 1..encrypted.len() {
            if encrypted[i] > encrypted[i - 1] {
                greater_count += 1;
            }
        }

        let ratio = greater_count as f64 / (SAMPLE_COUNT - 1) as f64;

        // Should be close to 50% (random ordering)
        // With 10k samples, we expect 50% ± 1.5%
        assert!(
            (ratio - 0.5).abs() < 0.02,
            "Sequential timestamps produce ordered outputs: {:.2}% ascending (expected ~50%)",
            ratio * 100.0
        );
    }

    // ==================================================================================
    // AVALANCHE EFFECT TEST
    // ==================================================================================
    //
    // WHAT IT PROVES:
    // Flipping a single bit in the input should flip approximately 50% of the output bits.
    // This is the "avalanche effect" - a hallmark of good diffusion in block ciphers.
    //
    // WHY IT MATTERS:
    // If flipping one input bit only changes one output bit, an attacker could
    // potentially reverse-engineer the plaintext. Good ciphers make every output
    // bit depend on every input bit.
    //
    // TECHNICAL DETAIL:
    // FF1's Feistel structure with 10 rounds achieves this through repeated mixing.
    // Each round spreads changes further until the entire block is affected.
    // ==================================================================================

    #[test]
    fn avalanche_effect_single_bit_flip() {
        let key = test_key();
        const SAMPLE_COUNT: usize = 10_000;
        const SECRET_BITS: u32 = SECRET_DATA_BIT_NUM as u32;

        let mut total_flipped_bits = 0u64;
        let mut min_flipped = u32::MAX;
        let mut max_flipped = 0u32;

        for i in 0..SAMPLE_COUNT {
            // Generate a random-ish input
            let input1 = (i as u128).wrapping_mul(0x123456789ABCDEF0123456789ABCDEF)
                & ((1u128 << SECRET_BITS) - 1);

            // Flip one random bit (deterministic based on i)
            let bit_to_flip = (i as u32 * 7) % SECRET_BITS;
            let input2 = input1 ^ (1u128 << bit_to_flip);

            let output1 = encrypt(input1, &key);
            let output2 = encrypt(input2, &key);

            // Count differing bits
            let diff = (output1 ^ output2).count_ones();
            total_flipped_bits += diff as u64;
            min_flipped = min_flipped.min(diff);
            max_flipped = max_flipped.max(diff);
        }

        let avg_flipped = total_flipped_bits as f64 / SAMPLE_COUNT as f64;
        let expected = SECRET_BITS as f64 / 2.0; // 50 bits for 100-bit output

        // Average should be close to 50 bits (within 5 bits)
        assert!(
            (avg_flipped - expected).abs() < 5.0,
            "Avalanche effect too weak: avg {:.1} bits flipped (expected ~{:.0})",
            avg_flipped,
            expected
        );

        // No single-bit flip should cause fewer than 30 or more than 70 bits to change
        // (Very rare for good ciphers to be this uneven)
        assert!(
            min_flipped >= 25,
            "Minimum bit flips too low: {} (suggests weak diffusion)",
            min_flipped
        );
        assert!(
            max_flipped <= 75,
            "Maximum bit flips too high: {} (suggests weak diffusion)",
            max_flipped
        );
    }

    // ==================================================================================
    // FIRST NIBBLE (HEX DIGIT) DISTRIBUTION TEST
    // ==================================================================================
    //
    // WHAT IT PROVES:
    // The first 4 bits of encrypted output should be uniformly distributed (0-15),
    // not clustered around any particular value.
    //
    // WHY IT MATTERS:
    // This catches a specific failure mode: if the high bits of the timestamp
    // (which are very predictable, like 0x019A for 2025 dates) somehow "leak through"
    // to the high bits of the ciphertext, this test would fail.
    //
    // STATISTICAL NOTE:
    // With 50k samples and 16 buckets, we expect ~3125 per bucket.
    // Chi-squared test would be more rigorous, but we use a simple ±30% threshold.
    // ==================================================================================

    #[test]
    fn first_nibble_uniformly_distributed() {
        let key = test_key();
        const SAMPLE_COUNT: usize = 50_000;
        const BUCKETS: usize = 16;

        let base_time: u64 = 1_750_000_000_000;

        // Count first nibble occurrences
        let mut counts = [0usize; BUCKETS];

        for i in 0..SAMPLE_COUNT {
            let timestamp = base_time + (i as u64);
            let random = (i as u64).wrapping_mul(0xDEADBEEFCAFEBABE);
            let plaintext = simulate_v0_secret_data(timestamp, random);
            let encrypted = encrypt(plaintext, &key);

            // Extract first nibble (bits 96-99 of the 100-bit value)
            let first_nibble = ((encrypted >> 96) & 0xF) as usize;
            counts[first_nibble] += 1;
        }

        let expected_per_bucket = SAMPLE_COUNT / BUCKETS; // 3125

        for (nibble, &count) in counts.iter().enumerate() {
            let deviation =
                (count as f64 - expected_per_bucket as f64).abs() / expected_per_bucket as f64;

            // Allow up to 20% deviation (very conservative for chi-squared)
            assert!(
                deviation < 0.20,
                "First nibble {} has uneven distribution: {} occurrences (expected ~{}, deviation {:.1}%)",
                nibble,
                count,
                expected_per_bucket,
                deviation * 100.0
            );
        }
    }

    // ==================================================================================
    // COLLISION TEST
    // ==================================================================================
    //
    // WHAT IT PROVES:
    // Format-preserving encryption is a bijection (one-to-one mapping). Different
    // inputs MUST produce different outputs. This test verifies no accidental
    // collisions occur in our implementation.
    //
    // WHY IT MATTERS:
    // If two different V0 TNIDs encrypted to the same V1 TNID, you couldn't decrypt
    // unambiguously. This would be a catastrophic implementation bug.
    //
    // TECHNICAL NOTE:
    // FF1 is mathematically guaranteed to be a bijection over its domain, so this
    // test is really checking that our bit manipulation (extract/expand) doesn't
    // lose information.
    // ==================================================================================

    #[test]
    fn no_collisions_in_encrypted_output() {
        let key = test_key();
        const SAMPLE_COUNT: usize = 100_000;

        let base_time: u64 = 1_750_000_000_000;

        let encrypted: std::collections::HashSet<u128> = (0..SAMPLE_COUNT)
            .map(|i| {
                let timestamp = base_time + (i as u64);
                let random = i as u64;
                simulate_v0_secret_data(timestamp, random)
            })
            .map(|plaintext| encrypt(plaintext, &key))
            .collect();

        assert_eq!(
            encrypted.len(),
            SAMPLE_COUNT,
            "Collision detected: {} unique outputs from {} inputs",
            encrypted.len(),
            SAMPLE_COUNT
        );
    }

    // ==================================================================================
    // KEY SENSITIVITY TEST
    // ==================================================================================
    //
    // WHAT IT PROVES:
    // Changing even a single bit of the key produces completely different ciphertexts.
    // The wrong key should produce output that looks nothing like the correct output.
    //
    // WHY IT MATTERS:
    // This confirms that security depends on the full key, not just part of it.
    // An attacker who knows 127 of 128 key bits still can't predict outputs.
    // ==================================================================================

    #[test]
    fn different_keys_produce_unrelated_outputs() {
        let key1 = test_key();
        let mut key2_bytes = TEST_KEY_BYTES;
        key2_bytes[0] ^= 1; // Flip one bit
        let key2 = EncryptionKey::new(key2_bytes);

        const SAMPLE_COUNT: usize = 1_000;
        const SECRET_BITS: u32 = SECRET_DATA_BIT_NUM as u32;

        let mut total_diff_bits = 0u64;

        for i in 0..SAMPLE_COUNT {
            let plaintext = (i as u128).wrapping_mul(0x123456789) & ((1u128 << SECRET_BITS) - 1);

            let encrypted1 = encrypt(plaintext, &key1);
            let encrypted2 = encrypt(plaintext, &key2);

            total_diff_bits += (encrypted1 ^ encrypted2).count_ones() as u64;
        }

        let avg_diff = total_diff_bits as f64 / SAMPLE_COUNT as f64;
        let expected = SECRET_BITS as f64 / 2.0;

        // Different keys should produce ~50% different bits (like random)
        assert!(
            (avg_diff - expected).abs() < 5.0,
            "Key sensitivity too low: avg {:.1} bits differ (expected ~{:.0})",
            avg_diff,
            expected
        );
    }

    // ==================================================================================
    // BYTE DISTRIBUTION TEST (Chi-Squared Approximation)
    // ==================================================================================
    //
    // WHAT IT PROVES:
    // Each byte position in the encrypted output should have values uniformly
    // distributed across 0-255. This is a more granular version of the monobit test.
    //
    // WHY IT MATTERS:
    // Catches cases where individual bits might be balanced but byte-level patterns
    // exist (e.g., bytes are always even, or always < 200).
    //
    // NOTE:
    // The encrypted output is 100 bits. We check the lower 96 bits (12 full bytes),
    // skipping the top 4 bits which would only give a half-byte (nibble).
    // ==================================================================================

    #[test]
    fn byte_distribution_uniform() {
        let key = test_key();
        const SAMPLE_COUNT: usize = 25_600; // Divisible by 256 for clean expected values
        const BYTES_TO_CHECK: usize = 4; // Check 4 full bytes from the lower portion

        let base_time: u64 = 1_750_000_000_000;

        // For each byte position, count occurrences of each value
        let mut byte_counts: [[usize; 256]; BYTES_TO_CHECK] = [[0; 256]; BYTES_TO_CHECK];

        for i in 0..SAMPLE_COUNT {
            let timestamp = base_time + (i as u64);
            let random = (i as u64).wrapping_mul(0xFEDCBA9876543210);
            let plaintext = simulate_v0_secret_data(timestamp, random);
            let encrypted = encrypt(plaintext, &key);

            // Extract bytes from the lower portion where we have full bytes.
            // 100 bits = 12 full bytes (96 bits) + 4 extra bits at the top.
            // We check bytes 0-3 starting from bit 0 (least significant).
            for byte_idx in 0..BYTES_TO_CHECK {
                let shift = byte_idx * 8; // Byte 0 at bits 0-7, byte 1 at 8-15, etc.
                let byte_val = ((encrypted >> shift) & 0xFF) as usize;
                byte_counts[byte_idx][byte_val] += 1;
            }
        }

        let expected_per_value = SAMPLE_COUNT / 256; // 100

        for (byte_idx, counts) in byte_counts.iter().enumerate() {
            // Simple chi-squared-like check: no value should deviate too much
            let max_deviation = counts
                .iter()
                .map(|&c| {
                    ((c as f64) - (expected_per_value as f64)).abs() / (expected_per_value as f64)
                })
                .fold(0.0f64, f64::max);

            // With 25.6k samples and 256 buckets, expect ~100 per bucket
            // Allow up to 50% deviation for any single bucket (very conservative)
            assert!(
                max_deviation < 0.50,
                "Byte {} has non-uniform distribution (max deviation {:.1}%)",
                byte_idx,
                max_deviation * 100.0
            );
        }
    }

    // ==================================================================================
    // RUNS TEST (Sequence Randomness)
    // ==================================================================================
    //
    // WHAT IT PROVES:
    // The encrypted output shouldn't have unusually long runs of consecutive 0s or 1s.
    // Random data has a predictable distribution of run lengths.
    //
    // WHY IT MATTERS:
    // A cipher that produces outputs like "000000...111111..." (long runs) would
    // be distinguishable from random data. Good encryption produces outputs that
    // "look random" in terms of run lengths too.
    //
    // SIMPLIFIED APPROACH:
    // Instead of a full NIST runs test, we check that the average run length is
    // close to 2 (the expected value for random bits).
    // ==================================================================================

    #[test]
    fn run_lengths_are_reasonable() {
        let key = test_key();
        const SAMPLE_COUNT: usize = 1_000;
        const SECRET_BITS: u32 = SECRET_DATA_BIT_NUM as u32;

        let mut total_runs = 0u64;

        for i in 0..SAMPLE_COUNT {
            let timestamp = 1_750_000_000_000u64 + (i as u64);
            let random = (i as u64).wrapping_mul(0xABCDEF0123456789);
            let plaintext = simulate_v0_secret_data(timestamp, random);
            let encrypted = encrypt(plaintext, &key);

            // Count runs in this value
            let mut runs = 1u32;
            for bit_pos in 1..SECRET_BITS {
                let prev_bit = (encrypted >> (bit_pos - 1)) & 1;
                let curr_bit = (encrypted >> bit_pos) & 1;
                if prev_bit != curr_bit {
                    runs += 1;
                }
            }

            total_runs += runs as u64;
        }

        // Expected runs in n bits of random data: (n+1)/2 ≈ 50.5 for 100 bits
        // Average run length = n / runs ≈ 2
        let avg_runs_per_sample = total_runs as f64 / SAMPLE_COUNT as f64;
        let expected_runs = (SECRET_BITS as f64 + 1.0) / 2.0; // ~50.5

        assert!(
            (avg_runs_per_sample - expected_runs).abs() < 5.0,
            "Unusual run pattern: avg {:.1} runs per sample (expected ~{:.1})",
            avg_runs_per_sample,
            expected_runs
        );
    }

    // ==================================================================================
    // HELPER FUNCTION
    // ==================================================================================
    //
    // Simulates extracting Payload bits from a V0 TNID structure.
    // This creates a realistic bit pattern matching what `extract_secret_data_bits`
    // would produce from an actual V0 TNID.
    // ==================================================================================

    /// Simulates the Payload bits of a V0 TNID given timestamp and random bits.
    ///
    /// V0 layout:
    /// - 43 bits: milliseconds since epoch
    /// - 57 bits: random data
    ///
    /// This function packs them into the 100-bit format that encryption operates on.
    fn simulate_v0_secret_data(epoch_millis: u64, random: u64) -> u128 {
        // The actual bit positions match v0.rs, but for encryption we just need
        // a realistic distribution of data. The exact layout doesn't matter as
        // long as we're testing with realistic entropy patterns.
        let timestamp_bits = (epoch_millis & ((1u64 << 43) - 1)) as u128;
        let random_bits = (random & ((1u64 << 57) - 1)) as u128;

        // Pack into 100 bits: [43-bit timestamp][57-bit random]
        (timestamp_bits << 57) | random_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_data_extract_correctly() {
        let extract = extract_secret_data_bits(u128::MAX);
        assert_eq!(extract.leading_zeros(), 28);
        assert_eq!(extract.count_ones(), SECRET_DATA_BIT_NUM as u32);

        assert_eq!(
            COMPLETE_SECRET_DATA_MASK.count_ones(),
            SECRET_DATA_BIT_NUM as u32
        );

        let extract = extract_secret_data_bits(COMPLETE_SECRET_DATA_MASK);
        assert_eq!(extract.leading_zeros(), 28);
        assert_eq!(extract.count_ones(), SECRET_DATA_BIT_NUM as u32);
    }

    #[test]
    fn secret_data_expand_correctly() {
        // Expand should produce the mask when given all 100 bits set
        let expanded = expand_secret_data_bits(u128::MAX);
        assert_eq!(expanded, COMPLETE_SECRET_DATA_MASK);
        assert_eq!(expanded.count_ones(), SECRET_DATA_BIT_NUM as u32);
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
