/// Number of bits each char decodes to
pub const CHAR_BIT_LENGTH: u8 = 6;

/// Number of data bits in a TNID
pub const DATA_BIT_NUM: u8 = 102;

/// Number of chars needed to encode all the [`DATA_BIT_NUM`] bits
pub const DATA_CHAR_ENCODING_LEN: u8 = DATA_BIT_NUM / CHAR_BIT_LENGTH;

/// Number of possible chars requires to represent data chunks
const ENCODING_CHAR_NUM: u8 = 2u8.pow(CHAR_BIT_LENGTH as u32);

pub const CHAR_MAPPING: [(u8, u8); ENCODING_CHAR_NUM as usize] = [
    // dash
    (0, b'-'),
    // nums
    (1, b'0'),
    (2, b'1'),
    (3, b'2'),
    (4, b'3'),
    (5, b'4'),
    (6, b'5'),
    (7, b'6'),
    (8, b'7'),
    (9, b'8'),
    (10, b'9'),
    // uppercase alpha
    (11, b'A'),
    (12, b'B'),
    (13, b'C'),
    (14, b'D'),
    (15, b'E'),
    (16, b'F'),
    (17, b'G'),
    (18, b'H'),
    (19, b'I'),
    (20, b'J'),
    (21, b'K'),
    (22, b'L'),
    (23, b'M'),
    (24, b'N'),
    (25, b'O'),
    (26, b'P'),
    (27, b'Q'),
    (28, b'R'),
    (29, b'S'),
    (30, b'T'),
    (31, b'U'),
    (32, b'V'),
    (33, b'W'),
    (34, b'X'),
    (35, b'Y'),
    (36, b'Z'),
    // underscore
    (37, b'_'),
    // lowercase alpha
    (38, b'a'),
    (39, b'b'),
    (40, b'c'),
    (41, b'd'),
    (42, b'e'),
    (43, b'f'),
    (44, b'g'),
    (45, b'h'),
    (46, b'i'),
    (47, b'j'),
    (48, b'k'),
    (49, b'l'),
    (50, b'm'),
    (51, b'n'),
    (52, b'o'),
    (53, b'p'),
    (54, b'q'),
    (55, b'r'),
    (56, b's'),
    (57, b't'),
    (58, b'u'),
    (59, b'v'),
    (60, b'w'),
    (61, b'x'),
    (62, b'y'),
    (63, b'z'),
];

/// Error when decoding a TNID data string.
///
/// Note: This error type is generally not used directly, but is exposed through
/// [`ParseTnidError::InvalidDataEncoding`](crate::ParseTnidError::InvalidDataEncoding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataEncodingError {
    /// The data string has wrong length.
    /// Contains the actual length (expected is 17).
    WrongLength(usize),
    /// An invalid character was found in the data string.
    /// Contains the invalid byte.
    InvalidChar(u8),
}

impl std::fmt::Display for DataEncodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLength(len) => {
                write!(
                    f,
                    "data string length {len} is invalid; expected {DATA_CHAR_ENCODING_LEN} characters"
                )
            }
            Self::InvalidChar(byte) => {
                write!(
                    f,
                    "invalid character '{}' (0x{byte:02x}) in data string",
                    char::from(*byte)
                )
            }
        }
    }
}

impl std::error::Error for DataEncodingError {}

pub fn id_data_to_string(id: u128) -> String {
    let mut s = String::with_capacity(17);

    let id = extract_data_bits(id);

    for i in 1..=DATA_CHAR_ENCODING_LEN {
        let shift = (DATA_CHAR_ENCODING_LEN - i) * CHAR_BIT_LENGTH;
        let char_val: u8 = (id >> shift) as u8;
        let char_val = char_val << 2 >> 2; // remove 2 leading bits

        debug_assert!(char_val <= ENCODING_CHAR_NUM);

        let mapping = CHAR_MAPPING.iter().find(|(value, _)| *value == char_val);

        let (_, char) = mapping.expect("Mapping must exist");

        s.push(*char as char);
    }

    debug_assert_eq!(s.len(), DATA_CHAR_ENCODING_LEN as usize);
    s
}

pub(crate) fn string_to_id_data(s: &str) -> Result<u128, DataEncodingError> {
    // Validate length
    if s.len() != DATA_CHAR_ENCODING_LEN as usize {
        return Err(DataEncodingError::WrongLength(s.len()));
    }

    let mut result = 0u128;

    for c in s.bytes() {
        // Reverse lookup in CHAR_MAPPING
        let value = CHAR_MAPPING
            .iter()
            .find(|(_, char)| *char == c)
            .map(|(val, _)| val)
            .ok_or(DataEncodingError::InvalidChar(c))?;

        result = (result << CHAR_BIT_LENGTH) | (*value as u128);
    }

    Ok(result)
}

const RIGHT_DATA_SECTION_MASK: u128 = 0x00000000_0000_0000_3fff_ffffffffffff;
const MIDDLE_DATA_SECTION_MASK: u128 = 0x00000000_0000_0fff_0000_000000000000;
const LEFT_DATA_SECTION_MASK: u128 = 0x00000fff_ffff_0000_0000_000000000000;
/// Get all bits except the name and UUID parts
pub(crate) fn extract_data_bits(id: u128) -> u128 {
    let extracted = id & RIGHT_DATA_SECTION_MASK;

    const BETWEEN_MIDDLE_RIGHT: i32 = 2;
    let extracted = extracted | ((id & MIDDLE_DATA_SECTION_MASK) >> BETWEEN_MIDDLE_RIGHT);

    const BETWEEN_LEFT_MIDDLE: i32 = BETWEEN_MIDDLE_RIGHT + 4;
    extracted | ((id & LEFT_DATA_SECTION_MASK) >> BETWEEN_LEFT_MIDDLE)
}

/// Expand compacted data bits back into their positions (inverse of extract_data_bits)
pub(crate) fn expand_data_bits(compact_bits: u128) -> u128 {
    // Right section stays in place
    let expanded = compact_bits & RIGHT_DATA_SECTION_MASK;

    // Middle section shifts left
    const BETWEEN_MIDDLE_RIGHT: i32 = 2;
    let middle_mask = MIDDLE_DATA_SECTION_MASK >> BETWEEN_MIDDLE_RIGHT;
    let expanded = expanded | ((compact_bits & middle_mask) << BETWEEN_MIDDLE_RIGHT);

    // Left section shifts left
    const BETWEEN_LEFT_MIDDLE: i32 = BETWEEN_MIDDLE_RIGHT + 4;
    let left_mask = LEFT_DATA_SECTION_MASK >> BETWEEN_LEFT_MIDDLE;
    expanded | ((compact_bits & left_mask) << BETWEEN_LEFT_MIDDLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPLETE_DATA_MASK: u128 =
        RIGHT_DATA_SECTION_MASK | MIDDLE_DATA_SECTION_MASK | LEFT_DATA_SECTION_MASK;

    #[test]
    fn data_extract_correctly() {
        let extract = extract_data_bits(u128::MAX);
        assert_eq!(extract.leading_zeros(), 26);
        assert_eq!((extract).count_ones(), DATA_BIT_NUM as u32);

        assert_eq!((COMPLETE_DATA_MASK).count_ones(), DATA_BIT_NUM as u32);

        let extract = extract_data_bits(COMPLETE_DATA_MASK);
        assert_eq!(extract.leading_zeros(), 26);
        assert_eq!((extract).count_ones(), DATA_BIT_NUM as u32);

        assert_eq!((COMPLETE_DATA_MASK).count_ones(), DATA_BIT_NUM as u32);
    }

    #[test]
    fn data_encodes_correctly() {
        let encoded = id_data_to_string(COMPLETE_DATA_MASK);
        assert_eq!(encoded.len(), DATA_CHAR_ENCODING_LEN as usize);
        assert_eq!(encoded, String::from("zzzzzzzzzzzzzzzzz"));

        let encoded = id_data_to_string(0u128);
        assert_eq!(encoded.len(), DATA_CHAR_ENCODING_LEN as usize);
        assert_eq!(encoded, String::from("-----------------"));
    }

    #[test]
    fn expand_data_bits_roundtrip() {
        let original = COMPLETE_DATA_MASK;
        let extracted = extract_data_bits(original);
        let expanded = expand_data_bits(extracted);
        assert_eq!(expanded, original);
    }

    #[test]
    fn string_to_id_data_roundtrip() {
        let original_id = 0x00000abc_def1_2345_6789_abcdef123456u128;
        let string = id_data_to_string(original_id);
        let decoded = string_to_id_data(&string).expect("valid encoding");
        assert_eq!(decoded, extract_data_bits(original_id));
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod tests_release {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 1_000_000, .. ProptestConfig::default()
        })]
        #[test]
        fn id_data_to_string_no_panic(id: u128){
            id_data_to_string(id);
        }
    }
}
