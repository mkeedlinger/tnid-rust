use crate::{Case, TnidVariant};

/// Mask for the UUID version (8) and variant (RFC 4122) bits.
pub const UUID_V8_MASK: u128 = 0x00000000_0000_8000_8000_000000000000;

/// Returns the complete bitmask for UUID version/variant and TNID variant.
pub fn uuid_and_variant_mask(tnid_variant: u8) -> u128 {
    // should only take at most 2 bits
    debug_assert!(tnid_variant.leading_zeros() >= 6);

    let variant = tnid_variant as u128;

    UUID_V8_MASK | (variant << 60)
}

/// Changes the TNID variant bits in a 128-bit ID.
pub fn change_variant(id: u128, to_variant: TnidVariant) -> u128 {
    // Clear the old variant bits (bits 60-61)
    let variant_mask = 0b11u128 << 60;
    let id_without_variant = id & !variant_mask;

    // Set the new variant bits
    let new_variant = to_variant.as_u8() as u128;

    id_without_variant | (new_variant << 60)
}

/// Formats a 128-bit value as a standard UUID hex string.
///
/// Produces the format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
pub fn u128_to_uuid_string(id: u128, case: Case) -> String {
    // Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    let first_section = (id >> 96) as u32;
    let second_section = ((id >> 80) & 0xffff) as u16;
    let third_section = ((id >> 64) & 0xffff) as u16;
    let fourth_section = ((id >> 48) & 0xffff) as u16;
    let fifth_section = (id & 0xffffffffffff) as u64;

    match case {
        Case::Upper => format!(
            "{:08X}-{:04X}-{:04X}-{:04X}-{:012X}",
            first_section, second_section, third_section, fourth_section, fifth_section
        ),
        Case::Lower => format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            first_section, second_section, third_section, fourth_section, fifth_section
        ),
    }
}

/// Converts a hexadecimal character byte to its numeric value.
///
/// Returns `Some(0-15)` if the character is a valid hex digit (`0-9`, `a-f`, `A-F`),
/// otherwise returns `None`.
pub fn hex_char_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_mask_correct_location() {
        let mask = uuid_and_variant_mask(0);

        assert_eq!(mask.leading_zeros(), 48);
        assert_eq!(mask.trailing_zeros(), 63);
        assert_eq!(mask.count_ones(), 2);
    }

    #[test]
    fn change_variant_changes_only_variant_bits() {
        let id: u128 = 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef;
        let v0 = change_variant(id, TnidVariant::V0);
        let v1 = change_variant(id, TnidVariant::V1);

        // Only bits 60-61 should differ.
        let mask = 0b11u128 << 60;
        assert_eq!(id & !mask, v0 & !mask);
        assert_eq!(id & !mask, v1 & !mask);
        assert_ne!(v0 & mask, v1 & mask);
    }
}
