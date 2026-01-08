use crate::TNIDVariant;

pub const UUID_V8_MASK: u128 = 0x00000000_0000_8000_8000_000000000000;

pub fn uuid_and_variant_mask(tnid_variant: u8) -> u128 {
    // should only take at most 2 bits
    debug_assert!(tnid_variant.leading_zeros() >= 6);

    let variant = tnid_variant as u128;

    UUID_V8_MASK | (variant << 60)
}

pub fn change_variant(id: u128, to_variant: TNIDVariant) -> u128 {
    // Clear the old variant bits (bits 60-61)
    let variant_mask = 0b11u128 << 60;
    let id_without_variant = id & !variant_mask;

    // Set the new variant bits
    let new_variant = to_variant.as_u8() as u128;

    id_without_variant | (new_variant << 60)
}

pub fn u128_to_uuid_string(id: u128, uppercase: bool) -> String {
    // Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    let first_section = (id >> 96) as u32;
    let second_section = ((id >> 80) & 0xffff) as u16;
    let third_section = ((id >> 64) & 0xffff) as u16;
    let fourth_section = ((id >> 48) & 0xffff) as u16;
    let fifth_section = (id & 0xffffffffffff) as u64;

    if uppercase {
        format!(
            "{:08X}-{:04X}-{:04X}-{:04X}-{:012X}",
            first_section, second_section, third_section, fourth_section, fifth_section
        )
    } else {
        format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            first_section, second_section, third_section, fourth_section, fifth_section
        )
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
}
