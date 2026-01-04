use crate::NameStr;
use crate::name_encoding;
use crate::utils;

const RANDOM_MASK: u128 = 0x00000fff_ffff_0fff_0fff_ffffffffffff;
fn random_bits_mask(random: u128) -> u128 {
    random & RANDOM_MASK
}

pub fn make_from_parts(name: NameStr, random: u128) -> u128 {
    let mut id = 0u128;

    id |= name_encoding::name_mask(name);
    id |= utils::uuid_and_variant_mask(1);
    id |= random_bits_mask(random);

    id
}

#[cfg(test)]
mod tests {
    use std::u128;

    use super::*;

    #[test]
    fn random_mask() {
        let mask = random_bits_mask(u128::MAX);

        assert_eq!(mask.count_ones(), 100);
        assert_eq!(mask.leading_zeros(), 20);
        assert_eq!(mask.trailing_ones(), 60);
    }
}
