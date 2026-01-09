/// The 4 possible TNID variants.
///
/// Similar to UUID variants, TNID variants have different construction that makes them useful for different situations.
#[derive(Debug, PartialEq, Eq)]
pub enum TnidVariant {
    /// V0 is most like UUIDv7, and is meant to be time-sortable. See [`Tnid::new_v0`](crate::Tnid::new_v0).
    V0,
    /// V1 is most like UUIDv4, and is meant to maximize entropy (randomness). See [`Tnid::new_v1`](crate::Tnid::new_v1).
    V1,
    /// V2 is undefined but reserved for future use.
    V2,
    /// V3 is undefined but reserved for future use.
    V3,
}

impl TnidVariant {
    /// Converts a u8 to a [`TnidVariant`].
    ///
    /// Only the bottom 2 bits are used to determine the variant (ignores the top 6 bits).
    /// For example, `0b0000_0000`, `0b0000_0100`, and `0b1111_1100` all have bottom 2 bits of `00`,
    /// so they all map to V0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::TnidVariant;
    ///
    /// // Bottom 2 bits are 0b00 -> V0
    /// assert_eq!(TnidVariant::from_u8(0b00000000), TnidVariant::V0);
    /// assert_eq!(TnidVariant::from_u8(0b11111100), TnidVariant::V0);
    ///
    /// // Bottom 2 bits are 0b01 -> V1
    /// assert_eq!(TnidVariant::from_u8(0b00000001), TnidVariant::V1);
    /// assert_eq!(TnidVariant::from_u8(0b11111101), TnidVariant::V1);
    /// ```
    pub fn from_u8(variant_bits: u8) -> TnidVariant {
        let variant_bits = variant_bits & 0b11;

        match variant_bits {
            0 => TnidVariant::V0,
            1 => TnidVariant::V1,
            2 => TnidVariant::V2,
            3 => TnidVariant::V3,
            _ => unreachable!("2 bits can only have 4 values"),
        }
    }

    /// Returns the u8 representation of this variant.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tnid::TnidVariant;
    ///
    /// assert_eq!(TnidVariant::V0.as_u8(), 0);
    /// assert_eq!(TnidVariant::V1.as_u8(), 1);
    /// assert_eq!(TnidVariant::V2.as_u8(), 2);
    /// assert_eq!(TnidVariant::V3.as_u8(), 3);
    /// ```
    pub fn as_u8(&self) -> u8 {
        match self {
            TnidVariant::V0 => 0,
            TnidVariant::V1 => 1,
            TnidVariant::V2 => 2,
            TnidVariant::V3 => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u8_no_panic() {
        for i in u8::MIN..=u8::MAX {
            TnidVariant::from_u8(i);
        }
    }
}
