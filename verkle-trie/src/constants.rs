use banderwagon::fr_from_u64_limbs;
pub use banderwagon::Fr;
use ipa_multipoint::{crs::CRS, lagrange_basis::PrecomputedWeights};
use once_cell::sync::Lazy;

pub const FLUSH_BATCH: u32 = 20_000;
// This library only works for a width of 256. It can be modified to work for other widths, but this is
// out of scope for this project.
pub const VERKLE_NODE_WIDTH: usize = 256;
// Seed used to compute the 256 pedersen generators
// using try-and-increment
const PEDERSEN_SEED: &[u8] = b"eth_verkle_oct_2021";

pub(crate) const TWO_POW_128: Fr = fr_from_u64_limbs([0, 0, 1, 0]);

pub static CRS: Lazy<CRS> = Lazy::new(|| CRS::new(VERKLE_NODE_WIDTH, PEDERSEN_SEED));
pub fn new_crs() -> CRS {
    CRS::new(VERKLE_NODE_WIDTH, PEDERSEN_SEED)
}
pub static PRECOMPUTED_WEIGHTS: Lazy<PrecomputedWeights> =
    Lazy::new(|| PrecomputedWeights::new(VERKLE_NODE_WIDTH));

#[cfg(test)]
mod tests {
    use super::TWO_POW_128;
    use banderwagon::{trait_defs::*, Fr};

    #[test]
    fn test_two_pow128_constant() {
        let mut arr = [0u8; 17];
        arr[0] = 1;
        let expected = Fr::from_be_bytes_mod_order(&arr);
        assert_eq!(TWO_POW_128, expected)
    }
}
