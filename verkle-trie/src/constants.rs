use ark_ff::BigInteger256;
use ark_serialize::CanonicalSerialize;
pub use bandersnatch::Fr;
use ipa_multipoint::multiproof::CRS;

pub const FLUSH_BATCH: u32 = 20_000;
// This library only works for a width of 256. It can be modified to work for other widths, but this is
// out of scope for this project.
pub const VERKLE_NODE_WIDTH: usize = 256;
// Seed used to compute the 256 pedersen generators
// using try-and-increment
const PEDERSEN_SEED: &'static [u8] = b"eth_verkle_oct_2021";

pub(crate) const TWO_POW_128: Fr = Fr::new(BigInteger256([
    3195623856215021945,
    6342950750355062753,
    18424290587888592554,
    1249884543737537366,
]));

use once_cell::sync::Lazy;
pub static CRS: Lazy<CRS> = Lazy::new(|| CRS::new(VERKLE_NODE_WIDTH, PEDERSEN_SEED));
