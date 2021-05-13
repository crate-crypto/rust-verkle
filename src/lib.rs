#![feature(test)]
extern crate test;

pub mod commitment;
pub mod hash;
mod interop;
pub mod kzg10;
pub mod transcript;
pub mod trie;
pub mod util;
pub mod verkle;

use ark_bls12_381::Bls12_381;
pub use commitment::VerkleCommitment;
use hash::Hash;
use kzg10::{CommitKey, OpeningKey, PublicParameters};
pub use trie::{VerkleTrait, VerkleTrie};
pub use verkle::{VerklePath, VerkleProof};

use sha2::Digest;
pub type HashFunction = sha2::Sha256;

/// create a dummy srs
pub fn dummy_setup(width: usize) -> (CommitKey<Bls12_381>, OpeningKey<Bls12_381>) {
    let num_children = 1 << width;
    let degree = num_children - 1;
    let srs = PublicParameters::<Bls12_381>::setup_from_secret(
        degree,
        ark_bls12_381::Fr::from(8927347823478352432985u128),
    )
    .unwrap();
    srs.trim(degree).unwrap()
}

/// Bit extraction interprets the bytes as bits
/// It then chunkifies  all of the bits with each chunk being `WIDTH` length
/// or less. If it is less, we pad the bits with 0's to the right.
/// This is so that we are interopable with the python implementation.
/// ie, it is okay to not pad, but it will be a different number.
/// XXX: Note that this method puts a limit on the trie width.
/// since a usize is for the most part, at most 64 bits
// XXX: Change name of method, it extracts all bits
pub fn bit_extraction(bytes: &[u8], width: usize) -> Vec<usize> {
    use bitvec::prelude::*;

    let bits = bytes.view_bits::<Msb0>().to_bitvec();

    // let mut chunks = Vec::with_capacity(bytes.len() / width);

    // for chunk in bits.chunks(width) {
    //     if chunk.len() < width {
    //         // Pad it with zeroes to the right
    //         let mut chunk_alloc = chunk.to_bitvec();
    //         for _ in 0..(width - chunk.len()) {
    //             chunk_alloc.push(false)
    //         }
    //         chunks.push(chunk_alloc.load_be::<usize>());
    //         continue;
    //     }
    //     chunks.push(chunk.load_be::<usize>());
    // }

    let s: Vec<_> = bits
        .chunks(width)
        .map(|chunk_bits| {
            if chunk_bits.len() < width {
                // Pad the last chunk with zeroes if it is less than
                // the width
                let mut bv = chunk_bits.to_bitvec();
                bv.extend(bitvec![Msb0, usize; 0; width - chunk_bits.len()]);
                return bv.load_be::<usize>();
            }
            chunk_bits.load_be::<usize>()
        })
        .collect();

    s
}

// Remove duplicate code below and move into trie module
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Key(ByteArr);

impl Key {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn as_string(&self) -> String {
        self.0.as_string()
    }
    pub const fn from_arr(arr: [u8; 32]) -> Key {
        Key(ByteArr(arr))
    }
    pub const fn zero() -> Key {
        Key(ByteArr::zero())
    }
    pub const fn one() -> Key {
        Key(ByteArr::one())
    }
    pub const fn max() -> Key {
        Key(ByteArr::max())
    }

    pub fn path_indices(&self, width: usize) -> impl Iterator<Item = usize> + '_ {
        let bytes = self.as_bytes();
        bit_extraction(bytes, width).into_iter()
    }

    // Returns a list of all of the path indices where the two keys
    // are the same and the next path index where they both differ for each
    // key.
    pub fn path_difference(
        key_a: &Key,
        key_b: &Key,
        width: usize,
    ) -> (Vec<usize>, Option<usize>, Option<usize>) {
        const AVERAGE_NUMBER_OF_SHARED_INDICES: usize = 3;

        let path_indice_a = key_a.path_indices(width);
        let path_indice_b = key_b.path_indices(width);

        let mut same_path_indices = Vec::with_capacity(AVERAGE_NUMBER_OF_SHARED_INDICES);

        for (p_a, p_b) in path_indice_a.into_iter().zip(path_indice_b) {
            if p_a != p_b {
                return (same_path_indices, Some(p_a), Some(p_b));
            }
            same_path_indices.push(p_a)
        }

        (same_path_indices, None, None)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Value(ByteArr);

impl Value {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub const fn from_arr(arr: [u8; 32]) -> Value {
        Value(ByteArr(arr))
    }
    pub const fn zero() -> Value {
        Value(ByteArr::zero())
    }
    pub const fn one() -> Value {
        Value(ByteArr::one())
    }
    pub const fn max() -> Value {
        Value(ByteArr::max())
    }
}
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct ByteArr(pub [u8; 32]);

impl ByteArr {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn as_string(&self) -> String {
        hex::encode(self.0)
    }

    pub const fn zero() -> ByteArr {
        ByteArr([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
    }
    pub const fn one() -> ByteArr {
        ByteArr([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
    }
    pub const fn max() -> ByteArr {
        ByteArr([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ])
    }
}

#[test]
fn path_diff() {
    let zero = Key::zero();
    let one = Key::one();
    let width = 10;

    let (shared_path, path_diff_a, path_diff_b) = Key::path_difference(&zero, &one, width);

    // Note: this is for width = 10 bits and key_size is 256 bits.
    //
    // There are 26 paths altogether, and these keys differ at one path, the last one
    // so shared path should have 25 path indices
    assert_eq!(shared_path.len(), 25);
    // All of the shared path indices should be zero
    for path in shared_path {
        assert_eq!(path, 0)
    }

    assert_eq!(path_diff_a.unwrap(), 0);
    assert_eq!(path_diff_b.unwrap(), 16);
}
#[test]
fn ten_bit_path_index() {
    let width = 10;
    let key = Key::from_arr([
        1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 7, 0, 6, 0, 5, 0, 4, 0, 3, 0, 2, 0, 1, 0,
        0, 1,
    ]);
    let path_indices: Vec<_> = key.path_indices(width).collect();

    // These are all of the numbers we use:
    // 0 -> 0000_0000
    // 1 -> 0000_0001
    // 2 -> 0000_0010
    // 3 -> 0000_0011
    // 4 -> 0000_0100
    // 5 -> 0000_0101
    // 6 -> 0000_0110
    // 7 -> 0000_0111
    // 8 -> 0000_1000

    // 1 -> 0000_0001
    // 0 -> 0000_0000
    // 2 -> 0000_0010
    // 0 -> 0000_0000
    // 3 -> 0000_0011
    // 0 -> 0000_0000
    // 4 -> 0000_0100
    // 0 -> 0000_0000
    // 5 -> 0000_0101
    // 0 -> 0000_0000
    // 6 -> 0000_0110
    // 0 -> 0000_0000
    // 7 -> 0000_0111
    // 0 -> 0000_0000
    // 8 -> 0000_1000
    // 0 -> 0000_0000
    // 7 -> 0000_0111
    // 0 -> 0000_0000
    // 6 -> 0000_0110
    // 0 -> 0000_0000
    // 5 -> 0000_0101
    // 0 -> 0000_0000
    // 4 -> 0000_0100
    // 0 -> 0000_0000
    // 3 -> 0000_0011
    // 0 -> 0000_0000
    // 2 -> 0000_0010
    // 0 -> 0000_0000
    // 1 -> 0000_0001
    // 0 -> 0000_0000
    // 0 -> 0000_0000
    // 1 -> 0000_0001

    // Grouping them by 10 bits, we get:
    /*
        0000000100
        0000000000
        0010000000
        0000000011
        0000000000
        0001000000
        0000000001
        0100000000
        0000011000
        0000000000
        0111000000
        0000001000
        0000000000
        0001110000
        0000000001
        1000000000
        0000010100
        0000000000
        0100000000
        0000000011
        0000000000
        0000100000
        0000000000
        0100000000
        0000000000
        0000010000
    */

    // Now interpret the each number as a u16
    // This means we need to pad each binary string to be 16 bits.
    // The padding is applied to the left.
    // The first binary string is 0000000100 once padded it becomes 0000_0000_0000_0100 = 2^2 = 4
    let path_0 = &path_indices[0];
    assert_eq!(path_0, &4);

    // Now I will manually convert the rest of the array to u16s by padding each to the left
    // and interpreting it as a u16 in BE

    /*
    0000000000000100 -> 4
    0000000000000000 -> 0
    0000000010000000 -> 128
    0000000000000011 -> 3
    0000000000000000 -> 0
    0000000001000000 -> 64
    0000000000000001 -> 1
    0000000100000000 -> 256
    0000000000011000 -> 24
    0000000000000000 -> 0
    0000000111000000 -> 448
    0000000000001000 -> 8
    0000000000000000 -> 0
    0000000001110000 -> 112
    0000000000000001 -> 1
    0000001000000000 -> 512
    0000000000010100 -> 20
    0000000000000000 -> 0
    0000000100000000 -> 256
    0000000000000011 -> 3
    0000000000000000 -> 0
    0000000000100000 -> 32
    0000000000000000 -> 0
    0000000100000000 -> 256
    0000000000000000 -> 0
    0000010000000000 -> 16
            */

    // One thing to note here is that the last element was padded to the right to make it 10 bits.
    // Which would make us interpret it as 16. If this was not done, then we would interpret it as 1.

    // We now have 4,0,128,3,0,64,1,256,24,0,448,8,0,112,1,512,20,0,256,3,0,32,0,256,0,16
    let expected = vec![
        4, 0, 128, 3, 0, 64, 1, 256, 24, 0, 448, 8, 0, 112, 1, 512, 20, 0, 256, 3, 0, 32, 0, 256,
        0, 16,
    ];

    for (array_index, (got, expected)) in path_indices.into_iter().zip(expected).enumerate() {
        assert_eq!(
            got, expected,
            "indices do not match at array index {}, got {}, expected {}",
            array_index, got, expected
        )
    }
}
