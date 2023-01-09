use ethereum_types::{H256, U256};

use crate::{parameters::VERKLE_NODE_WIDTH, Address32, Hasher};

#[must_use]
pub(crate) fn swap_last_byte(mut hash: H256, byte: U256) -> H256 {
    let byte: u8 = byte
        .as_u32()
        .try_into()
        .expect("number cannot be represented as a byte");

    let bytes = hash.as_bytes_mut();
    let last_byte = bytes.last_mut().expect("infallible");
    *last_byte = byte;
    hash
}

pub(crate) fn hash_addr_int<H: Hasher>(addr: Address32, integer: U256) -> H256 {
    let address_bytes = addr.as_fixed_bytes();

    let mut integer_bytes = [0u8; 32];
    integer.to_little_endian(&mut integer_bytes);

    let mut hash_input = [0u8; 64];
    let (first_half, second_half) = hash_input.split_at_mut(32);

    // Copy address and index into slice, then hash it
    first_half.copy_from_slice(address_bytes);
    second_half.copy_from_slice(&integer_bytes);

    H::hash64(hash_input)
}

// Chunk the input into 16 byte integers. This is because the scalar field
// we are using can not hold full 256 bit integers.
pub(crate) fn chunk_bytes(input: &[u8]) -> Vec<u128> {
    // We can only commit to VERKLE_NODE_WIDTH elements at once
    // since we need 1 element to represent the encoding flag
    // the commit capcacit is therefore the WIDTH-1
    let commit_capacity = (VERKLE_NODE_WIDTH - 1u8).as_u32() as usize;

    // We will chop our byte slice into 16 byte integers
    // Therefore we need to ensure that the input is not too large
    assert!(input.len() <= (commit_capacity * 16));

    // This is so that we can seperate the extension marker and suffix commmitments
    // from this. ExtMarker = 1;SuffixMarker = 0;
    let type_encoding: u128 = 2;
    // 256 * input.len() has an upper bound of 2^8 * 2^8 ^ 2^4
    // hence any integer that can hold more than 20 bits, will be enough
    let encoding_flag: u128 = type_encoding + 256 * input.len() as u128;

    // We will pad the input with zeroes. This is to ensure
    // that when we chunk the slice into 16 byte integers, everything is aligned
    // Also note that in our case, H(x, 0) = H(x) , so the zeroes
    // can be ignored, but this is not the case with functions like sha256
    // Hence this way is future proof. One could also argue that since the
    // length is encoded, then we can skip the zeroes
    //
    // TODO: this pads to 255*16, but we really only need it to be aligned
    let pad_by = commit_capacity * 16 - input.len();
    // Make the input 16 byte aligned
    let mut aligned_input = encoding_flag.to_le_bytes().to_vec();
    aligned_input.extend_from_slice(input);
    aligned_input.extend(vec![0u8; pad_by]);

    let mut input_as_u128 = Vec::new();

    //Now chunk the input into 16 byte chunks
    for chunk in aligned_input.chunks(16) {
        let chunk: [u8; 16] = chunk
            .try_into()
            .expect("input is not 16 byte aligned. This should not happen after padding is added.");
        input_as_u128.push(u128::from_le_bytes(chunk))
    }

    input_as_u128
}

// Specialised version of `chunk_bytes` for 64 bytes without the padding
pub(crate) fn chunk64(bytes64: [u8; 64]) -> [u128; 5] {
    const INPUT_LEN: u128 = 64;

    let mut chunked_input = [[0u8; 16]; 5];

    let type_encoding: u128 = 2;
    let encoding_flag = (type_encoding + 256 * INPUT_LEN).to_le_bytes();
    chunked_input[0] = encoding_flag;

    for (c_input, chunk) in chunked_input.iter_mut().skip(1).zip(bytes64.chunks(16)) {
        c_input.copy_from_slice(chunk)
    }

    let mut input_as_u128 = [0u128; 5];

    for (result, chunk) in (input_as_u128).iter_mut().zip(chunked_input) {
        *result = u128::from_le_bytes(chunk)
    }

    input_as_u128
}
// Pads the input until it is a multiple of `alignment`
pub(crate) fn zero_align_bytes(mut bytes: Vec<u8>, alignment: usize) -> Vec<u8> {
    assert!(alignment > 0);

    if bytes.len() % alignment == 0 {
        return bytes;
    }

    let pad_by = alignment - bytes.len() % alignment;
    bytes.extend(vec![0u8; pad_by]);

    bytes
}

#[test]
fn swap_byte() {
    let replacement_byte = 123u8;

    let hash = H256::repeat_byte(2);
    let got = swap_last_byte(hash, U256::from(replacement_byte));

    let mut expected = *hash.as_fixed_bytes();
    *expected.last_mut().unwrap() = replacement_byte;

    assert_eq!(*got.as_fixed_bytes(), expected)
}
#[test]
fn chunk_bytes_consistency() {
    let bytes = [1u8; 64];
    let res_cbytes = chunk_bytes(&bytes);
    let mut res_c64 = chunk64(bytes).to_vec();

    let len_diff = res_cbytes.len() - res_c64.len();
    let pad = vec![0u128; len_diff];
    res_c64.extend(pad);

    assert_eq!(res_c64, res_cbytes);
}
#[test]
fn check_padding() {
    // We check alignment upto x
    let end = 150;

    for alignment in 1..end {
        for initial_num_elements in 0..alignment {
            let bytes = vec![0; initial_num_elements];
            let result = zero_align_bytes(bytes, alignment);

            // The result should be aligned
            assert_eq!(result.len() % alignment, 0)
        }
    }
}
