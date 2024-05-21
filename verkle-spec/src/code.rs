use ethereum_types::{H256, U256};

use crate::{
    parameters::{CODE_OFFSET, VERKLE_NODE_WIDTH},
    util::{hash_addr_int, swap_last_byte, zero_align_bytes},
    Address32, Hasher,
};

pub struct Code {
    code_chunk_tree_key: H256,
}

impl Code {
    pub fn new<H: Hasher>(address: Address32, chunk_id: U256) -> Code {
        let index = (CODE_OFFSET + chunk_id) / VERKLE_NODE_WIDTH;
        let sub_index = (CODE_OFFSET + chunk_id) % VERKLE_NODE_WIDTH;

        let base_hash = hash_addr_int::<H>(address, index);
        let code_chunk_tree_key = swap_last_byte(base_hash, sub_index);

        Code {
            code_chunk_tree_key,
        }
    }

    pub fn code_chunk(&self) -> H256 {
        self.code_chunk_tree_key
    }
}

const PUSH_OFFSET: u8 = 95;
const PUSH1: u8 = PUSH_OFFSET + 1;
const PUSH32: u8 = PUSH_OFFSET + 32;

// Note: If the largest ethereum contract is ~24Kb , chunking the code
// which produces arrays, which are then stored in the stack should not give a stack
// overflow. That being said, its possible for us to store everthing as one vector and
// then call .chunks(32).try_into() when we need a [u8;32]
pub type Bytes32 = [u8; 32];

// Breaks up the code into 32 byte chunks
// The code is stored in 31 bytes and the leading byte is reserved as an indicator
// For whether the previous chunk has push data available
pub fn chunkify_code(code: Vec<u8>) -> Vec<Bytes32> {
    // First pad the input, so it is 31 byte aligned
    let aligned_code = zero_align_bytes(code, 31);

    // First we chunk the aligned code into 31 bytes
    let chunked_code31 = aligned_code.chunks_exact(31);

    let mut remaining_pushdata_bytes = Vec::new();
    // The first byte will not have any remaing push data bytes
    // Since there was no chunk that came before it
    let mut leftover_push_data = 0usize;
    remaining_pushdata_bytes.push(leftover_push_data);

    let last_chunk_index = chunked_code31.len() - 1;
    // set this to true, if the last chunk had a push data instruction that
    // needed another chunk
    let mut last_chunk_push_data = false;
    for (chunk_i, chunk) in chunked_code31.clone().enumerate() {
        // Case1: the left over push data is larger than the chunk size
        //
        // The left over push data can be larger than the chunk size
        // For example, if the last instruction was a PUSH32 and chunk size is 31
        // We can compute the left over push data for this chunk as 31, the chunk size
        // and then the left over push data for the next chunk as 32-31=1
        if leftover_push_data > chunk.len() {
            if chunk_i == last_chunk_index {
                last_chunk_push_data = true;
                break;
            }

            leftover_push_data -= chunk.len();
            remaining_pushdata_bytes.push(leftover_push_data);
            continue;
        }

        // Case2: the left over push data is smaller than the chunk size
        //
        // Increment the counter by how many bytes we need to push from the
        // previous chunk. For example, if the previous chunk ended with a PUSH4
        // we need to skip the first four bytes
        let pc = leftover_push_data;
        let offsetted_chunk = &chunk[pc..];
        leftover_push_data = compute_leftover_push_data(offsetted_chunk) as usize;
        remaining_pushdata_bytes.push(leftover_push_data.min(chunk.len()));
    }

    // Merge the remaining push data byte markers with the 31 byte chunks.
    // Note: This can be done in one for loop, for now this is easier to read.
    let mut chunked_code32: Vec<[u8; 32]> = Vec::with_capacity(chunked_code31.len());
    for (prefix_byte, chunk31) in remaining_pushdata_bytes.into_iter().zip(chunked_code31) {
        let prefix_byte: u8 = prefix_byte
            .try_into()
            .expect("prefix canot be stored in a u8. This should be infallible.");

        let mut chunk32 = [0u8; 32];
        chunk32[0] = prefix_byte;
        chunk32[1..].copy_from_slice(chunk31);
        chunked_code32.push(chunk32)
    }

    if last_chunk_push_data {
        // If the last chunk had remaining push data to be added
        // we add a new chunk with 32 zeroes. This is fine
        chunked_code32.push([0u8; 32])
    }

    chunked_code32
}
// This functions returns a number which indicates how much PUSHDATA
// we still need to process. For example, if the last byte in the slice
// contained the instruction PUSH32. This function would return 32
// because we need to process 32 bytes of data.
//
// Another example, if the code_chunk has a length of `10`
// and the first byte contains the instruction PUSH24.Then this
// method will return the number 15 because we used one byte to represent
// PUSH24 leaving 9 bytes left to store some of the 24 bytes that we need.
//
// Note this implicitly assumes that we cannot push more than 254 bytes of
// PUSHDATA
fn compute_leftover_push_data(code_chunk: &[u8]) -> u8 {
    // Start the program counter off at zero
    let mut pos = 0usize;
    while pos < code_chunk.len() {
        let curr_instruction = code_chunk[pos];
        let is_push_instruction = (PUSH1..=PUSH32).contains(&curr_instruction);

        // Increment the counter by 1 to move past the current instruction
        pos += 1;

        if is_push_instruction {
            // Figure out how many bytes we need to increment the position counter
            let amount_bytes_to_push = curr_instruction - PUSH_OFFSET;
            pos += amount_bytes_to_push as usize;
        }
    }

    // Arriving here means that the position counter went over the length of the code chunk
    // We can calculate the leftover push data by taking the offset of the counter and the length of
    // the code chunk
    let leftover: u8 = (pos - code_chunk.len())
        .try_into()
        .expect("left over cannot fit into a u8");

    leftover
}

#[test]
fn check_against_eip() {
    // This was taken directly from the EIP as a sniff test
    let push4 = PUSH_OFFSET + 4;
    let remaining = compute_leftover_push_data(&[push4, 99, 98]);
    assert_eq!(remaining, 2)
}
#[test]
fn leftover_fuzz() {
    // The push32 instruction should give us a leftover of 2, because we can only store 30 elements
    // in the remaining chunk
    let chunk: [u8; 32] = [
        3, PUSH32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30,
    ];
    let remaining = compute_leftover_push_data(&chunk);
    assert_eq!(remaining, 2);

    // Push32 at the end of the chunk should give us a leftover of 32
    let chunk: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, PUSH32,
    ];
    let remaining = compute_leftover_push_data(&chunk);
    assert_eq!(remaining, 32);

    // This should return 0, since push4 treats the PUSH32 as PUSHDATA
    let push4 = PUSH_OFFSET + 4;
    let chunk: [u8; 32] = [
        push4, PUSH32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let remaining = compute_leftover_push_data(&chunk);
    assert_eq!(remaining, 0);
}

#[test]
fn chunkify_simple_test() {
    let push4 = PUSH_OFFSET + 4;
    let push3 = PUSH_OFFSET + 3;
    let push21 = PUSH_OFFSET + 21;
    let push7 = PUSH_OFFSET + 7;
    let push30 = PUSH_OFFSET + 30;

    let code: Vec<[u8; 31]> = vec![
        // First 31 bytes
        [
            0, push4, 1, 2, 3, 4, push3, 58, 68, 12, push21, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            13, 14, 15, 16, 17, 18, 19, 20,
        ],
        // Second 31 bytes
        [
            0, push21, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            push7, 1, 2, 3, 4, 5, 6, 7,
        ],
        // Third 31 bytes
        [
            push30, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25, 26, 27, 28, 29, 30,
        ],
    ];
    let code = code.into_iter().flatten().collect();

    let chunked_code = chunkify_code(code);

    let num_chunks = chunked_code.len();
    assert_eq!(num_chunks, 3);

    let chunk1 = chunked_code[0];
    let chunk2 = chunked_code[1];
    let chunk3 = chunked_code[2];

    // The first chunk should have a leading byte of 0;
    assert_eq!(chunk1[0], 0);
    // The second chunk should have a leading byte of 1, because the last push instruction from chunk1 was PUSH21
    // and we could only store 20 bytes in that chunk
    assert_eq!(chunk2[0], 1);
    // The third chunk should have a leading by of 0, since the last push instruction was PUSH7 and we stored all 7 bytes
    // in the second chunk
    assert_eq!(chunk3[0], 0);
}

#[test]
fn chunkify_with_push32_at_end_test() {
    let push21 = PUSH_OFFSET + 21;

    let code: Vec<[u8; 31]> = vec![
        // First 31 bytes
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, PUSH32,
        ],
        // Second 31 bytes
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31,
        ],
        // Third 31 bytes
        [
            32, push21, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            0, 0, 0, 0, 0, 0, 0, 0,
        ],
    ];
    let code = code.into_iter().flatten().collect();

    let chunked_code = chunkify_code(code);

    let num_chunks = chunked_code.len();
    assert_eq!(num_chunks, 3);

    let chunk1 = chunked_code[0];
    let chunk2 = chunked_code[1];
    let chunk3 = chunked_code[2];

    // The first chunk should have a leading byte of 0;
    assert_eq!(chunk1[0], 0);
    // The second chunk should have a leading byte of 31, because the last push instruction from chunk1 was PUSH32
    // and we couldn't store any of 32 bytes in that chunk, but chunk can store only 31 non-leading bytes.
    assert_eq!(chunk2[0], 31);
    // The third chunk should have a leading byte of 1, because the last push instruction was PUSH32 in chunk1 that
    // we didn't finish in chunk2.
    assert_eq!(chunk3[0], 1);
}
