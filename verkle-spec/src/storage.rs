use ethereum_types::{H256, U256};

use crate::{
    parameters::{CODE_OFFSET, HEADER_STORAGE_OFFSET, MAIN_STORAGE_OFFSET, VERKLE_NODE_WIDTH},
    util::{hash_addr_int, swap_last_byte},
    Address32, Hasher,
};

pub struct Storage {
    storage_slot_tree_key: H256,
}

impl Storage {
    pub fn new<H: Hasher>(address: Address32, storage_key: U256) -> Storage {
        let pos = if storage_key < (CODE_OFFSET - HEADER_STORAGE_OFFSET) {
            HEADER_STORAGE_OFFSET + storage_key
        } else {
            MAIN_STORAGE_OFFSET + storage_key
        };

        let base_hash = hash_addr_int::<H>(address, pos / VERKLE_NODE_WIDTH);
        let storage_slot_tree_key = swap_last_byte(base_hash, pos % VERKLE_NODE_WIDTH);

        Storage {
            storage_slot_tree_key,
        }
    }

    pub fn storage_slot(&self) -> H256 {
        self.storage_slot_tree_key
    }
}
