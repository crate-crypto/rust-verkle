use ethereum_types::H256;
use ethereum_types::U256;

use crate::parameters::{
    BALANCE_LEAF_KEY, CODE_KECCAK_LEAF_KEY, CODE_SIZE_LEAF_KEY, NONCE_LEAF_KEY, VERSION_LEAF_KEY,
};
use crate::util::hash_addr_int;
use crate::Hasher;
use crate::{util::swap_last_byte, Address32};

pub struct Header {
    balance_tree_key: H256,
    version_tree_key: H256,
    code_size_tree_key: H256,
    nonce_tree_key: H256,
    code_keccak_tree_key: H256,
}

impl Header {
    pub fn new<H: Hasher>(address: Address32) -> Header {
        let tree_index = U256::zero();
        Header::with_tree_index::<H>(address, tree_index)
    }

    pub fn with_tree_index<H: Hasher>(addr: Address32, tree_index: U256) -> Header {
        let base_hash = hash_addr_int::<H>(addr, tree_index);

        let version_tree_key = swap_last_byte(base_hash, VERSION_LEAF_KEY);
        let balance_tree_key = swap_last_byte(base_hash, BALANCE_LEAF_KEY);
        let nonce_tree_key = swap_last_byte(base_hash, NONCE_LEAF_KEY);
        let code_keccak_tree_key = swap_last_byte(base_hash, CODE_KECCAK_LEAF_KEY);
        let code_size_tree_key = swap_last_byte(base_hash, CODE_SIZE_LEAF_KEY);

        Header {
            balance_tree_key,
            version_tree_key,
            code_size_tree_key,
            code_keccak_tree_key,
            nonce_tree_key,
        }
    }

    pub fn balance(&self) -> H256 {
        self.balance_tree_key
    }

    pub fn nonce(&self) -> H256 {
        self.nonce_tree_key
    }

    // Backwards compatibility for EXTCODEHASH
    pub fn code_keccak(&self) -> H256 {
        self.code_keccak_tree_key
    }

    //  Backwards compatibility for EXTCODESIZE
    pub fn code_size(&self) -> H256 {
        self.code_size_tree_key
    }

    pub fn version(&self) -> H256 {
        self.version_tree_key
    }
}
