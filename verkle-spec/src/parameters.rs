use ethereum_types::U256;

// Parameters
pub(crate) const VERSION_LEAF_KEY: U256 = U256::zero();
pub(crate) const BALANCE_LEAF_KEY: U256 = U256([1, 0, 0, 0]);
pub(crate) const NONCE_LEAF_KEY: U256 = U256([2, 0, 0, 0]);
pub(crate) const CODE_KECCAK_LEAF_KEY: U256 = U256([3, 0, 0, 0]);
pub(crate) const CODE_SIZE_LEAF_KEY: U256 = U256([4, 0, 0, 0]);
pub(crate) const HEADER_STORAGE_OFFSET: U256 = U256([64, 0, 0, 0]);
pub(crate) const CODE_OFFSET: U256 = U256([128, 0, 0, 0]);
pub(crate) const VERKLE_NODE_WIDTH: U256 = U256([256, 0, 0, 0]);
pub(crate) const MAIN_STORAGE_OFFSET: U256 = U256([0, 0, 0, 2u64.pow(56)]);

#[test]
fn check_hardcoded_values() {
    // Check that the constants were hardcoded correctly by
    // checking against the `From` trait implementation

    let version_leaf_key = U256::from(0u8);
    assert_eq!(version_leaf_key, VERSION_LEAF_KEY);

    let balance_leaf_key = U256::from(1u8);
    assert_eq!(balance_leaf_key, BALANCE_LEAF_KEY);

    let nonce_leaf_key = U256::from(2u8);
    assert_eq!(nonce_leaf_key, NONCE_LEAF_KEY);

    let code_keccak_leaf_key = U256::from(3u8);
    assert_eq!(code_keccak_leaf_key, CODE_KECCAK_LEAF_KEY);

    let code_size_leaf_key = U256::from(4u8);
    assert_eq!(code_size_leaf_key, CODE_SIZE_LEAF_KEY);

    let header_storage_offset = U256::from(64u8);
    assert_eq!(header_storage_offset, HEADER_STORAGE_OFFSET);

    let code_offset = U256::from(128u8);
    assert_eq!(code_offset, CODE_OFFSET);

    let verkle_node_width = U256::from(256u16);
    assert_eq!(verkle_node_width, VERKLE_NODE_WIDTH);

    let main_storage_offset = U256::from(256u16).pow(U256::from(31u8));
    assert_eq!(main_storage_offset, MAIN_STORAGE_OFFSET);
}

#[test]
fn check_invariants() {
    //It’s a required invariant that VERKLE_NODE_WIDTH > CODE_OFFSET > HEADER_STORAGE_OFFSET
    // and that HEADER_STORAGE_OFFSET is greater than the leaf keys.
    assert!(VERKLE_NODE_WIDTH > CODE_OFFSET);
    assert!(CODE_OFFSET > HEADER_STORAGE_OFFSET);
    assert!(HEADER_STORAGE_OFFSET > VERSION_LEAF_KEY);
    assert!(HEADER_STORAGE_OFFSET > BALANCE_LEAF_KEY);
    assert!(HEADER_STORAGE_OFFSET > NONCE_LEAF_KEY);
    assert!(HEADER_STORAGE_OFFSET > CODE_KECCAK_LEAF_KEY);
    assert!(HEADER_STORAGE_OFFSET > CODE_SIZE_LEAF_KEY);

    // MAIN_STORAGE_OFFSET must be a power of VERKLE_NODE_WIDTH
    //
    assert!(MAIN_STORAGE_OFFSET == VERKLE_NODE_WIDTH.pow(U256::from(31)))
}
