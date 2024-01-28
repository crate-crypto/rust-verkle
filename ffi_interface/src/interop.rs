use banderwagon::{multi_scalar_mul, CanonicalSerialize};
use banderwagon::{Element, Fr, PrimeField};
use ipa_multipoint::{committer::DefaultCommitter, crs::CRS};
use verkle_spec::{hash64, H256};

#[allow(non_snake_case)]
pub fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_pedersenHash(
    input: &[u8],
) -> Vec<u8> {
    let mut address32 = [0u8; 32];

    address32.copy_from_slice(&input[0..32]);

    let mut trie_index = [0u8; 32];

    trie_index.copy_from_slice(&input[32..64]);
    trie_index.reverse(); // reverse for little endian per specs

    let base_hash = hash_addr_int(&address32, &trie_index);

    let result = base_hash.as_fixed_bytes();

    result.to_vec()
}

// Helper function to hash an address and an integer taken from rust-verkle/verkle-specs.
pub(crate) fn hash_addr_int(addr: &[u8; 32], integer: &[u8; 32]) -> H256 {
    let address_bytes = addr;

    let integer_bytes = integer;
    let mut hash_input = [0u8; 64];
    let (first_half, second_half) = hash_input.split_at_mut(32);

    // Copy address and index into slice, then hash it
    first_half.copy_from_slice(address_bytes);
    second_half.copy_from_slice(integer_bytes);

    let crs = CRS::default();
    let committer = DefaultCommitter::new(&crs.G);

    hash64(&committer, hash_input)
}

#[allow(non_snake_case)]
pub fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commit(
    inp: &[u8],
) -> Vec<u8> {
    let len = inp.len();
    if len % 32 != 0 {
        panic!(
            "java/lang/IllegalArgumentException Invalid input length. Should be a multiple of 32-bytes.",
        )
    }
    let n_scalars = len / 32;
    if n_scalars > 256 {
        panic!(
            "java/lang/IllegalArgumentException Invalid input length. Should be at most 256 elements of 32-bytes.",
        )
    }

    // Each 32-be-bytes are interpreted as field elements.
    let mut scalars: Vec<banderwagon::Fr> = Vec::with_capacity(n_scalars);
    for b in inp.chunks(32) {
        scalars.push(Fr::from_be_bytes_mod_order(b));
    }

    // Committing all values at once.
    let bases = CRS::default();
    let commit = multi_scalar_mul(&bases.G, &scalars);

    // Serializing via x/y in projective coordinates, to int and to scalars.
    let scalar = group_to_field(&commit);
    let mut scalar_bytes = [0u8; 32];
    scalar
        .serialize_compressed(&mut scalar_bytes[..])
        .expect("could not serialise Fr into a 32 byte array");
    scalar_bytes.reverse();

    scalar_bytes.to_vec()
}

#[allow(non_snake_case)]
pub fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commitRoot(
    inp: &[u8],
) -> Vec<u8> {
    let len = inp.len();
    if len % 32 != 0 {
        panic!(
            "java/lang/IllegalArgumentException Invalid input length. Should be a multiple of 32-bytes.",
        )
    }

    let n_scalars = len / 32;
    if n_scalars > 256 {
        panic!(
            "java/lang/IllegalArgumentException Invalid input length. Should be at most 256 elements of 32-bytes.",
        )
    }

    // Each 32-be-bytes are interpreted as field elements.
    let mut scalars: Vec<Fr> = Vec::with_capacity(n_scalars);
    for b in inp.chunks(32) {
        scalars.push(Fr::from_be_bytes_mod_order(b));
    }

    // Committing all values at once.
    let bases = CRS::default();
    let commit = multi_scalar_mul(&bases.G[0..scalars.len()], &scalars);

    // Serializing using first affine coordinate
    let commit_bytes = commit.to_bytes();

    commit_bytes.to_vec()
}

// Note: This is a 2 to 1 map, but the two preimages are identified to be the same
// TODO: Create a document showing that this poses no problems
pub(crate) fn group_to_field(point: &Element) -> Fr {
    point.map_to_scalar_field()
}

#[cfg(test)]
mod test {
    use super::Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_pedersenHash;
    use crate::{
        commit_to_scalars, deprecated_serialize_commitment, fr_to_be_bytes, get_tree_key_hash,
        hash_commitment,
        interop::{
            Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commit,
            Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commitRoot,
        },
    };
    use banderwagon::Fr;
    use ipa_multipoint::{committer::DefaultCommitter, crs::CRS};

    #[test]
    fn interop_pedersen_hash() {
        let ones = [u8::MAX; 64];
        let expected_hash =
            Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_pedersenHash(&ones);

        let crs = CRS::default();
        let committer = DefaultCommitter::new(&crs.G);

        let address = [u8::MAX; 32];
        let tree_index = [u8::MAX; 32];

        let got_hash = get_tree_key_hash(&committer, address, tree_index);

        assert_eq!(got_hash.to_vec(), expected_hash);
    }

    #[test]
    fn interop_commit() {
        let scalars: Vec<_> = (0..256)
            .map(|i| {
                let val = Fr::from((i + 1) as u128);
                fr_to_be_bytes(-val)
            })
            .flatten()
            .collect();

        let expected_hash =
            Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commit(&scalars);

        let crs = CRS::default();
        let committer = DefaultCommitter::new(&crs.G);

        let got_commitment = commit_to_scalars(&committer, &scalars).unwrap();
        let got_hash = hash_commitment(got_commitment);
        assert_eq!(got_hash.to_vec(), expected_hash)
    }

    #[test]
    fn interop_commit_root() {
        let scalars: Vec<_> = (0..256)
            .map(|i| {
                let val = Fr::from((i + 1) as u128);
                fr_to_be_bytes(-val)
            })
            .flatten()
            .collect();

        let expected_hash =
            Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commitRoot(&scalars);

        let crs = CRS::default();
        let committer = DefaultCommitter::new(&crs.G);

        let got_commitment = commit_to_scalars(&committer, &scalars).unwrap();
        let got_hash = deprecated_serialize_commitment(got_commitment);
        assert_eq!(got_hash.to_vec(), expected_hash)
    }
}
