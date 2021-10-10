# Verkle Trie 

**This code has not been reviewed and is not safe to use in non-research capacities.**

This is a proof of concept implementation of Verkle Tries. Any and all mistakes made are mine and are not reflective of the protocol.

## Note on Performance

There are still a few places in the code where performance can be improved:

- Upon inserting a single leaf, a multi scalar is currently being done
- Parallelism is not currently being used, in places where it could be.

## Note on Differences with reference

- The code has been intentionally implemented in a different way in most places to check for consistency and any misunderstandings. For example, recursion is not used as much when inserting leaves. This means that the code will be more verbose as we need to compute exactly when the algorithm will stop ahead of time.

- An arena is used to allocate node data, which further changes the way the code looks. 

- Consistency between implementations has not been tested and most likely will not be the case as hash_to_fr for example, is implemented differently in golang. 

## About

This implementation references the go-verkle implementation : https://github.com/gballet/go-verkle

It also uses the kzg scheme referenced here for multi-point proofs: https://notes.ethereum.org/nrQqhVpQRi6acQckwm1Ryg

## Usage

```rust
use verkle_trie::{dummy_setup, Key, Value, VerkleTrie};

    // Trusted setup
    let srs_poly_degree = 1024;
    let (commit_key, opening_key) = dummy_setup(srs_poly_degree);

    // Create a trie and insert two values
    let width = 10;
    let mut trie = VerkleTrie::new(width);
    trie.insert(Key::one(), Value::one());
    trie.insert(Key::zero(), Value::one());

    // Create a VerklePath for key
    let verkle_path = trie.create_path(&Key::one(), &commit_key).unwrap();

    // Create a VerkleProof
    let verkle_proof = verkle_path.create_proof(&commit_key);

    // Verification here means that the KZG10 proof passed
    //
    // To "finish" the proof, the verifier should check the hash of leaf node themselves
    let ok = verkle_proof.verify(
        &opening_key,
        &verkle_path.commitments,
        &verkle_path.omega_path_indices,
        &verkle_path.node_roots,
    );

    assert!(ok);

```

## License

MIT/APACHE