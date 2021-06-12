use verkle_trie::{dummy_setup, Key, Value, VerkleTrait, VerkleTrie};
fn main() {
    println!("creating trusted setup");
    let (commit_key, opening_key) = dummy_setup(10);

    let mut trie = VerkleTrie::new(10, &commit_key);

    println!("creating inserting values");
    trie.insert_single(Key::one(), Value::one());
    trie.insert_single(Key::from_arr([1; 32]), Value::one());

    println!("creating verkle path");
    let verkle_path = trie.create_verkle_path(&Key::one()).unwrap();

    println!("creating verkle proof");
    let verkle_proof = verkle_path.create_proof(&commit_key);

    println!("verifying");
    let ok = verkle_proof.verify(
        &opening_key,
        &verkle_path.commitments,
        &verkle_path.omega_path_indices,
        &verkle_path.node_roots,
    );

    println!("proof validity: {}", ok);
}
