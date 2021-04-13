use verkle_trie::{dummy_setup, Key, Value, VerkleTrie};
fn main() {
    let mut trie = VerkleTrie::new(10);

    println!("creating trusted setup");
    let (commit_key, opening_key) = dummy_setup(1023);

    println!("creating inserting values");
    trie.insert(Key::one(), Value::one());
    trie.insert(Key::from_arr([1; 32]), Value::one());

    println!("creating verkle path");
    let verkle_path = trie.create_path(&Key::one(), &commit_key).unwrap();

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
