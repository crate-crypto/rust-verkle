// TODO: move into trie module

// Returns a list of all of the path indices where the two stems
// are the same and the next path index where they both differ for each
// stem.
// XXX: Clean up
pub fn path_difference(key_a: [u8; 31], key_b: [u8; 31]) -> (Vec<u8>, Option<u8>, Option<u8>) {
    const AVERAGE_NUMBER_OF_SHARED_INDICES: usize = 3;

    let mut same_path_indices = Vec::with_capacity(AVERAGE_NUMBER_OF_SHARED_INDICES);

    for (p_a, p_b) in key_a.into_iter().zip(key_b.into_iter()) {
        if p_a != p_b {
            return (same_path_indices, Some(*p_a), Some(*p_b));
        }
        same_path_indices.push(*p_a)
    }

    (same_path_indices, None, None)
}
