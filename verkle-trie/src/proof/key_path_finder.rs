use crate::database::{Meta, ReadOnlyHigherDb};
use crate::trie::BranchId;

// PathFinder is an algorithm to find the path to a given key
// If the key is not found, this algorithm returns the path to the node where
// the key would have been inserted. This gives the verifier enough information
// to update the key.
pub(crate) struct KeyPathFinder;
#[derive(Debug, Copy, Clone)]
pub(crate) enum KeyState {
    // The key was found, we return its value
    Found([u8; 32]),
    NotFound(KeyNotFound),
}

impl KeyState {
    pub(crate) fn different_stem(&self) -> Option<[u8; 31]> {
        match self {
            KeyState::NotFound(KeyNotFound::DifferentStem(stem)) => Some(*stem),
            _ => None,
        }
    }
    pub(crate) fn value(&self) -> Option<[u8; 32]> {
        match self {
            KeyState::Found(value) => Some(*value),
            _ => None,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum KeyNotFound {
    // The key was not found, however the slot where we would
    // have inserted it, there is a different stem
    // An example of this happening is:
    // We insert the key [0,0,0,0], then we try to find [0,1,0,0]
    DifferentStem([u8; 31]),
    // The key was not found, however its stem is present
    // in the trie.
    StemFound,
    // The key was found, however the slot that we would have inserted it at
    // is empty.
    Empty,
}
// The path to the key, including all of the nodes along the path
pub(crate) struct KeyPath {
    pub nodes: Vec<(BranchId, u8, Meta)>,
    // depth refers to the depth that the key_path terminated at
    // This can also be computed by taking the length of the `nodes`
    pub depth: u8,
    pub key_state: KeyState,
}

impl KeyPath {
    // We only require an opening for an extension,
    // if the last node was a stem.
    // This occurs in all cases, except for `Empty`
    pub(crate) fn requires_extension_proof(&self) -> bool {
        !matches!(self.key_state, KeyState::NotFound(KeyNotFound::Empty))
    }
}

impl KeyPathFinder {
    pub(crate) fn find_key_path<Storage: ReadOnlyHigherDb>(
        storage: &Storage,
        key: [u8; 32],
    ) -> KeyPath {
        let mut nodes_by_path = Vec::new();
        let mut current_node = vec![];
        let mut current_node_meta = storage.get_branch_meta(&current_node).unwrap();

        for index in key.iter() {
            nodes_by_path.push((
                current_node.clone(),
                *index,
                Meta::Branch(current_node_meta),
            ));
            let depth = nodes_by_path.len() as u8;

            let child = storage.get_branch_child(&current_node, *index);
            // If the child is empty, we just return nodes_by_path
            // which will have it's last element as a path to a branch node
            let child = match child {
                Some(child) => child,
                None => {
                    return KeyPath {
                        nodes: nodes_by_path,
                        key_state: KeyState::NotFound(KeyNotFound::Empty),
                        depth,
                    };
                }
            };

            match child {
                crate::database::BranchChild::Stem(stem_id) => {
                    let stem_meta = storage.get_stem_meta(stem_id).unwrap();
                    current_node.push(*index);
                    nodes_by_path.push((current_node, key[31], Meta::Stem(stem_meta)));
                    let depth = nodes_by_path.len() as u8;

                    // We have stopped at a stem, however it is not clear whether
                    // this stem belongs to the key.
                    // This happens when the key is not in the tree, but a key with a similar path is
                    //
                    // However, we note that iff the key is in the trie
                    // then this must be the stem for the key. Otherwise, it is a bug.
                    // We assert the invariant below.
                    if let Some(value) = storage.get_leaf(key) {
                        assert_eq!(&stem_id, &key[0..31]);

                        return KeyPath {
                            nodes: nodes_by_path,
                            key_state: KeyState::Found(value),
                            depth,
                        };
                    };
                    // Arriving here means that we have encountered a stem
                    // however, the key is not present.
                    // There are two possible cases here, either the stem corresponding to the key is present or it's a completely different stem
                    //
                    // We will need this path for update proofs

                    if stem_id == key[0..31] {
                        return KeyPath {
                            nodes: nodes_by_path,
                            key_state: KeyState::NotFound(KeyNotFound::StemFound),
                            depth,
                        };
                    }

                    return KeyPath {
                        nodes: nodes_by_path,
                        key_state: KeyState::NotFound(KeyNotFound::DifferentStem(stem_id)),
                        depth,
                    };
                }
                crate::database::BranchChild::Branch(branch_meta) => {
                    current_node_meta = branch_meta;
                    current_node.push(*index);
                    continue;
                }
            }
        }
        // It should be impossible to arrive here, because we cannot have 32 inner nodes,
        // which is the only way for the for loop to iterate until the end
        // If this is the case, we have a bug
        unreachable!()
    }
}
