use crate::constants::TWO_POW_128;
use crate::{errors::VerificationError, group_to_field, proof::ExtPresent};
use banderwagon::{trait_defs::*, Element, Fr};
use ipa_multipoint::committer::Committer;
use std::collections::{BTreeMap, HashSet};

use super::{UpdateHint, VerkleProof};
// TODO fix all panics and return Results instead
//
// TODO: This needs to be modified more, ie to return a correct error variant
// and to refactor panics into error variants
pub fn verify_and_update<C: Committer>(
    proof: VerkleProof,
    root: Element,
    keys: Vec<[u8; 32]>,
    values: Vec<Option<[u8; 32]>>,
    updated_values: Vec<Option<[u8; 32]>>,
    commiter: C,
) -> Result<Element, VerificationError> {
    // TODO: replace Clone with references if possible
    let (ok, update_hint) = proof.check(keys.clone(), values.clone(), root);
    if !ok {
        return Err(VerificationError::InvalidProof);
    }

    let update_hint =
        update_hint.expect("update hint should be `Some` if the proof passes verification");

    // Return the new root
    update_root(update_hint, keys, values, updated_values, root, commiter)
}

pub(crate) fn update_root<C: Committer>(
    hint: UpdateHint,
    keys: Vec<[u8; 32]>,
    values: Vec<Option<[u8; 32]>>,
    updated_values: Vec<Option<[u8; 32]>>,
    root: Element,
    committer: C,
) -> Result<Element, VerificationError> {
    if !values.len() == updated_values.len() {
        return Err(VerificationError::UnexpectedUpdatedLength(
            values.len(),
            updated_values.len(),
        ));
    }
    if !keys.len() == updated_values.len() {
        return Err(VerificationError::MismatchedKeyLength);
    }

    // check that keys are unique
    // Since this is the main place this is used, make sure to exit early as soon as 2 keys are the same
    let keys_unique = has_unique_elements(keys.iter());
    if !keys_unique {
        return Err(VerificationError::DuplicateKeys);
    }
    // TODO Check root against the root in commitments by path

    // type Prefix = Vec<u8>;
    // struct StemUp {
    //     stem: [u8; 31],
    //     suffices: Vec<u8>,
    // }
    // struct UpdateData {
    //     // Many stems means we need a subtree
    //     stems: Vec<[u8; 31]>,
    //     suffices: Vec<u8>,
    // }
    // let all_data: BTreeMap<Prefix, UpdateData> = BTreeMap::new();

    // Maps suffix -> (old_value, new_value)
    type SuffixUpdate = BTreeMap<u8, (Option<[u8; 32]>, [u8; 32])>;
    // Maps stem -> SuffixUpdate
    let mut updated_stems: BTreeMap<[u8; 31], SuffixUpdate> = BTreeMap::new();
    // First, not all of the keys will need to be updated, so we filter
    // for all of the keys which will need to be updated
    for ((key, old_value), updated_value) in keys.into_iter().zip(values).zip(updated_values) {
        let stem: [u8; 31] = key[0..31].try_into().unwrap();
        let suffix = key[31];

        let updated_value = match updated_value {
            Some(x) => x,
            None => continue,
        };

        // if let Some(val) = old_value {
        //     if val == updated_value {
        //         continue;
        //     }
        // }

        updated_stems
            .entry(stem)
            .or_default()
            .insert(suffix, (old_value, updated_value));
    }

    // TODO: Prefix can be &'a [u8] instead of Vec<u8> which avoids unnecessary allocations... This may be unneeded when we switch to SmallVec32
    let mut updated_stems_by_prefix: BTreeMap<Vec<u8>, HashSet<[u8; 31]>> = BTreeMap::new();
    let mut updated_commitents_by_stem: BTreeMap<[u8; 31], (Element, Fr)> = BTreeMap::new();

    for (stem, suffix_update) in updated_stems {
        let (ext_pres, depth) = hint.depths_and_ext_by_stem[&stem];
        let prefix = stem[0..depth as usize].to_vec();
        updated_stems_by_prefix
            .entry(prefix.clone())
            .or_default()
            .insert(stem);

        if ext_pres == ExtPresent::Present {
            let ext_path = stem[0..depth as usize].to_vec(); // It is the prefix

            let mut c_1_delta_update = Element::zero();
            let mut c_2_delta_update = Element::zero();

            // TODO abstract this into a function, since it's duplicated
            for (suffix, (old_value, new_value)) in suffix_update {
                // Split values into low_16 and high_16
                let new_value_low_16 = new_value[0..16].to_vec();
                let new_value_high_16 = new_value[16..32].to_vec();

                let (old_value_low_16, old_value_high_16) = match old_value {
                    Some(val) => (
                        Fr::from_le_bytes_mod_order(&val[0..16]) + TWO_POW_128,
                        Fr::from_le_bytes_mod_order(&val[16..32]),
                    ),
                    None => (Fr::zero(), Fr::zero()), // The extension can be present, but it's suffix can be missing
                };

                // We need to compute two deltas
                let delta_low =
                    Fr::from_le_bytes_mod_order(&new_value_low_16) + TWO_POW_128 - old_value_low_16;
                let delta_high =
                    Fr::from_le_bytes_mod_order(&new_value_high_16) - old_value_high_16;

                let position = suffix;
                let is_c1_comm_update = position < 128;

                let pos_mod_128 = position % 128;

                let low_index = 2 * pos_mod_128 as usize;
                let high_index = low_index + 1;

                let generator_low = committer.scalar_mul(delta_low, low_index);
                let generator_high = committer.scalar_mul(delta_high, high_index);

                if is_c1_comm_update {
                    c_1_delta_update += generator_low + generator_high;
                } else {
                    c_2_delta_update += generator_low + generator_high;
                }
            }
            // Compute the delta for C1 and C2, so that we can update the extension commitment
            let mut hash_c1_delta = Fr::zero();
            let mut hash_c2_delta = Fr::zero();
            if !c_1_delta_update.is_zero() {
                let mut c1_path = ext_path.clone();
                c1_path.push(2);

                let old_c1_comm = hint.commitments_by_path[&c1_path];
                let new_c1_commitment = old_c1_comm + c_1_delta_update;
                let hash_c1_new = group_to_field(&new_c1_commitment);
                let hash_c1_old = group_to_field(&old_c1_comm);
                hash_c1_delta = hash_c1_new - hash_c1_old;
            }
            if !c_2_delta_update.is_zero() {
                let mut c2_path = ext_path.clone();
                c2_path.push(3);

                let old_c2_comm = hint.commitments_by_path[&c2_path];
                let new_c2_commitment = old_c2_comm + c_2_delta_update;
                let hash_c2_new = group_to_field(&new_c2_commitment);
                let hash_c2_old = group_to_field(&old_c2_comm);
                hash_c2_delta = hash_c2_new - hash_c2_old;
            }

            let mut stem_comm_update = Element::zero();
            stem_comm_update += committer.scalar_mul(hash_c1_delta, 2);
            stem_comm_update += committer.scalar_mul(hash_c2_delta, 3);

            let stem_comm_old = hint.commitments_by_path[&ext_path];
            let stem_comm_new = stem_comm_old + stem_comm_update;
            let hash_stem_comm_new = group_to_field(&stem_comm_new);

            // Note that we have been given a stem to which we know is in the trie (ext_pres) and
            // we have computed all of the updates for that particular stem
            updated_commitents_by_stem.insert(stem, (stem_comm_new, hash_stem_comm_new));
        } else if ext_pres == ExtPresent::DifferentStem {
            let other_stem = hint.other_stems_by_prefix[&prefix];
            updated_stems_by_prefix
                .entry(prefix)
                .or_default()
                .insert(other_stem);

            // Since this stem was not present in the trie, we need to make its initial stem commitment
            //
            // This is similar to the case of ExtPres::Present, except that the old_value is zero, so we can ignore it
            // TODO we could take this for loop out of the if statement and then use the if statement for the rest
            let mut c_1 = Element::zero();
            let mut c_2 = Element::zero();
            for (suffix, (old_value, new_value)) in suffix_update {
                if old_value.is_some() {
                    return Err(VerificationError::OldValueIsPopulated);
                }
                // Split values into low_16 and high_16
                let new_value_low_16 = new_value[0..16].to_vec();
                let new_value_high_16 = new_value[16..32].to_vec();

                // We need to compute two deltas
                let value_low = Fr::from_le_bytes_mod_order(&new_value_low_16) + TWO_POW_128;
                let value_high = Fr::from_le_bytes_mod_order(&new_value_high_16);

                let position = suffix;
                let is_c1_comm_update = position < 128;

                let pos_mod_128 = position % 128;

                let low_index = 2 * pos_mod_128 as usize;
                let high_index = low_index + 1;

                let generator_low = committer.scalar_mul(value_low, low_index);
                let generator_high = committer.scalar_mul(value_high, high_index);

                if is_c1_comm_update {
                    c_1 += generator_low + generator_high;
                } else {
                    c_2 += generator_low + generator_high;
                }
            }

            let stem_comm_0 = Fr::one(); // TODO: We can get rid of this and just add SRS[0]
            let stem_comm_1 = Fr::from_le_bytes_mod_order(&stem);
            let stem_comm_2 = group_to_field(&c_1);
            let stem_comm_3 = group_to_field(&c_2);
            let stem_comm = committer.commit_sparse(vec![
                (stem_comm_0, 0),
                (stem_comm_1, 1),
                (stem_comm_2, 2),
                (stem_comm_3, 3),
            ]);
            let hash_stem_comm = group_to_field(&stem_comm);
            updated_commitents_by_stem.insert(stem, (stem_comm, hash_stem_comm));
        }

        //We have now processed all of the necessary extension proof edits that need to be completed.
        // let recompute the root
    }

    let mut tree = SparseVerkleTree::new(root);

    for (prefix, stems) in updated_stems_by_prefix {
        // First fetch the old commitment for this prefix
        // If the prefix is for a stem that was not in the trie, then it will be 0
        let old_hash_value = match hint.commitments_by_path.get(&prefix) {
            Some(comm) => group_to_field(comm),
            None => Fr::zero(),
        };

        if stems.len() == 1 {
            let stem = stems.iter().next().unwrap();
            let (_, new_hash_value) = updated_commitents_by_stem[stem];

            tree.update_prefix(
                &hint.commitments_by_path,
                &committer,
                prefix.clone(),
                old_hash_value,
                new_hash_value,
            )
            .unwrap();
        } else {
            // If we have more than one stem to be processed for a prefix, we need to build a subtree and
            // then update the prefix with the root of the subtree
            //
            // Note, once we take the root from the subtree, we can discard the tree
            // We know that all updates to this prefix will happen here.
            //
            // Get all of the stems and their commitments
            let mut elements = Vec::new();
            for stem in stems {
                let updated_comm = updated_commitents_by_stem.get(&stem);
                let stem_comm = match updated_comm {
                    Some((comm, _)) => *comm,
                    None => hint.commitments_by_path[&prefix],
                };
                elements.push((stem, stem_comm))
            }
            let subtree_root_comm = build_subtree(prefix.clone(), elements, &committer);
            let new_hash_value = group_to_field(&subtree_root_comm);

            tree.update_prefix(
                &hint.commitments_by_path,
                &committer,
                prefix.clone(),
                old_hash_value,
                new_hash_value,
            )
            .unwrap();
        }
    }

    // There are two types of updates that we need to distinguish, an update where the key was None (Other stem) and an update where the key was some
    Ok(tree.root)
}

// Build a subtree from a set of stems and their commitments
// We will start from an empty tree and iterate each stem
// modifying the inner node commitments along the way
//
// This algorithm should match the stateful trie insert, however
// it has been rewritten here so that that section of the code does not increase in complexity
//
// TODO we can rewrite this to place the node commitments in the tree and
// TODO then recursively sweep up the tree, updating each node using commit_sparse
//
// We could _not_ pass in the prefix and slice off stem[prefix.len()..], then compute the root
// as if we were starting from a tree of depth=0
fn build_subtree<C: Committer>(
    prefix: Vec<u8>,
    elements: Vec<([u8; 31], Element)>,
    committer: &C,
) -> Element {
    let mut tree: BTreeMap<Vec<u8>, Node> = BTreeMap::new();

    // Insert the root
    tree.insert(
        vec![],
        Node::Inner(InnerNode {
            commitment: Element::zero(),
        }),
    );

    #[derive(Debug, Clone)]
    struct InnerNode {
        commitment: Element,
    }
    #[derive(Debug, Clone, Copy)]
    struct Stem {
        id: [u8; 31],
        commitment: Element,
    }
    #[derive(Debug, Clone)]
    enum Node {
        Inner(InnerNode),
        Stem(Stem),
    }

    impl Node {
        fn is_inner(&self) -> bool {
            match self {
                Node::Inner(_) => true,
                Node::Stem(_) => false,
            }
        }
        fn inner(&self) -> &InnerNode {
            match self {
                Node::Inner(inner) => inner,
                Node::Stem(_) => panic!("found stem"),
            }
        }
        fn inner_mut(&mut self) -> &mut InnerNode {
            match self {
                Node::Inner(inner) => inner,
                Node::Stem(_) => panic!("found stem"),
            }
        }
    }

    for (stem, commitment) in elements {
        let mut depth = prefix.len();
        // Everything before the prefix is irrelevant to the subtree
        let _relative_stem = &stem[depth..];

        let mut path = vec![];
        let mut current_node = tree[&path].clone();

        while current_node.is_inner() {
            let index = stem[depth];
            path.push(index);
            depth += 1;
            match tree.get(&path) {
                Some(node) => {
                    current_node = node.clone();
                }
                None => {
                    break;
                }
            };
        }

        let (mut child_old_value, mut child_new_value) = match current_node {
            Node::Inner(_) => {
                // Add a stem at the path which points to the child of the previous node

                tree.insert(
                    path.clone(),
                    Node::Stem(Stem {
                        id: stem,
                        commitment,
                    }),
                );

                let child_new_value = group_to_field(&commitment);
                let child_old_value = Fr::zero();

                (child_old_value, child_new_value)
            }
            Node::Stem(old_stem) => {
                // assert_ne!(old_stem.id, stem);
                // We now need to add a  bunch of new inner nodes for each index that these two stems share
                // The current node which is a stem will be shifted down the tree, the node that was pointing to this stem will now point to an inner node
                let mut new_inner_node = InnerNode {
                    commitment: Element::zero(),
                };
                let stem_to_innernode_path = path.clone(); // Save the path of the node which was a stem and is now a inner node (currently an edge case)
                tree.insert(path.clone(), Node::Inner(new_inner_node)); // This inner node now replaces the old_stem

                while old_stem.id[depth] == stem[depth] {
                    let index = stem[depth];
                    depth += 1;
                    path.push(index);
                    new_inner_node = InnerNode {
                        commitment: Element::zero(),
                    };
                    tree.insert(path.clone(), Node::Inner(new_inner_node));
                }

                let mut old_stem_path = path.clone();
                let old_stem_index = old_stem.id[depth];
                old_stem_path.push(old_stem_index);
                tree.insert(old_stem_path, Node::Stem(old_stem));

                let mut stem_path = path.clone();
                let stem_index = stem[depth];
                stem_path.push(stem_index);
                tree.insert(
                    stem_path,
                    Node::Stem(Stem {
                        id: stem,
                        commitment,
                    }),
                );

                // Now lets modify the bottom inner node's commitment with respects to the two new stems
                let old_stem_child_comm = committer.scalar_mul(
                    group_to_field(&old_stem.commitment),
                    old_stem_index as usize,
                );
                let stem_child_comm =
                    committer.scalar_mul(group_to_field(&commitment), stem_index as usize);

                let delta_comm = old_stem_child_comm + stem_child_comm;
                tree.get_mut(&path).unwrap().inner_mut().commitment += delta_comm;
                let comm = tree.get(&path).unwrap().inner().commitment;

                let mut child_new_value = group_to_field(&comm);
                let mut child_old_value = Fr::zero(); // previous value of this bottom inner node was zero

                // Process the chain of inner nodes who only have one child which is an inner node
                while path != stem_to_innernode_path {
                    let child_index = path.pop().unwrap();

                    let parent_old_comm = tree.get(&path).unwrap().inner().commitment;

                    let delta = child_new_value - child_old_value;
                    tree.get_mut(&path).unwrap().inner_mut().commitment +=
                        committer.scalar_mul(delta, child_index as usize);

                    child_old_value = group_to_field(&parent_old_comm);
                    child_new_value = group_to_field(&tree.get(&path).unwrap().inner().commitment);
                }

                // Now process the node which was previously a stem and is now an inner node
                child_old_value = group_to_field(&old_stem.commitment);
                let child_index = path.pop().unwrap();
                let delta = child_new_value - child_old_value;
                let parent_old_comm = tree[&path].inner().commitment;
                tree.get_mut(&path).unwrap().inner_mut().commitment +=
                    committer.scalar_mul(delta, child_index as usize);

                child_old_value = group_to_field(&parent_old_comm);
                child_new_value = group_to_field(&tree.get(&path).unwrap().inner().commitment);

                (child_old_value, child_new_value)
            }
        };

        while let Some(child_index) = path.pop() {
            let parent_old_comm = tree.get(&path).unwrap().inner().commitment;

            let delta = child_new_value - child_old_value;
            tree.get_mut(&path).unwrap().inner_mut().commitment +=
                committer.scalar_mul(delta, child_index as usize);

            child_old_value = group_to_field(&parent_old_comm);
            child_new_value = group_to_field(&tree.get(&path).unwrap().inner().commitment);
        }
    }

    tree.get(&vec![]).unwrap().inner().commitment
}

struct SparseVerkleTree {
    root: Element,
    updated_commitments_by_path: BTreeMap<Vec<u8>, Element>,
}

impl SparseVerkleTree {
    fn new(root: Element) -> SparseVerkleTree {
        SparseVerkleTree {
            root,
            updated_commitments_by_path: BTreeMap::default(),
        }
    }

    fn update_prefix<C: Committer>(
        &mut self,
        commitments_by_path: &BTreeMap<Vec<u8>, Element>,
        committer: &C,
        mut prefix: Vec<u8>,
        old_value: Fr,
        new_value: Fr,
    ) -> Result<(), VerificationError> {
        if prefix.is_empty() {
            return Err(VerificationError::EmptyPrefix);
        }
        // First lets compute the delta between the old_value and the new value
        let mut delta = new_value - old_value;

        let mut current_parent_comm = None;

        // Now lets fetch the parent node's commitment and recursively update each parent

        while let Some(child_index) = prefix.pop() {
            // Safety: Fine unwrap because we've checked prefix isn't empty
            // If we have never updated the parent node before,
            // then it will be the old commitment
            // If we have then it will be in updated commitments

            let parent_comm = self.updated_commitments_by_path.get(&prefix);
            let old_parent_comm = match parent_comm {
                Some(comm) => *comm,
                None => commitments_by_path[&prefix],
            };

            // Update the parent_comm at the child index
            let comm_update = committer.scalar_mul(delta, child_index as usize);
            let new_parent_comm = old_parent_comm + comm_update;
            current_parent_comm = Some(new_parent_comm);

            self.updated_commitments_by_path
                .insert(prefix.clone(), new_parent_comm);

            delta = group_to_field(&new_parent_comm) - group_to_field(&old_parent_comm)
        }

        self.root = current_parent_comm.unwrap();

        Ok(())
    }
}

// https://stackoverflow.com/a/46767732
// TODO Check if there is a similar method in itertools
fn has_unique_elements<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + std::hash::Hash,
{
    let mut uniq = std::collections::HashSet::new();
    iter.into_iter().all(move |x| uniq.insert(x))
}

#[cfg(test)]
mod test {

    use banderwagon::trait_defs::*;

    use crate::constants::new_crs;
    use crate::database::memory_db::MemoryDb;
    use crate::database::ReadOnlyHigherDb;
    use crate::proof::prover;
    use crate::proof::stateless_updater::update_root;
    use crate::{group_to_field, DefaultConfig};
    use crate::{trie::Trie, TrieTrait};
    use ipa_multipoint::committer::DefaultCommitter;

    #[test]
    fn basic_update() {
        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let mut keys = Vec::new();
        for i in 0..2 {
            let mut key_0 = [0u8; 32];
            key_0[0] = i;
            keys.push(key_0);
            trie.insert_single(key_0, key_0);
        }
        let root = vec![];
        let meta = trie.storage.get_branch_meta(&root).unwrap();

        let proof = prover::create_verkle_proof(&trie.storage, keys.clone()).unwrap();
        let values: Vec<_> = keys.iter().map(|val| Some(*val)).collect();
        let (ok, updated_hint) = proof.check(keys.clone(), values.clone(), meta.commitment);
        assert!(ok);

        let new_root_comm = update_root(
            updated_hint.unwrap(),
            keys.clone(),
            values,
            vec![Some([0u8; 32]), None],
            meta.commitment,
            DefaultCommitter::new(&new_crs().G),
        );

        let mut got_bytes = [0u8; 32];
        group_to_field(&new_root_comm.unwrap())
            .serialize_compressed(&mut got_bytes[..])
            .unwrap();

        trie.insert_single(keys[0], [0u8; 32]);
        let expected_root = trie.root_hash();
        let mut expected_bytes = [0u8; 32];
        expected_root
            .serialize_compressed(&mut expected_bytes[..])
            .unwrap();

        assert_eq!(got_bytes, expected_bytes)
    }
    #[test]
    fn basic_update_using_subtree() {
        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let key_a = [0u8; 32];
        trie.insert_single(key_a, key_a);

        let key_b = [1u8; 32];
        trie.insert_single(key_b, key_b);

        let mut key_c = [0u8; 32];
        key_c[3] = 1;

        let keys = vec![key_a, key_b, key_c];
        let values = vec![Some(key_a), Some(key_b), None];

        let root = vec![];
        let meta = trie.storage.get_branch_meta(&root).unwrap();

        let proof = prover::create_verkle_proof(&trie.storage, keys.clone()).unwrap();
        let (ok, updated_hint) = proof.check(keys.clone(), values.clone(), meta.commitment);
        assert!(ok);

        let updated_values = vec![None, None, Some(key_c)];

        let new_root_comm = update_root(
            updated_hint.unwrap(),
            keys,
            values,
            updated_values,
            meta.commitment,
            DefaultCommitter::new(&new_crs().G),
        );

        let mut got_bytes = [0u8; 32];
        group_to_field(&new_root_comm.unwrap())
            .serialize_compressed(&mut got_bytes[..])
            .unwrap();

        trie.insert_single(key_c, key_c);
        let expected_root = trie.root_hash();
        let mut expected_bytes = [0u8; 32];
        expected_root
            .serialize_compressed(&mut expected_bytes[..])
            .unwrap();

        assert_eq!(got_bytes, expected_bytes)
    }
    #[test]
    fn basic_update3() {
        // traverse the subtree twice
        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let key_a = [0u8; 32];
        trie.insert_single(key_a, key_a);

        let key_b = [1u8; 32];
        trie.insert_single(key_b, key_b);

        let mut keys = vec![key_a, key_b];
        let mut values = vec![Some(key_a), Some(key_b)];
        let mut updated_values = vec![None, None];
        for i in 1..=30 {
            let mut key = [0u8; 32];
            key[i] = 1;
            keys.push(key);
            values.push(None);
            updated_values.push(Some(key))
        }

        let root = vec![];

        let meta = trie.storage.get_branch_meta(&root).unwrap();

        let proof = prover::create_verkle_proof(&trie.storage, keys.clone()).unwrap();
        let (ok, updated_hint) = proof.check(keys.clone(), values.clone(), meta.commitment);
        assert!(ok, "proof failed to verify");

        let new_root_comm = update_root(
            updated_hint.unwrap(),
            keys.clone(),
            values,
            updated_values,
            meta.commitment,
            DefaultCommitter::new(&new_crs().G),
        );

        let mut got_bytes = [0u8; 32];
        group_to_field(&new_root_comm.unwrap())
            .serialize_uncompressed(&mut got_bytes[..])
            .unwrap();
        dbg!(&got_bytes);

        for key in keys.into_iter().skip(2) {
            // skip two keys that are already in the trie
            trie.insert_single(key, key);
        }

        let expected_root = trie.root_hash();
        let mut expected_bytes = [0u8; 32];
        expected_root
            .serialize_uncompressed(&mut expected_bytes[..])
            .unwrap();
        dbg!(&expected_bytes);
        assert_eq!(got_bytes, expected_bytes)
    }
}
