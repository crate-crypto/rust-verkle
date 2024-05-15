use super::VerkleProof;
use crate::{
    constants::TWO_POW_128,
    group_to_field,
    proof::{ExtPresent, UpdateHint},
};
use banderwagon::{trait_defs::*, Element, Fr};
use ipa_multipoint::multiproof::VerifierQuery;
use std::collections::{BTreeMap, BTreeSet};

// TODO Document this better and refactor
pub fn create_verifier_queries(
    proof: VerkleProof,
    keys: Vec<[u8; 32]>,
    values: Vec<Option<[u8; 32]>>,
    root: Element,
) -> Option<(Vec<VerifierQuery>, UpdateHint)> {
    let commitments_sorted_by_path: Vec<_> =
        std::iter::once(root).chain(proof.comms_sorted).collect();

    // Get all of the stems
    let stems: BTreeSet<[u8; 31]> = keys
        .iter()
        .map(|key| key[0..31].try_into().unwrap())
        .collect();

    let mut depths_and_ext_by_stem: BTreeMap<[u8; 31], (ExtPresent, u8)> = BTreeMap::new();

    let mut stems_with_extension: BTreeSet<[u8; 31]> = BTreeSet::new();
    let mut other_stems_used: BTreeSet<[u8; 31]> = BTreeSet::new();

    let mut all_paths: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut all_paths_and_zs: BTreeSet<(Vec<u8>, u8)> = BTreeSet::new();
    let mut leaf_values_by_path_and_z: BTreeMap<(Vec<u8>, u8), Fr> = BTreeMap::new();

    let mut other_stems_by_prefix: BTreeMap<Vec<u8>, [u8; 31]> = BTreeMap::new();

    // Associate stems with their depths and extension status
    // depths and extension status were sorted by stem order
    // when the prover made the proof
    for ((stem, depth), ext_pres) in stems
        .into_iter()
        .zip(proof.verification_hint.depths)
        .zip(proof.verification_hint.extension_present)
    {
        depths_and_ext_by_stem.insert(stem, (ext_pres, depth));

        if ext_pres == ExtPresent::Present {
            stems_with_extension.insert(stem);
        }
    }

    for (key, value) in keys.into_iter().zip(values) {
        let stem: [u8; 31] = key[0..31].try_into().unwrap();
        let (extpres, depth) = depths_and_ext_by_stem[&stem];

        // Add branch node information, we know that if the stem has depth `d`
        // then there are d -1  inner nodes from the root to the stem
        for i in 0..depth {
            all_paths.insert(stem[0..i as usize].to_vec());
            all_paths_and_zs.insert((stem[0..i as usize].to_vec(), stem[i as usize]));
        }

        // We can use the extension present
        if extpres == ExtPresent::DifferentStem || extpres == ExtPresent::Present {
            all_paths.insert(stem[0..depth as usize].to_vec());

            all_paths_and_zs.insert((stem[0..depth as usize].to_vec(), 0));
            all_paths_and_zs.insert((stem[0..depth as usize].to_vec(), 1));
            leaf_values_by_path_and_z.insert((stem[0..depth as usize].to_vec(), 0), Fr::one());

            if extpres == ExtPresent::Present {
                let suffix = key[31];
                let opening_index = if suffix < 128 { 2 } else { 3 };

                all_paths_and_zs.insert((stem[0..depth as usize].to_vec(), opening_index));
                leaf_values_by_path_and_z.insert(
                    (stem[0..depth as usize].to_vec(), 1),
                    Fr::from_le_bytes_mod_order(&stem),
                );

                let mut suffix_tree_path = stem[0..depth as usize].to_vec();
                suffix_tree_path.push(opening_index);

                all_paths.insert(suffix_tree_path.clone());
                let val_lower_index = 2 * (suffix % 128);
                let val_upper_index = val_lower_index + 1;
                all_paths_and_zs.insert((suffix_tree_path.clone(), val_lower_index));
                all_paths_and_zs.insert((suffix_tree_path.clone(), val_upper_index));

                let (value_low, value_high) = match value {
                    Some(val) => {
                        let value_low = Fr::from_le_bytes_mod_order(&val[0..16]) + TWO_POW_128;
                        let value_high = Fr::from_le_bytes_mod_order(&val[16..32]);
                        (value_low, value_high)
                    }
                    None => (Fr::zero(), Fr::zero()),
                };
                leaf_values_by_path_and_z
                    .insert((suffix_tree_path.clone(), val_lower_index), value_low);
                leaf_values_by_path_and_z
                    .insert((suffix_tree_path.clone(), val_upper_index), value_high);
            } else if extpres == ExtPresent::DifferentStem {
                // Since this stem points to a different stem,
                // the value was never set
                if value.is_some() {
                    return None;
                }

                // Check if this stem already has an extension proof
                // TODO this was taken from python, redo
                // TODO It's left here for compatibility, but it might not be needed
                // Logic: stem[...depth] points to a stem in the trie
                // it cannot point to two different stems however
                // if two stems do share the prefix stem[..depth], then there will be
                // an inner node present
                // depth cannot be 31 because then that would mean that stem[...depth]
                // is looking for it's tem. This is not possible, because we have already
                // noted that ExtPresent is DifferentStem
                assert!(depth != stem.len() as u8);

                let mut other_stem = None;
                let mut found: Vec<_> = stems_with_extension
                    .iter()
                    .filter(|x| x[0..depth as usize] == stem[0..depth as usize])
                    .collect();
                if found.len() > 1 {
                    // TODO return error instead when we change the func signature to return Result instead of bool
                    panic!("found more than one instance of stem_with_extension at depth {}, see: {:?}", depth, found)
                } else if found.len() == 1 {
                    other_stem = found.pop();
                }
                // None means that we need to create the extension proof
                else if found.is_empty() {
                    let mut found: Vec<_> = proof
                        .verification_hint
                        .diff_stem_no_proof
                        .iter()
                        .filter(|x| x[0..depth as usize] == stem[0..depth as usize])
                        .collect();
                    let encountered_stem = found.pop().expect(
                        "ExtPresent::DifferentStem flag but we cannot find the encountered stem",
                    );
                    other_stem = Some(encountered_stem);

                    other_stems_used.insert(*encountered_stem);

                    // Add extension node to proof in particular, we only want to open at (1, stem)
                    leaf_values_by_path_and_z.insert(
                        (stem[0..depth as usize].to_vec(), 1),
                        Fr::from_le_bytes_mod_order(&encountered_stem[..]),
                    );
                }

                other_stems_by_prefix
                    .insert(stem[0..depth as usize].to_vec(), *other_stem.unwrap());
            }
        } else if extpres == ExtPresent::None {
            // If the extension was not present, then the value should be None
            if value.is_some() {
                return None;
            }

            //TODO: we may need to rewrite the prover/verifier algorithm to fix this if statement properly.
            // This is a special case. If the depth == 1 and the there is no stem to prove the proof of absence
            // then this means that the path should point to the root node.
            //
            // TODO: Fix in python codebase and check for this in go code
            if depth == 1 {
                let root_path = vec![];
                leaf_values_by_path_and_z.insert((root_path, stem[depth as usize - 1]), Fr::zero());
            } else {
                leaf_values_by_path_and_z.insert(
                    (stem[0..depth as usize].to_vec(), stem[depth as usize - 1]),
                    Fr::zero(),
                );
            }
        }
    }

    assert!(proof.verification_hint.diff_stem_no_proof == other_stems_used);
    assert!(commitments_sorted_by_path.len() == all_paths.len());

    let commitments_by_path: BTreeMap<Vec<_>, Element> = all_paths
        .into_iter()
        .zip(commitments_sorted_by_path)
        .collect();
    let commitment_by_path_and_z: BTreeMap<_, _> = all_paths_and_zs
        .iter()
        .cloned()
        .map(|(path, z)| {
            let comm = commitments_by_path[&path];
            ((path, z), comm)
        })
        .collect();
    let mut ys_by_path_and_z: BTreeMap<(Vec<u8>, u8), Fr> = BTreeMap::new();
    for (path, z) in &all_paths_and_zs {
        let mut child_path = path.clone();
        child_path.push(*z);
        let y = match leaf_values_by_path_and_z.get(&(path.clone(), *z)) {
            Some(val) => *val,
            None => match commitments_by_path.get(&child_path) {
                Some(commitment_by_path) => group_to_field(commitment_by_path),
                None => Fr::zero(),
            },
        };

        ys_by_path_and_z.insert((path.clone(), *z), y);
    }

    let cs = commitment_by_path_and_z.values();
    let zs = all_paths_and_zs
        .into_iter()
        .map(|(_, z)| Fr::from(z as u128));
    let ys = ys_by_path_and_z.into_values();

    let mut queries = Vec::with_capacity(cs.len());
    for ((y, z), comm) in ys.into_iter().zip(zs).zip(cs) {
        let query = VerifierQuery {
            commitment: *comm,
            point: z,
            result: y,
        };
        queries.push(query);
    }

    let update_hint = UpdateHint {
        depths_and_ext_by_stem,
        commitments_by_path,
        other_stems_by_prefix,
    };

    Some((queries, update_hint))
}
