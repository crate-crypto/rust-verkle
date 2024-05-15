// This is just tech debt. The golang codebase should be reverted to make proofs opaque again
// and the rest of the code should be handled by clients.

use banderwagon::{CanonicalDeserialize, Element, Fr};
use ipa_multipoint::{ipa::IPAProof, multiproof::MultiPointProof};

use super::{ExtPresent, VerificationHint, VerkleProof};

struct SuffixDiff {
    suffix: u8,
    current_value: Option<[u8; 32]>,
    new_value: Option<[u8; 32]>,
}

struct StateDiff {
    stem: [u8; 31],
    suffix_diffs: Vec<SuffixDiff>,
}

impl StateDiff {
    #[allow(clippy::type_complexity)]
    /// Returns the keys, their old values and their new values
    pub fn keys_with_current_values(
        &self,
    ) -> (Vec<[u8; 32]>, Vec<Option<[u8; 32]>>, Vec<Option<[u8; 32]>>) {
        let mut keys = Vec::new();
        let mut current_values = Vec::new();
        let mut new_values = Vec::new();

        let stem = self.stem;
        for suffix_diff in &self.suffix_diffs {
            let suffix = suffix_diff.suffix;
            let current_value = suffix_diff.current_value;
            let new_value = suffix_diff.new_value;

            let mut key = stem.to_vec();
            key.push(suffix);
            keys.push(key.try_into().unwrap());

            current_values.push(current_value);
            new_values.push(new_value);
        }

        (keys, current_values, new_values)
    }
}

pub struct VerkleProofGo {
    state_diffs: Vec<StateDiff>,
    commitments_by_path: Vec<[u8; 32]>,
    other_stems: Vec<[u8; 31]>,
    proof: MultiPointProofGo,
    depths_extension_present: Vec<u8>,
}

pub struct KeysValues {
    pub keys: Vec<[u8; 32]>,
    pub current_values: Vec<Option<[u8; 32]>>,
    pub new_values: Vec<Option<[u8; 32]>>,
}

impl VerkleProofGo {
    pub fn from_verkle_proof_go_to_verkle_proof(&self) -> Option<(VerkleProof, KeysValues)> {
        let mut depths = Vec::new();
        let mut extension_present = Vec::new();
        for byte in &self.depths_extension_present {
            let (ext_status, depth) = byte_to_depth_extension_present(*byte);
            extension_present.push(ext_status);
            depths.push(depth);
        }
        let mut keys: Vec<[u8; 32]> = Vec::new();
        let mut current_values = Vec::new();
        let mut new_values = Vec::new();
        for state_diff in &self.state_diffs {
            let (state_keys, state_current_values, state_new_values) =
                state_diff.keys_with_current_values();
            keys.extend(state_keys);
            current_values.extend(state_current_values);
            new_values.extend(state_new_values);
        }

        let mut comms_sorted = Vec::with_capacity(self.commitments_by_path.len());
        for comm_sorted in &self.commitments_by_path {
            comms_sorted.push(bytes32_to_element(*comm_sorted)?)
        }

        let mut l_vec = Vec::with_capacity(self.proof.cl.len());
        for cl in &self.proof.cl {
            l_vec.push(bytes32_to_element(*cl)?)
        }
        let mut r_vec = Vec::with_capacity(self.proof.cr.len());
        for cr in &self.proof.cr {
            r_vec.push(bytes32_to_element(*cr)?)
        }

        let proof = MultiPointProof {
            open_proof: IPAProof {
                L_vec: l_vec,
                R_vec: r_vec,
                a: bytes32_to_scalar(self.proof.final_evaluation),
            },
            g_x_comm: bytes32_to_element(self.proof.d)?,
        };

        Some((
            VerkleProof {
                verification_hint: VerificationHint {
                    depths,
                    extension_present,
                    diff_stem_no_proof: self.other_stems.iter().copied().collect(),
                },
                comms_sorted,
                proof,
            },
            KeysValues {
                keys,
                current_values,
                new_values,
            },
        ))
    }

    pub fn from_json_str(execution_witness: &str) -> Self {
        let execution_witness: serde_conversions::ExecutionWitness =
            serde_json::from_str(execution_witness).unwrap();

        let state_diffs = execution_witness
            .state_diffs
            .into_iter()
            .map(|state_diff| StateDiff {
                stem: hex_to_bytes31(&state_diff.stem),
                suffix_diffs: state_diff
                    .suffix_diffs
                    .into_iter()
                    .map(|suffix_diff| SuffixDiff {
                        suffix: suffix_diff.suffix,
                        current_value: suffix_diff.current_value.map(|cv| hex_to_bytes32(&cv)),
                        new_value: suffix_diff.new_value.map(|nv| hex_to_bytes32(&nv)),
                    })
                    .collect(),
            })
            .collect();

        let other_stems = execution_witness
            .verkle_proof
            .other_stems
            .into_iter()
            .map(|os| hex_to_bytes31(&os))
            .collect();

        let commitments_by_path = execution_witness
            .verkle_proof
            .commitments_by_path
            .into_iter()
            .map(|cbp| hex_to_bytes32(&cbp))
            .collect();

        let proof = MultiPointProofGo {
            d: hex_to_bytes32(&execution_witness.verkle_proof.d),
            cl: execution_witness
                .verkle_proof
                .ipa_proof
                .cl
                .into_iter()
                .map(|cl| hex_to_bytes32(&cl))
                .collect(),
            cr: execution_witness
                .verkle_proof
                .ipa_proof
                .cr
                .into_iter()
                .map(|cr| hex_to_bytes32(&cr))
                .collect(),
            final_evaluation: hex_to_bytes32(
                &execution_witness.verkle_proof.ipa_proof.final_evaluation,
            ),
        };

        Self {
            state_diffs,
            commitments_by_path,
            other_stems,
            proof,
            depths_extension_present: hex_to_bytes(
                &execution_witness.verkle_proof.depth_extension_present,
            ),
        }
    }
}

struct MultiPointProofGo {
    d: [u8; 32],
    cl: Vec<[u8; 32]>,
    cr: Vec<[u8; 32]>,
    final_evaluation: [u8; 32],
}

pub fn hex_to_bytes32(hex: &str) -> [u8; 32] {
    hex_to_fixed_size_array(hex)
}
fn hex_to_bytes31(hex: &str) -> [u8; 31] {
    hex_to_fixed_size_array(hex)
}
fn hex_to_fixed_size_array<const N: usize>(hex: &str) -> [u8; N] {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(hex).unwrap();
    let mut bytes_n = [0u8; N];
    bytes_n.copy_from_slice(&bytes);
    bytes_n
}
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(hex).unwrap();
    let mut bytes_vec = vec![0u8; bytes.len()];
    bytes_vec.copy_from_slice(&bytes);
    bytes_vec
}
pub fn bytes32_to_element(bytes: [u8; 32]) -> Option<Element> {
    Element::from_bytes(&bytes)
}
fn bytes32_to_scalar(mut bytes: [u8; 32]) -> Fr {
    bytes.reverse();
    CanonicalDeserialize::deserialize_compressed(&bytes[..]).unwrap()
}

fn byte_to_depth_extension_present(value: u8) -> (ExtPresent, u8) {
    let ext_status = value & 3;
    let ext_status = match ext_status {
        0 => ExtPresent::None,
        1 => ExtPresent::DifferentStem,
        2 => ExtPresent::Present,
        x => panic!("unexpected ext status number {} ", x),
    };
    let depth = value >> 3;
    (ext_status, depth)
}

// Taken from https://github.com/ethereumjs/ethereumjs-monorepo/blob/master/packages/statemanager/test/testdata/verkleKaustinenBlock.json#L1-L2626
// Block number 0x62
pub const PREVIOUS_STATE_ROOT: &str =
    "0x2cf2ab8fed2dcfe2fa77da044ab16393dbdabbc65deea5fdf272107a039f2c60";
pub const EXECUTION_WITNESS_JSON: &str = r#"
         {
      "stateDiff": [
        {
          "stem": "0xab8fbede899caa6a95ece66789421c7777983761db3cfb33b5e47ba10f413b",
          "suffixDiffs": [
            {
              "suffix": 97,
              "currentValue": null,
              "newValue": "0x2f08a1461ab75873a0f2d23170f46d3be2ade2a7f4ebf607fc53fb361cf85865"
            }
          ]
        }
      ],
      "verkleProof": {
        "otherStems": [],
        "depthExtensionPresent": "0x12",
        "commitmentsByPath": [
          "0x4900c9eda0b8f9a4ef9a2181ced149c9431b627797ab747ee9747b229579b583",
          "0x491dff71f13c89dac9aea22355478f5cfcf0af841b68e379a90aa77b8894c00e",
          "0x525d67511657d9220031586db9d41663ad592bbafc89bc763273a3c2eb0b19dc"
        ],
        "d": "0x5c6e856174962f2786f0711288c8ddd90b0c317db7769ab3485818460421f08c",
        "ipaProof": {
          "cl": [
            "0x4ff3c1e2a97b6bd0861a2866acecd2fd6d2e5949196429e409bfd4851339832e",
            "0x588cfd2b401c8afd04220310e10f7ccdf1144d2ef9191ee9f72d7d44ad1cf9d0",
            "0x0bb16d917ecdec316d38b92558d46450b21553673f38a824037716bfee067220",
            "0x2bdb51e80b9e43cc5011f4b51877f4d56232ce13035671f191bd4047baa11f3d",
            "0x130f6822a47533ed201f5f15b144648a727217980ca9e86237977b7f0fe8f41e",
            "0x2c4b83ccd0bb8ad8d370ab8308e11c95fb2020a6a62e71c9a1c08de2d32fc9f1",
            "0x4424bec140960c09fc97ee29dad2c3ff467b7e01a19ada43979c55c697b4f583",
            "0x5c8f76533d04c7b868e9d7fcaa901897c5f35b27552c3bf94f01951fae6fcd2a"
          ],
          "cr": [
            "0x31cb234eeff147546cabd033235c8f446812c7f44b597d9580a10bbecac9dd82",
            "0x6945048c033a452d346977ab306df4df653b6e7f3e0b75a705a650427ee30e88",
            "0x38ca3c4ebbee982301b6bafd55bc9e016a7c59af95e9666b56a0680ed1cd0673",
            "0x16160e96b0fb20d0c9c7d9ae76ca9c74300d34e05d3688315c0062204ab0d07b",
            "0x2bc96deadab15bc74546f8882d8b88c54ea0b62b04cb597bf5076fe25c53e43c",
            "0x301e407f62f0d1f6bf56f2e252ca89dd9f3bf09acbb0cca9230ecda24ac783b5",
            "0x3ce1800a2e3f10e641f3ef8a8aaacf6573e9e33f4cb5b429850271528ed3cd31",
            "0x471b1578afbd3f2762654d04db73c6a84e9770f3d6b8a189596fbad38fffa263"
          ],
          "finalEvaluation": "0x07ca48ff9f0fb458967f070c18e5cdf180e93212bf3efba6378384c5703a61fe"
        }
      }
    }
    "#;

// Serde conversion so we can convert from the json execution witness string into the golang proof format
pub mod serde_conversions {

    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    pub struct ExecutionWitness {
        #[serde(rename = "stateDiff")]
        pub(crate) state_diffs: Vec<StateDiff>,
        #[serde(rename = "verkleProof")]
        pub(crate) verkle_proof: VerkleProof,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct StateDiff {
        pub(crate) stem: String,
        #[serde(rename = "suffixDiffs")]
        pub(crate) suffix_diffs: Vec<SuffixDiff>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct SuffixDiff {
        pub(crate) suffix: u8,
        #[serde(rename = "currentValue")]
        pub(crate) current_value: Option<String>,
        #[serde(rename = "newValue")]
        pub(crate) new_value: Option<String>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct VerkleProof {
        #[serde(rename = "otherStems")]
        pub(crate) other_stems: Vec<String>,
        #[serde(rename = "depthExtensionPresent")]
        pub(crate) depth_extension_present: String,
        #[serde(rename = "commitmentsByPath")]
        pub(crate) commitments_by_path: Vec<String>,
        pub(crate) d: String,
        #[serde(rename = "ipaProof")]
        pub(crate) ipa_proof: IpaProof,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct IpaProof {
        pub(crate) cl: Vec<String>,
        pub(crate) cr: Vec<String>,
        #[serde(rename = "finalEvaluation")]
        pub(crate) final_evaluation: String,
    }

    #[test]
    fn test_serde_works() {
        use super::EXECUTION_WITNESS_JSON;
        let _: ExecutionWitness = serde_json::from_str(EXECUTION_WITNESS_JSON).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::proof::golang_proof_format::{
        bytes32_to_element, hex_to_bytes32, VerkleProofGo, EXECUTION_WITNESS_JSON,
        PREVIOUS_STATE_ROOT,
    };

    #[test]
    fn test_proof_from_json_golang_serde() {
        let verkle_proof_go = VerkleProofGo::from_json_str(EXECUTION_WITNESS_JSON);
        let (got_verkle_proof, keys_values) = verkle_proof_go
            .from_verkle_proof_go_to_verkle_proof()
            .unwrap();

        let prestate_root = bytes32_to_element(hex_to_bytes32(PREVIOUS_STATE_ROOT)).unwrap();

        let (ok, _) =
            got_verkle_proof.check(keys_values.keys, keys_values.current_values, prestate_root);
        assert!(ok);
    }
}
