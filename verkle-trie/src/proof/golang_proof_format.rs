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
    pub fn from_verkle_proof_go_to_verkle_proof(&self) -> (VerkleProof, KeysValues) {
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

        let comms_sorted = self
            .commitments_by_path
            .iter()
            .copied()
            .map(bytes32_to_element)
            .collect();
        let proof = MultiPointProof {
            open_proof: IPAProof {
                L_vec: self
                    .proof
                    .cl
                    .iter()
                    .copied()
                    .map(bytes32_to_element)
                    .collect(),
                R_vec: self
                    .proof
                    .cr
                    .iter()
                    .copied()
                    .map(bytes32_to_element)
                    .collect(),
                a: bytes32_to_scalar(self.proof.final_evaluation),
            },
            g_x_comm: bytes32_to_element(self.proof.d),
        };

        (
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
        )
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
    hex_to_bytesN(hex)
}
fn hex_to_bytes31(hex: &str) -> [u8; 31] {
    hex_to_bytesN(hex)
}
fn hex_to_bytesN<const N: usize>(hex: &str) -> [u8; N] {
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
pub fn bytes32_to_element(bytes: [u8; 32]) -> Element {
    Element::from_bytes(&bytes).unwrap()
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

fn bytes_to_depth_extension_present(bytes: &[u8]) -> (Vec<ExtPresent>, Vec<u8>) {
    let mut ext_present_statuses = Vec::with_capacity(bytes.len());
    let mut depths = Vec::with_capacity(bytes.len());
    for byte in bytes.into_iter() {
        let (ext_status, depth) = byte_to_depth_extension_present(*byte);
        ext_present_statuses.push(ext_status);
        depths.push(depth);
    }

    (ext_present_statuses, depths)
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

const EXECUTION_WITNESS_LARGE: &str = r#"

{"stateDiff":[{"stem":"0x017006b80219b11af2ac6f432126ebbfe7680e7d5524245f7ee6aa42fbbfbe","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":1,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":null,"newValue":"0x0100000000000000000000000000000000000000000000000000000000000000"},{"suffix":3,"currentValue":null,"newValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x04348c5de7dc51e2d9ff4f9f5796fe5803411abbca8b063f28f3161dfe75f4","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x050b1e0fce7ffa3c0a1c09a6a4a49ff1c8016cf4db04ec5ec8a4d9de95597e","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x05e189319992c0fd98c18bfdabef3b2c68f548e3bea9d339380114a014cb31","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x0b7a4c7f9fd61722c1531733626c74b5a92c72b67cfa5881eeb191ce8192f7","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x0b7bbd4ded827ef27f13317598b1192dc038a45a40250b7f5a036ba01f186c","suffixDiffs":[{"suffix":241,"currentValue":null,"newValue":null}]},{"stem":"0x0e7afbe28737e52dbe4cd760de339886e08b481f831a90656b89e3d1dcab23","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x1315b50eaf6d505c7e75621a5629a707747708a48240b9e0ce5b2de216ca2b","suffixDiffs":[{"suffix":132,"currentValue":null,"newValue":null}]},{"stem":"0x1711d8c0b81f750b13dcd0bec790b5cf60fc292c0cb7e886c78d4f26f44151","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":1,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":null,"newValue":"0x0100000000000000000000000000000000000000000000000000000000000000"},{"suffix":3,"currentValue":null,"newValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x1a100684fd68185060405f3f160e4bb6e034194336b547bdae323f888d5332","suffixDiffs":[{"suffix":0,"currentValue":"0x0000000000000000000000000000000000000000000000000000000000000000","newValue":null},{"suffix":1,"currentValue":"0x0100000000000000000000000000000000000000000000000000000000000000","newValue":null},{"suffix":2,"currentValue":"0x0000000000000000000000000000000000000000000000000000000000000000","newValue":null},{"suffix":3,"currentValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x1a14128328cb8fd3aac992186c39d7f4f07553089c3ad193d605e83bac2595","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x1b65200a84306f7cee3350e1ed50c5c69dd419e2544e2c390fdf1033f45dbe","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x207a28ac3a0a304a0ef467ef7ca7aa25c34f38458802c135575c66ac2eed2a","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x20f7f610611c3ce7d998d0d340752eaa7d653c002b159caca10632910fda95","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x2130a4a333c044f6d766d1f252fbbbf59a5a75aea92651a42e36895a0b2d63","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x242271cf1aaa13ede9bb0a1550d6f181c6135afb92be8270221f03cc8a721e","suffixDiffs":[{"suffix":0,"currentValue":"0x0000000000000000000000000000000000000000000000000000000000000000","newValue":null},{"suffix":1,"currentValue":"0x0d1dd99346c4c10c000000000000000000000000000000000000000000000000","newValue":"0xeb376f42173eb90c000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":"0x8403000000000000000000000000000000000000000000000000000000000000","newValue":"0xb603000000000000000000000000000000000000000000000000000000000000"},{"suffix":3,"currentValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x2a24ac441dcb3d88f9edce2fbb9a4a9ca87c1ad87d184d268e8e1a516852d3","suffixDiffs":[{"suffix":171,"currentValue":null,"newValue":null}]},{"stem":"0x2a8e4c809c8e5ca76169f6ca034641002beb6ec7db545d946e0b3fe1f12677","suffixDiffs":[{"suffix":78,"currentValue":null,"newValue":null}]},{"stem":"0x3087c1d3864b8c24f9b2d18881a80beb8c77c1ec32f2a8e89d8d7c4178df55","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":1,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":null,"newValue":"0x0100000000000000000000000000000000000000000000000000000000000000"},{"suffix":3,"currentValue":null,"newValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x319df8e1e52f3924d3ee7bdc4d6f955eb5e16bda0ccf1017575c67d5d646f7","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x344809f462d960744a454e5c049cd1eafaa5fdb0d19685903b40e2aa37bf29","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x35d5b7aa5634a28b8388ae5b1eb5f6e4dc5505d3c50d848c417a7e67f6ad44","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x365939e7176beaac068b84f42ce8f6a54d6ca5c8229e6a4000302035b517cf","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x384f65775d591ce73645c7b57eb8aade9a612972a60aaf09e9971556aba3c8","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x3b2e5d54e5905a039c04527bab9df831b3ae615a5fa9592cde6b49d6f34bc1","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x3b6b317ea7bea32cef0c57098a79ab320ed864b5d6b148511effdbcc06bfc7","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x43bb97899885b913e32e84b99e048518101e63601863f8b00c452f72d686d6","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":1,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":null,"newValue":"0x0100000000000000000000000000000000000000000000000000000000000000"},{"suffix":3,"currentValue":null,"newValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x45690df7630dd877f7d577f2447dfdc9c3960d545c55eac8e64297bc78ac69","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x47ff6581425dd7a090124ffff0eb532b5771b077a630899ae5ca7e7095d9b5","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x48ee0ed3347c9261f5e982d37807924422531ba8ae423eaa34406a051ec8d9","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x49d10a26deee9a6bd255cd504401c47e90a0caf5f54bb0e6d511e0c9ae6d89","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x4ea004ce295bdc23e91211809db4932463065c33f027078f3a8968a95354b9","suffixDiffs":[{"suffix":78,"currentValue":null,"newValue":null}]},{"stem":"0x4f0ec4ffee00047ec425c83896f01a0dab8a9ef2da6763a8b65618165e18e8","suffixDiffs":[{"suffix":108,"currentValue":null,"newValue":null},{"suffix":153,"currentValue":null,"newValue":null},{"suffix":180,"currentValue":null,"newValue":null}]},{"stem":"0x52baa6546d83d159aa555f5a6430174081fb131bdf99a89262f7f3ac44d9a9","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x52d1a52265c5a3743fe1ddcb85794b0de91f7d48b126c2d637854c28717cfc","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x5456025d250761c899c9234818ee09be98139476b967144e097f4d00fa27a5","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x55e755c2523808992fc4c57c0df613348281bd487c5f9f6c448822529a9d1b","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x564b8d3dcb2d0ab4c2c1ad3542c807755bd6cfa583bcf007ad56728111ae86","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x5b1723bfb8987bc2a9ca151e93bea546b5cfb5a5e21aeee87ecacef9ce2370","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x5cfce71f1df2399cc353ad5ad5a4f33622889b115fe338ec4b435a28a376ff","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x5ece59968887d00c91546b4c10c6dbf55978fbd73eb17ad8f7d535cda0c493","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x60e4f5729dd38df2544a016bba055e7a00f7ee34f688990a1da3f3528b4ae4","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x61539fa23e8ed1103c9c6b8e5334d06dbf727e659762744d2ecba3e9421bd2","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x61b2eff1b9b6c70b6981187bd3276c6ea91ad0008a28a5f4198140b5e82a98","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":1,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":null,"newValue":"0x0100000000000000000000000000000000000000000000000000000000000000"},{"suffix":3,"currentValue":null,"newValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x662ec7784240b5924c7379231a1de20cbe68ada97e7ef4b6f076bdc3781e52","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x6944d9432aeeeff727f891982d7582a764465a356ff518e70e2e00bbf2dedf","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x69719d5264ca8dc3633705f016ed52b5edd3ce4f50caca06deaf9bdf5e2cae","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x6b9949a9da1a61cf65eeddaaf55807ea7e4db7d0a3c92df33befb895977e57","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x6ba3f8c865478dfb716f343f393ba26d89550ca4d5c21c4afcd9885591844b","suffixDiffs":[{"suffix":162,"currentValue":null,"newValue":null}]},{"stem":"0x6bfad7fda48dad1d3097b298d236122f1c1721026e2f0da905d582ed471f04","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x6fb379d575aa2f4a2ea81067c6a0fb2c3c4b6888eac9413b1da806b19ee286","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x740e2cbe3aeb15cafefa28beb5fe99acad47f6d0fd801f9d45f36b57c2ff63","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x76d7f376f13a60e2c0793f3329134594a98660d27015da1431c0c69e9fca8e","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x77687783189656f37cd56aa158a685debb20c5839d5e3bcf7e176f04277bd9","suffixDiffs":[{"suffix":108,"currentValue":null,"newValue":null},{"suffix":153,"currentValue":null,"newValue":null},{"suffix":180,"currentValue":null,"newValue":null}]},{"stem":"0x7b4b1a5b730a5406ddf1852bb870f20558bc4eb390d60a914eaac157cd12b7","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x81ba3da96d6ac3aa57d206ada35b53f5615997c74b87df9bfa82d979280451","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x833be99f57f9e79b93af274c3a5d5e19c2d68ff1d0a44b596b0c6384fd61a6","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":1,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":null,"newValue":"0x0100000000000000000000000000000000000000000000000000000000000000"},{"suffix":3,"currentValue":null,"newValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x83c8996e4ddfe95ab7954f305f09b3f785aebd3066386f8ca9f7d53101104d","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":1,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":null,"newValue":"0x0100000000000000000000000000000000000000000000000000000000000000"},{"suffix":3,"currentValue":null,"newValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x83dec4a9ebad542c5528b4df06b31c8661fe31739674af112f0a69d0910230","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":1,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":null,"newValue":"0x0100000000000000000000000000000000000000000000000000000000000000"},{"suffix":3,"currentValue":null,"newValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x8e786c7ef5325b72798f9efd5266622117f7fcb8b2b9f03a459ea82300b855","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x91a13b1f2af7688f4f20de48b33ebadeec275800e236a624ecb4290a9b60ad","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x920c19457d19e4f9c94314ae9ce3e9428e12057841e40529a93d4441c0303a","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0x96420dcc4d31b95ea8d0d9005cf04fb5c9bf08e0ca5bf151c57f701fcea830","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x96ed99018bcdb2439b664559f70a95ec161cfc6ef2b8e1b42ff61733e87f8e","suffixDiffs":[{"suffix":0,"currentValue":"0x0000000000000000000000000000000000000000000000000000000000000000","newValue":null},{"suffix":1,"currentValue":"0xf6f88a5683596b01000000000000000000000000000000000000000000000000","newValue":"0x8613f858f9757e01000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":"0x0000000000000000000000000000000000000000000000000000000000000000","newValue":null},{"suffix":3,"currentValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x9a05a4f94fed9cb8c240e4885f9e068c4712059bc0221223b377baf6be4e98","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0x9bcc5ad0a8cfed450d57a03d05402e2203dec8ba34d4d8cc800fddf803ccf4","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0xa1451bc49d9a925b85cc03213d8e8efc0efc710b720771f23ad6cc080af480","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0xa73a40fb17eb080f9391757de06a9465fdd43780b22428a7dd4166eba5d176","suffixDiffs":[{"suffix":172,"currentValue":null,"newValue":null}]},{"stem":"0xa85f7611bd30eed59670730a83ae83f1a31b0a1a2f287804e8f8bde77ff9f7","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0xa94b8dbcbbbb534b6bd0b029cf30414f96c81362fa791006b1bd584609d02b","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xab8fbede899caa6a95ece66789421c7777983761db3cfb33b5e47ba10f413b","suffixDiffs":[{"suffix":108,"currentValue":null,"newValue":"0x413b27b3edbc2826da866d330a7ff816ec267f09c7f4d492406ee063bd127153"}]},{"stem":"0xad813fcc9aec4ce51374ec9ea4b171e7de0bcf11462af58f576aa226dd35f2","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":1,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":null,"newValue":"0x0100000000000000000000000000000000000000000000000000000000000000"},{"suffix":3,"currentValue":null,"newValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xada8a5278c7337bfb9320156b868b4c9b124f8f1b62b949691d8208fddf69e","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xaebb71c04f6273f406e7c1d015dca28a5e5ee8d858e8cd75b945f4dd72ff77","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0xb17520caffecdcc97ff6cf44d336a2c3818a6a54bf2c3648215e0268d5ff28","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xb72fe117daedd24307cd572f36441f9fdbd49f019a97f38595b7ac65f1fb99","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xbb3e63f8567153d167c5fd54acbf91099446debc040fbacd305996300a216f","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xbea886b9a10dd38669b733a224100fe82c0c09a86d56e6c357d79d9f375a8d","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0xc1975954643279b1395b7d772c759d8dd2869e381aed642a0d1a8736d7c3ae","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0xcbb0c1dbd6c412fca45bead6bba2188933010dd479c18a9c3329a4d8e51717","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xcf5408fa602d6dbd8e2e641d14958a88836476fd0e0a32daa0de56ead34d24","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xd0cb01f479589dcf5074c338b07ef9d349fe7590be9b9313d4ae8f27401c5b","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":1,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":null,"newValue":"0x0100000000000000000000000000000000000000000000000000000000000000"},{"suffix":3,"currentValue":null,"newValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xd209b6c228aa78abeb593ff728d6ed3d257a3b82d0020603e674993fab6796","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0xd2a72bd4223e9652be02f886fd9a44ed6de8f9e8ce1800d33d9ebb4af0a60d","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0xd6fe81c6a1c388c8724583effa65d570126cb26be9f16e4b010138dd6d3c3b","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xd937a861c647cd7c8b99ffeac78b6e500c48ee13277d8a3729b9f5c8e62ace","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xdaf8572da38f6a2609cabe448c42a5f1a905fadca9cf7bdfb43aaf72c90071","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0xde9153b229430c15801ad845246deaf1e23186b7cebbdd8c76832cbb34f81a","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0xdf67dea9181141d6255ac05c7ada5a590fb30a375023f16c31223f067319e3","suffixDiffs":[{"suffix":0,"currentValue":"0x0000000000000000000000000000000000000000000000000000000000000000","newValue":null},{"suffix":1,"currentValue":"0xec3b8f34b0d5ba0c000000000000000000000000000000000000000000000000","newValue":"0x4609eccc673fb00c000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":"0x8403000000000000000000000000000000000000000000000000000000000000","newValue":"0xb603000000000000000000000000000000000000000000000000000000000000"},{"suffix":3,"currentValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xe1374c0c78728f3536a2a39216ba62a811e8f442a387dde4b3799cd37b6325","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0xe5fd64405fab652a1f8bab8e379e9e8cd373d2eb8c07d315ef6b14abe673b8","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":1,"currentValue":null,"newValue":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"suffix":2,"currentValue":null,"newValue":"0x0100000000000000000000000000000000000000000000000000000000000000"},{"suffix":3,"currentValue":null,"newValue":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xe6d385e89fcc7b13c0a3021cce93f021b11fd5f6295b3f6abe37761cc3fe59","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xeb23116380cc99cf8f2b8073dff5cf91941d44551e52d37303738276c258f6","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0xec6f07dd16d567ea94842fa36ca36dd94060142a60a7f144fd551d0c8e39f7","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]},{"stem":"0xee433a9309144d7ffccbd22b7f16421da0c68fcb44418cd01584e9486ae0bb","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xf98aee38f85fe1701c0cc22a08a171e8005410bd605638224975e39380351d","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":1,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null},{"suffix":3,"currentValue":null,"newValue":null},{"suffix":4,"currentValue":null,"newValue":null}]},{"stem":"0xfcd754911b1b7634e6341dab99477f96527fd294b0eafcbed314d85898fb8a","suffixDiffs":[{"suffix":0,"currentValue":null,"newValue":null},{"suffix":2,"currentValue":null,"newValue":null}]}],"verkleProof":{"otherStems":["0x047fcb202908cc002ea7cb645586cec152be8d8a170848ad044999c8563386","0x0ed32063daf65c1a44283813ba890843d1710143d061930199ecdf29250f01","0x307e2d1d6b9252fe6017a1577d27eee29a32314e68499b600bc1dec125bdf3","0x31c3393ffca13d19aa27b799d5bb93777f75c50c08548beca9f789e825f8d2","0x35e37865cf898ca89a6617057171a185ea0349923347a31ec92215e8fee705","0x3672f36fca2eaa3c2c1336bae8244a3df0a5e26f360d00916c14392776989e","0x3834093f36d29dec928b59e0c076b6e42ef5027e2bdb4dc7bb91c7d8c46506","0x488a440c7df074cb8191d657efcfa26ca28305404509a61914603faaa3f643","0x52f94c3594cb6d3c2bd956fff5940684786dfa1b968c584f6eb844df953746","0x5c6e42f42e98a787b1d0b9b5dc7a67732990e36ae06f59e7e7aac61836d6f3","0x5e5b7da56b2d4410da4e8427edac25d9014f7f7d38f61bb0cf0a1cb3d5d446","0x779ebf0394bb66dfad42c39874ab660541adb5b2a537469da5de5a6e660b0c","0x91a194aaa873dcae8546b4660631d9e47d06f1277533afa45308bfb7da91c8","0xa84aaa726b189a530eda32611eef4de5bba5dab33f108c7e9c5cc25ea34ae5","0xcb782f2de3586730e4f3fb872c7d83c1e3286460cd2dc23c47da0e46ef4ac9","0xd092de740adcb52108f42fc495a04faad6724d07e2c65febec47e9d765a08e","0xd9d86873e926dcc8d3ac6b190e54e71c40018c041d7b3a98f04c143dc4bbfd","0xda2cb66b79815fd0b93f8d6867feeb3ad69e34953e24c74abd3785dbac9f37"],"depthExtensionPresent":"0x10090808101009101012101010101012101009091009090910101010100908101009091010101009090808081010101010101010100910101010101011101012101008100910121010101008101010091009101010090910121010101010101010","commitmentsByPath":["0x722e1493938ec7e02160e25cb4999d7dabbb87f4b782ee9a6877838589085608","0x3c6264fb37bcac4e73ee1c78e60a1ba18ad8a9fb5de9ab99448156ce9a7fdba5","0x628384eb3cc6f31e3c7c9680b3c2a7c64570cb4c4df8e9d5dd292dcf67e4a7e1","0x34e82e045983b9fcebe07c5470b86314428e44c5bd0788bbcb6801eb835ceb0e","0x0312a52969e2641bfcd4bf0011b5f05d77046d08bb09c151a6f3708f2cab7efd","0x3aa4441b6c89365e21093ad98d32f286075e8ce26a907e99f1907e2c7920baff","0x37e9a7aec30a2f9512e1e3c4a1acd943e9d12b5d8a34e1821577a3e12402b33b","0x427b4a9ef0138f38eb2aa1004b32318028f41c34b3724313b73b4bbb3c7fb2a9","0x62dbc83963aef42b5c6696695bbbf01e92ad6d0db9e565b687bc145b463ec46c","0x2b0c3a24578268bfc761370d7d80c9851696db9698f7b6d50e92dcdd0b1d4215","0x21f1028ab40231e832b0b3d1f329127c29bc6c0f759a2ab35b8979f4cc7e82ae","0x4a366be28d0f65fbd93c8ef9cd1325c4a0326958d48626a51320fb19e1cebe07","0x27b370e1dcc37bd732fd3e5621f7b8ba5b83b3613824176799827a27f440e92e","0x25ad2426f631f76e94b1bc7a61a22ab4fcbc81905e8cd22da57887b3e398f090","0x6e07f6e4d24ab9aad8efe8db587db88f741671ba87efb85f385cb0043a46d103","0x64a7523c3a018a7d25bc824bb2ba0472d1f4b25630a4fa745f4cca61ef9aad0b","0x2361e30c77b5b1b5da73a446e7d6e78d67fc93e622e14aea409c34167ed34ff4","0x0e61ce0dc0366a7445ca583488912c5e26e21d69e768ceb2d3ff3194f166521e","0x1c9bd61333adb8f883866d4ebd33d2ec82786e6d6861ccaf95d54c9609841c0d","0x6bf63b2962a17a5da1567d0b3e8f3aedf17b8f0794804bbfdb152ea11f7f27b0","0x3222ea187aceb06553ecfe95d54a07bd6af3c4ee72eba4b4fce12a70fe7f7a25","0x4d78e3e86f807c6985268c878201a78ef9c3aaddff89c11888eb4bbafcb88aa5","0x0f0389697ab0a56792d6edd658708de1a7b52abea94ae0ddcc57ad76587693ff","0x587b29d9db85a566a206acc02245525c074d014046c5307bb29f6576a9444e8e","0x161ce7d2b6125bc0cc1b8807f6a341bd60099209790b43af0dd19752c7167d17","0x030caa77cf96039c5479b253008f3e8f399454fdfecc7ea87db0462a2fb69498","0x0bfe1faab7f13468a927aae175259d44c0d153a1f448b5b0ad681435bb4d3a60","0x59bb5ea3ac59d0d710897a93bbc1787712479b8a007355bd8320124e865b484a","0x14929fcbcc77ff4e60c3ce8281421589e4958ed0ffcc70c6172d7b1010268c40","0x028c9e37d89d201fbcb4f7d23e309701753d8304290871d28b2ced463bda56f6","0x5e8894015874cd7297da97a37f06dad7b4ad9bfa74baa9ec925a054c3655b8e3","0x6f569313f73d95ae204309dffbebb62672122d5fa053ae5647fd9ad80619ef2c","0x0d7a506c35e95ca6f482ae1b9641efb198635e219f874e43ea5f3acbaf48473c","0x1b8f1bf46af4187406944237fde359775ca2cad40d35bd5e9bd4ba5a9caa828e","0x6463e2bad091c34c8ac966a23b669f07005e724fcc60ff18f3f9b9f7586d7544","0x5b15a9239319470095f7b59631eb6acedd013df1c3768058a59916c34e103eba","0x690e98ec45cf5d9bf56df3cb85ea3975c357925d2ebee811ea2ef00322ee322f","0x3ee00bb6db4653ab3c3c010235a49dc8a1e6b243ef1eb5d9cceb8aab9696caf3","0x2a1c9995538a9992a5573f759490bae6dc720ed1098e2bad43546dd5bb4c520a","0x2aa951abbb03d98ebd822c492d577e7f8617fae2f439e26ab1313e479c68824d","0x4d0faee78baba86f2fb76dbef315323a010fddccb2adec613f494726af68c658","0x2416c1405bb8f7407631895af40cb1c42d1ecccfb7a4c6909cad91453db44603","0x4b459308d11efab0ddc71fb2d9de1f6ab6215c0f2662e7a4ed84afe547907367","0x7005223d163d8f7610ba5b6844d4eb5b47b411ea6b36a584ec401a3ee969e5e2","0x2f3473b9a8c0d32792700ed1b1ea8adcbf912e70e2bce1750c8ee595857b45b6","0x1c3a2ae1651eb5b00284fbc92ad530c740bc9dc7a26b0df7161b3a51c64d9305","0x414ab1efe26958ce1ec86e7a22523157638a17429872c3593cf4d39871360cc3","0x23f8b7161eecbf64eb8ad567b5aaeaa4aa1144ecd50ce06821537bfd2d415619","0x033a03296f06e0cd49d9e79fa64b72ab31de3ce21d454c34b1e233d9efd82862","0x6cfd0d9c1f59f48cc031087a72195dc9b6628262def798ab4c72892b5a4fbfa7","0x1432a371219dcbe09b6a271efc2d318d608a96ae932cc1f02574a569bc611053","0x0154b48424135d1d14b3e9a3e42dbd49634bebbb5155f0329e0a01ba9ee04d4a","0x5e5c46ef572540518d9900b25a73edd5aa1e90f9c22c4ae15a87cb3cb28c6f74","0x0d12ff36a3ef3769f92c05401b4b497f7f7d36a4dfb11b0502a6491a5ad46ecd","0x1ca171c1e8cafb84a36296cf77077e97e14fd55eb3a7b45529ef61cec6a60253","0x45b69ca639a9242a13ebb95a6558a62e5c802cfee6c711080fb32ff36bc9dca3","0x238d900d046f953295a656baa888396741277108ea3fd267db63dcb0a8b39e2c","0x3cb282d5a491e04ed1bd611c9206314c54803877155de3e5c27e39eb5deef0a0","0x5dad2926e2f6595dbf5f4afb7e78e485779fc5d81b1f262424caddc5e0df3089","0x195459a67a8cf70a9ceb5d0de533b97ef0fde79c371984dea6f6117a0596a6b3","0x388da52999461736bc4a7ff4f23628faf28e3eaccbb557346ef1d4a03524ff2a","0x40b535266c62bb27474596369aabc1a0fa5b4a628c85ef03aa949461f5cbda94","0x5cddd43de764b07615d5d45b98b8999a20c024382cdad665037a0d0ba98d5979","0x17446a59fc4bfe03d2f1ea6ca74307831d2d2753675569291da6011f130f9e0e","0x18cf68430324d0854a076ed958efc04223bed8d53355b331250c5c00e38bb878","0x48a58678f2b787e7054124e129baae331a5d637a26c6447470b10c4229c0e3d5","0x68d276a644c39a9a96c24185790d94b68acd8e0fe127957cf663cf90fa480a14","0x35bdffa38d4e528c9013926bba26ada9d33b3ec8ab5d4c6216230ed2f1d17605","0x172e4b0ebdb0da24f90f60570a7db2fd3a47bacca549eba99a9cc1d40b26732e","0x58917df0d0901cf067af992294f5487e64225cb3137e85d071c4d501b2c2d888","0x3b90981ce58e0aa481a76a1b4a4334391d10954f4b16d778cc6e3240b20645f8","0x1b6413aba15fa70614a5f19861e9dc5e2b48f8479606adb20bde6cd70f75f0aa","0x73ae14b1bcc9f1cf2e5e14e9d700b4dc5753e437f33eb2ff65e8cacf7c8c7877","0x2b71abc98c616732dcc7c3efc21684a31e6db0e96086cf26fe42c32b63444fce","0x6892cc5e72694ecd1989a72cdf038b72bcf41b8872bf77c78d07e5b5e72ae593","0x347f4eb32b8989061c251a30df032a3064b20dadf5ef608a17f66bf812d94d58","0x719833286499ad548906acd63399c44171b72b55a917ff2ffca0853c074a697a","0x2a51a21533cf3324c16244167d9b0b5e9f29ae7f4db5a786a5ddaed3a91de6da","0x593de6cdabdb1fc46fb439568f3e73810ff49dca3503c5b431e3a07bdedced0e","0x06b9b5816f9f1596e958c88ef9cd330c2919a0c716597ef356a9649efa1db061","0x6044defcef09b20c334c8eed3912c05e26b9ca99f71cf8f5bcc00a1b02564e38","0x1d63e0eb41b62e8c915bf38c4e7c63f5ea098dae4b7958cf6e3e9877d4595729","0x4115c344d113c884ecab66a2506cdaa0d721aa8e2ac29989e9f47bab0172b999","0x18ca7cb9e211abf9c2c1cb82f2355dcf30921ea70cd5d384fc44b0bf5227772f","0x14cec786771992338db76d054d8e0dfe9154eff89ced6f0c5f5e4ae4ec211353","0x71237e0ec5162fcb3af67bbe3a14c3f3db30125e51d6ceabc700ad9d0a9f0373"],"d":"0x47d3666feee19bd296e38c6aa00c575c30c09cf1fc1581daa0e2e5fdee1cc5f9","ipaProof":{"cl":["0x332c48bbd2df9e72de83c5052e33e99a4f93d07e9d92a6dea49cd8e435295dcd","0x545ae01e779e127cf3022def3732209dcceb5bc31ebf4b027d58b72a9cf2865f","0x56ca8306b174f1df39083f5a4d2c091e0a9ceb5c7a672681a98ce74335ac2f42","0x5305fec10a1c58ddbfde8d11dbc91a0e0257e5225d5541ac6c075a916fda6f8e","0x03e1ddc854ec5971caa93579321032381bf75d1f22074ccccbf1bc1cda7f5b98","0x5e54a97baff18144373e7c420010b5ca522fee050d9581e93780485fc4427142","0x013fe6126dbc13b3a415fc27409dc3fc3289f211ca8e5d9c8c3d8c5c3e1cec2b","0x66d5a793e1819fee933ff73a2ad7a280c21afdc08c14f455acf5fcff775abcd3"],"cr":["0x623efd491a9c0f14763f1630a87a5f79a0ac5c4e50f22c7d736342b860598a55","0x340faecdc1936cf28b80a02d02fbb5e8de813778d88d55a54f60ec15533d5441","0x149f9c62c047d137ebedd5da0091a7ed1b56c6941876344ab1c1bd90d16ffe22","0x4c28c783e094b245d7db7d3fc27570e581685124b3e93be2d21e292d9414f1d1","0x63d5c42c57106af72fea85189dc37294113c7993b22eedafb3a30f49e80118bc","0x1d17cb296463a5927a1c4dd611050c2de50584710e921855e6537f0dd3eed145","0x459373a019abd2efb51552de9ef310442d995ce0394bc4ce520d9551fd32ac7d","0x65900b8082d0273423e75408fe2f04ad572adc56afb3d47748aa8fe7257662de"],"finalEvaluation":"0x0947489acf359e2e0d8150f2e0024de202640528cb1a47e86df9e1b2a779aa86"}}}

"#;

// Serde conversion so we can convert from the json execution witness string into the golang proof format
pub mod serde_conversions {

    use serde::{Deserialize, Serialize};

    use super::{EXECUTION_WITNESS_JSON, EXECUTION_WITNESS_LARGE};

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
        let _: ExecutionWitness = serde_json::from_str(EXECUTION_WITNESS_JSON).unwrap();
        let _: ExecutionWitness = serde_json::from_str(EXECUTION_WITNESS_LARGE).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use ipa_multipoint::{ipa::IPAProof, multiproof::MultiPointProof};

    use crate::proof::{
        golang_proof_format::{
            bytes32_to_element, bytes32_to_scalar, bytes_to_depth_extension_present, hex_to_bytes,
            hex_to_bytes31, hex_to_bytes32, StateDiff, SuffixDiff, VerkleProofGo,
            EXECUTION_WITNESS_JSON, PREVIOUS_STATE_ROOT,
        },
        VerificationHint, VerkleProof,
    };

    #[test]
    fn test_proof_from_json_golang_manual_conversion() {
        // block number 0x62
        // state root
        let _current_state_root =
            "0x1817126b2e3f5bb9a77835e46cb42ce46f35968d0fcf2ef2b6678c7d826e49dd";

        // state diff
        let stem = "0xab8fbede899caa6a95ece66789421c7777983761db3cfb33b5e47ba10f413b";
        let suffix = 97;
        let current_value: Option<&str> = None;
        let new_value = "0x2f08a1461ab75873a0f2d23170f46d3be2ade2a7f4ebf607fc53fb361cf85865";

        let state_diff = StateDiff {
            stem: hex_to_bytes31(stem),
            suffix_diffs: vec![SuffixDiff {
                suffix,
                current_value: current_value.map(hex_to_bytes32),
                new_value: Some(hex_to_bytes32(new_value)),
            }],
        };

        let (keys, current_values, _new_values) = state_diff.keys_with_current_values();

        // Verkle proof
        let _other_stems: Vec<&str> = vec![];
        let depth_extension_present = "0x12";
        let commitments_by_path = vec![
            "0x4900c9eda0b8f9a4ef9a2181ced149c9431b627797ab747ee9747b229579b583",
            "0x491dff71f13c89dac9aea22355478f5cfcf0af841b68e379a90aa77b8894c00e",
            "0x525d67511657d9220031586db9d41663ad592bbafc89bc763273a3c2eb0b19dc",
        ];
        let d = "0x5c6e856174962f2786f0711288c8ddd90b0c317db7769ab3485818460421f08c";
        let (extension_present, depths) =
            bytes_to_depth_extension_present(&hex_to_bytes(&depth_extension_present));
        let commitments_by_path_elements: Vec<_> = commitments_by_path
            .into_iter()
            .map(hex_to_bytes32)
            .map(bytes32_to_element)
            .collect();
        let d_element = bytes32_to_element(hex_to_bytes32(d));

        // ipa proof
        let cl = vec![
            "0x4ff3c1e2a97b6bd0861a2866acecd2fd6d2e5949196429e409bfd4851339832e",
            "0x588cfd2b401c8afd04220310e10f7ccdf1144d2ef9191ee9f72d7d44ad1cf9d0",
            "0x0bb16d917ecdec316d38b92558d46450b21553673f38a824037716bfee067220",
            "0x2bdb51e80b9e43cc5011f4b51877f4d56232ce13035671f191bd4047baa11f3d",
            "0x130f6822a47533ed201f5f15b144648a727217980ca9e86237977b7f0fe8f41e",
            "0x2c4b83ccd0bb8ad8d370ab8308e11c95fb2020a6a62e71c9a1c08de2d32fc9f1",
            "0x4424bec140960c09fc97ee29dad2c3ff467b7e01a19ada43979c55c697b4f583",
            "0x5c8f76533d04c7b868e9d7fcaa901897c5f35b27552c3bf94f01951fae6fcd2a",
        ];
        let cr = vec![
            "0x31cb234eeff147546cabd033235c8f446812c7f44b597d9580a10bbecac9dd82",
            "0x6945048c033a452d346977ab306df4df653b6e7f3e0b75a705a650427ee30e88",
            "0x38ca3c4ebbee982301b6bafd55bc9e016a7c59af95e9666b56a0680ed1cd0673",
            "0x16160e96b0fb20d0c9c7d9ae76ca9c74300d34e05d3688315c0062204ab0d07b",
            "0x2bc96deadab15bc74546f8882d8b88c54ea0b62b04cb597bf5076fe25c53e43c",
            "0x301e407f62f0d1f6bf56f2e252ca89dd9f3bf09acbb0cca9230ecda24ac783b5",
            "0x3ce1800a2e3f10e641f3ef8a8aaacf6573e9e33f4cb5b429850271528ed3cd31",
            "0x471b1578afbd3f2762654d04db73c6a84e9770f3d6b8a189596fbad38fffa263",
        ];
        let final_evaluation = "0x07ca48ff9f0fb458967f070c18e5cdf180e93212bf3efba6378384c5703a61fe";

        let cl_scalars: Vec<_> = cl
            .into_iter()
            .map(hex_to_bytes32)
            .map(bytes32_to_element)
            .collect();
        let cr_scalars: Vec<_> = cr
            .into_iter()
            .map(hex_to_bytes32)
            .map(bytes32_to_element)
            .collect();
        let final_evaluation_scalar = bytes32_to_scalar(hex_to_bytes32(final_evaluation));

        let proof = VerkleProof {
            verification_hint: VerificationHint {
                depths,
                extension_present,
                diff_stem_no_proof: Default::default(), // other_stems is empty
            },
            comms_sorted: commitments_by_path_elements,
            proof: MultiPointProof {
                open_proof: IPAProof {
                    L_vec: cl_scalars,
                    R_vec: cr_scalars,
                    a: final_evaluation_scalar,
                },
                g_x_comm: d_element,
            },
        };

        let (ok, _) = proof.check(
            keys,
            current_values,
            bytes32_to_element(hex_to_bytes32(PREVIOUS_STATE_ROOT)),
        );
        assert!(ok);
    }

    #[test]
    fn test_proof_from_json_golang_serde() {
        let verkle_proof_go = VerkleProofGo::from_json_str(EXECUTION_WITNESS_JSON);
        let (got_verkle_proof, keys_values) =
            verkle_proof_go.from_verkle_proof_go_to_verkle_proof();

        let (ok, _) = got_verkle_proof.check(
            keys_values.keys,
            keys_values.current_values,
            bytes32_to_element(hex_to_bytes32(PREVIOUS_STATE_ROOT)),
        );
        assert!(ok);
    }
}
