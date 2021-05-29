use ark_bls12_381::{Bls12_381, Fr};
use once_cell::sync::Lazy;

use crate::{
    dummy_setup,
    kzg10::{precomp_lagrange::PrecomputeLagrange, CommitKeyLagrange, LagrangeCommitter},
    point_encoding::serialize_g1,
    Key, Value, VerkleProof, VerkleTrait, VerkleTrie,
};

const WIDTH_BITS: usize = 10;
// Setup secret scalar is 8927347823478352432985

static COMMITTED_KEY_1024: Lazy<CommitKeyLagrange<Bls12_381>> =
    Lazy::new(|| dummy_setup(WIDTH_BITS).0);

// static PRECOMPUTED_TABLE_1024: Lazy<PrecomputeLagrange<Bls12_381>> = Lazy::new(|| {
//     PrecomputeLagrange::<Bls12_381>::precompute(&COMMITTED_KEY_1024.lagrange_powers_of_g)
// });
#[test]
fn test_vector_1() {
    let mut trie = VerkleTrie::new(WIDTH_BITS, &*COMMITTED_KEY_1024);
    let key = Key::from_arr([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    trie.insert_single(key, Value::zero());

    let verkle_path = trie.create_verkle_path(&key).unwrap();
    let proof = verkle_path.create_proof(&*COMMITTED_KEY_1024);

    let (D, y, sigma) = proof.components();

    let proof_eq = ProofEquality{ 
        D: "a18a581ed272dd9396e05fe710a704d74b183d786cca5eff34957afe8ecc3014192f556013098d10b64ae6065d97541c", 
        y: "29cd64bf1ec5889042f16b6724909087e788c0f08f066ca8d207fee361a98616", 
        sigma: "ad0929802d2866123eaa895a6ae79e7ecf1c6be59f6baac4dcc6a11d8c1377677649aecb51a224a1f860bfdbdb290bfa",
    };

    proof_eq.check(&proof);
}
#[test]
fn test_vector_2() {
    let mut trie = VerkleTrie::new(WIDTH_BITS, &*COMMITTED_KEY_1024);
    let key = Key::from_arr([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let value = Value::from_arr([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    trie.insert_single(key, value);

    let verkle_path = trie.create_verkle_path(&key).unwrap();
    let proof = verkle_path.create_proof(&*COMMITTED_KEY_1024);

    let (D, y, sigma) = proof.components();

    let proof_eq = ProofEquality{ 
        D: "b8bb3f84e5fd58cb618595c01e56468e5a1dfc49a055fef451569f31c642d27c52e87efbe56c25f67aa08fba12b2242d", 
        y: "896e83fdb8f0cd73a139f700bfdfed2e88336a5911de5a162b5c17e3b66d131f", 
        sigma: "90e9a6e324504296651c9b45b155099d5619b0c5d5b42904b0fae54fe23fd8a84169894779506c020da9b26c462ce8eb",
    };

    proof_eq.check(&proof);
}
#[test]
fn test_vector_3() {
    use ark_ff::One;

    let mut trie = VerkleTrie::new(WIDTH_BITS, &*COMMITTED_KEY_1024);
    let key = Key::from_arr([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ]);
    let value = Value::from_arr([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    trie.insert_single(key, value);
    let key = Key::zero();
    let value = Value::zero();
    trie.insert_single(key, value);

    let verkle_path = trie.create_verkle_path(&key).unwrap();
    // All evaluation points should be omega^0 = 1
    for root in verkle_path.omega_path_indices {
        assert_eq!(root, Fr::one())
    }

    let expected_polynomial_evaluations = vec![
        "c4c441fdceab8071a4cbc26c03bed8d75df519efc4aaa3529413e99ecb4ec43d",
        "2890e6970eabaa3f5e0e6f6140b0cc582000e73d2d8ce539dc1606be9195d24a",
        "d5a1da0713a3361691b801b2bd5f4107094f863d6027d4236b18e56911072b09",
        "08b6af1f349ee300aee3d0fcba4d58a313ba35082f5c7020246eb1471ea78265",
        "f0c979b0ed3c16d0e8131a097faef89172c714cc442161d24a3955a010f32e64",
        "306b111c3d5bcb1382dc28c54445614dc89087b32b9b58a8e681b188d89f9064",
        "f3da6be0b9db5876ec0b72d9f3abaec2243ab394abbb31644f7ab24917687006",
        "ac4e7569cf5c77f1684a0722c7dc6eb0984b4ead255076f96acb1d08bb0a4436",
        "b30b89d63f467f677ee8d9c12ba71c9f524a3fc42374d887cdab354f22ed3a0f",
        "521aa2f923a1db16c5149901f7bfd3cc76110cb11b482c9256da441b369d2402",
        "aee78a6493b7a0a7ed82a4f874c31fec7f0f158c479835ed562b65e7f962690c",
        "d23b21adf942f6c04d9936a4563bc42a685c593a4a7f0402f5b85dcc24d43052",
        "d749567e06988384bd434a77013c875f1a18c4f0100c6157931b0240e73c8544",
        "f0a142311f264ee3de5c29c9fd5cc4bc5300be646c5b0ea9f6b7cd7ace258409",
        "d96dec830b81219aa3eb55945fc701aaeb84090178b8cea4363bc42d63223a5c",
        "10291acead276b74c0a54d044d0e65416ac7b1be24f5682de447e7324eabf33f",
        "6617d59b1a2ed7c5ae33fff1fd96e3dbbf5cdf46f69713641c63c09b6ec91b6e",
        "a490c475e0379c7dca63d44aef09c6f5e98d5c81847ff62f6fa5891f529c4e06",
        "f039d4bd042021077191a921c93f762e566ffe66f7a8f57925a92fa354629236",
        "59e5fb41874ca5ef420ad3410098bf515902703733e60cf653a1d01ccf0b7137",
        "ffe30535143af130a1cafdb74c956164c118db7c19b1490f398460b2c6c3f33f",
        "9a72b4cd320b3f19f72d610f95aea233b30246b677881e9214c787b594c80409",
        "201c228595119cdbba68cb18bc6b1cdebe0d9c14b9944efd2981dea1d8602941",
        "21becc0b58a865cda03fb59e7d3747831b068befba4b765155ea88f860bbe462",
        "ae1a036b767e768f1bd61ccdd33727f9adab4f2ee1fbd2c1134086e4f563ea0d",
        "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
    ];

    for (got_fr, expected_eval) in verkle_path
        .node_roots
        .iter()
        .zip(expected_polynomial_evaluations)
    {
        let got_eval = hex::encode(ark_ff::to_bytes!(got_fr).unwrap());
        assert_eq!(got_eval, expected_eval)
    }
}

struct ProofEquality {
    D: &'static str,
    y: &'static str,
    sigma: &'static str,
}

impl ProofEquality {
    fn check(self, proof: &VerkleProof) {
        let (D, y, sigma) = proof.components();

        assert_eq!(self.y, hex::encode(ark_ff::to_bytes!(y).unwrap()));
        assert_eq!(self.D, hex::encode(serialize_g1(&D.0)));
        assert_eq!(self.sigma, hex::encode(serialize_g1(&sigma.0)));
    }
}
