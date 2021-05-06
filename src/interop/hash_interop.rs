use ark_bls12_381::{G1Affine, G2Affine};
use ark_ec::AffineCurve;
use ark_ff::Fp384;
use ark_ff::FromBytes;
use ark_serialize::{
    CanonicalDeserializeWithFlags, CanonicalSerialize, CanonicalSerializeWithFlags, EmptyFlags,
    Flags, SWFlags,
};

// XXX: The below code can be cleaned up possibly by:
// - using const generics for the array size
// - being generic over the Field element. Fq for G1 and Fq2 for G2
// We need to be generic over CanonicalSerializeWithFlags so that
// EmptyFlag is used instead of SWFlag
fn serialize_g2_x(p: &G2Affine) -> [u8; 96] {
    let mut result = [0u8; 96];
    p.x.serialize_with_flags(&mut result[..], EmptyFlags)
        .unwrap();
    result.reverse();
    result
}
fn serialize_g1_x(p: &G1Affine) -> [u8; 48] {
    let mut result = [0u8; 48];
    p.x.serialize_with_flags(&mut result[..], EmptyFlags)
        .unwrap();
    result.reverse();
    result
}
pub fn deserialize_g1(mut bytes: [u8; 48]) -> G1Affine {
    let is_inf = (bytes[0] >> 6) & 1 == 1;
    if is_inf {
        return G1Affine::default();
    }
    let positive_y = (bytes[0] >> 5) & 1 == 1;

    // Remove the zcash bls encodings
    let mask = 255 >> 3;
    bytes[0] = bytes[0] & mask;

    // Put back the SWFlags encoding that arkworks recognises
    let flag = SWFlags::from_y_sign(positive_y);
    bytes[0] = bytes[0] | flag.u8_bitmask();

    // reverse array as the arkworks endian is little
    bytes.reverse();

    let x = Fp384::read(&bytes[..]).unwrap();

    G1Affine::get_point_from_x(x, positive_y).unwrap()
}

fn add_encoding(result: &mut [u8], is_inf: bool, positive_y: bool) {
    // add compression flag
    result[0] |= 1 << 7;

    if is_inf {
        result[0] |= 1 << 6;
        return;
    }

    if positive_y {
        result[0] |= 1 << 5;
        return;
    }
}

pub fn serialize_g1(p: &G1Affine) -> [u8; 48] {
    let mut result = serialize_g1_x(p);
    add_encoding(&mut result[..], p.infinity, p.y > -p.y);
    result
}
pub fn serialize_g2(p: &G2Affine) -> [u8; 96] {
    let mut result = serialize_g2_x(p);
    add_encoding(&mut result[..], p.infinity, p.y > -p.y);
    result
}

#[test]
fn test_correct_g1() {
    let p = G1Affine::prime_subgroup_generator();
    let enc = serialize_g1(&p);
    assert_eq!(hex::encode(enc), "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
    assert_eq!(hex::encode(serialize_g1(&G1Affine::default())), "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
}
#[test]
fn test_serialize_deserialize() {
    let p = G1Affine::prime_subgroup_generator();
    let got = deserialize_g1(serialize_g1(&p));

    assert_eq!(got, p)
}

#[test]
fn test_correct_g2() {
    let p = G2Affine::prime_subgroup_generator();
    assert_eq!(hex::encode(serialize_g2(&p)), "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8");
    assert_eq!(hex::encode(serialize_g2(&G2Affine::default())), "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
}
