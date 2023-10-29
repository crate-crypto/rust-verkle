use ark_serialize::CanonicalSerialize;
use banderwagon::Element;

use crate::{ipa::slow_vartime_multiscalar_mul, lagrange_basis::LagrangeBasis};

#[derive(Debug, Clone)]
pub struct CRS {
    pub n: usize,
    pub G: Vec<Element>,
    pub Q: Element,
}

impl CRS {
    pub fn new(n: usize, seed: &'static [u8]) -> CRS {
        // TODO generate the Q value from the seed also
        // TODO: this will also make assert_dedup work as expected
        // TODO: since we should take in `Q` too
        let G: Vec<_> = generate_random_elements(n, seed).into_iter().collect();
        let Q = Element::prime_subgroup_generator();

        CRS::assert_dedup(&G);

        CRS { n, G, Q }
    }
    // Asserts that not of the points generated are the same
    fn assert_dedup(points: &[Element]) {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        for point in points {
            assert!(
                map.insert(point.to_bytes(), ()).is_none(),
                "crs has duplicated points"
            )
        }
    }
    pub fn commit_lagrange_poly(&self, polynomial: &LagrangeBasis) -> Element {
        slow_vartime_multiscalar_mul(polynomial.values().iter(), self.G.iter())
    }
}

impl std::ops::Index<usize> for CRS {
    type Output = Element;

    fn index(&self, index: usize) -> &Self::Output {
        &self.G[index]
    }
}

fn generate_random_elements(num_required_points: usize, seed: &'static [u8]) -> Vec<Element> {
    use ark_ec::group::Group;
    use ark_ff::PrimeField;
    use bandersnatch::Fq;
    use sha2::{Digest, Sha256};

    let choose_largest = false;

    (0u64..)
        .into_iter()
        // Hash the seed + i to get a possible x value
        .map(|i| {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(&i.to_be_bytes());
            let bytes: Vec<u8> = hasher.finalize().to_vec();
            bytes
        })
        // The Element::from_bytes method does not reduce the bytes, it expects the
        // input to be in a canonical format, so we must do the reduction ourselves
        .map(|hash_bytes| Fq::from_be_bytes_mod_order(&hash_bytes))
        .map(|x_coord| {
            let mut bytes = [0u8; 32];
            x_coord.serialize(&mut bytes[..]).unwrap();
            // TODO: this reverse is hacky, and its because there is no way to specify the endianness in arkworks
            // TODO So we reverse it here, to be interopable with the banderwagon specs which needs big endian bytes
            bytes.reverse();
            bytes
        })
        // Deserialise the x-cordinate to get a valid banderwagon element
        .map(|bytes| Element::from_bytes(&bytes))
        .filter_map(|point| point)
        .take(num_required_points)
        .collect()
}

#[test]
fn crs_consistency() {
    // TODO: update hackmd as we are now using banderwagon and the point finding strategy
    // TODO is a bit different
    // See: https://hackmd.io/1RcGSMQgT4uREaq1CCx_cg#Methodology
    use ark_serialize::CanonicalSerialize;
    use bandersnatch::Fq;
    use sha2::{Digest, Sha256};

    let points = generate_random_elements(256, b"eth_verkle_oct_2021");

    let mut bytes = [0u8; 32];
    points[0].serialize(&mut bytes[..]).unwrap();
    assert_eq!(
        hex::encode(&bytes),
        "01587ad1336675eb912550ec2a28eb8923b824b490dd2ba82e48f14590a298a0",
        "the first point is incorrect"
    );
    let mut bytes = [0u8; 32];
    points[255].serialize(&mut bytes[..]).unwrap();
    assert_eq!(
        hex::encode(&bytes),
        "3de2be346b539395b0c0de56a5ccca54a317f1b5c80107b0802af9a62276a4d8",
        "the 256th (last) point is incorrect"
    );

    let mut hasher = Sha256::new();
    for point in &points {
        let mut bytes = [0u8; 32];
        point.serialize(&mut bytes[..]).unwrap();
        hasher.update(&bytes);
    }
    let bytes = hasher.finalize().to_vec();
    assert_eq!(
        hex::encode(&bytes),
        "1fcaea10bf24f750200e06fa473c76ff0468007291fa548e2d99f09ba9256fdb",
        "unexpected point encountered"
    );
}
