use crate::{ipa::slow_vartime_multiscalar_mul, lagrange_basis::LagrangeBasis};
use banderwagon::{try_reduce_to_element, Element};
use std::fs::File;
use banderwagon::CanonicalDeserialize;

#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct CRS {
    pub n: usize,
    pub G: Vec<Element>,
    pub Q: Element,
}

impl CRS {
    #[allow(non_snake_case)]
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
        use std::collections::HashSet;
        let mut map = HashSet::new();
        for point in points {
            let value_is_new = map.insert(point.to_bytes());
            assert!(value_is_new, "crs has duplicated points")
        }
    }
    pub fn commit_lagrange_poly(&self, polynomial: &LagrangeBasis) -> Element {
        slow_vartime_multiscalar_mul(polynomial.values().iter(), self.G.iter())
    }

    pub fn load_points_from_file(path: &str) -> CRS {
        let mut file = File::open(path).unwrap();
        let G: Vec<Element> = CanonicalDeserialize::deserialize_compressed(&mut file).unwrap();
        let Q = Element::prime_subgroup_generator();

        let n: usize = 256;
        CRS {n, G, Q}
    }
}

impl std::ops::Index<usize> for CRS {
    type Output = Element;

    fn index(&self, index: usize) -> &Self::Output {
        &self.G[index]
    }
}

fn generate_random_elements(num_required_points: usize, seed: &'static [u8]) -> Vec<Element> {
    use sha2::{Digest, Sha256};

    let _choose_largest = false;

    // Hash the seed + i to get a possible x value
    let hash_to_x = |index: u64| -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(index.to_be_bytes());
        let bytes: Vec<u8> = hasher.finalize().to_vec();
        bytes
    };

    (0u64..)
        .map(hash_to_x)
        .filter_map(|hash_bytes| try_reduce_to_element(&hash_bytes))
        .take(num_required_points)
        .collect()
}

#[test]
fn crs_consistency() {
    // TODO: update hackmd as we are now using banderwagon and the point finding strategy
    // TODO is a bit different
    // See: https://hackmd.io/1RcGSMQgT4uREaq1CCx_cg#Methodology

    use sha2::{Digest, Sha256};

    let points = generate_random_elements(256, b"eth_verkle_oct_2021");

    let bytes = points[0].to_bytes();
    assert_eq!(
        hex::encode(bytes),
        "01587ad1336675eb912550ec2a28eb8923b824b490dd2ba82e48f14590a298a0",
        "the first point is incorrect"
    );
    let bytes = points[255].to_bytes();
    assert_eq!(
        hex::encode(bytes),
        "3de2be346b539395b0c0de56a5ccca54a317f1b5c80107b0802af9a62276a4d8",
        "the 256th (last) point is incorrect"
    );

    let mut hasher = Sha256::new();
    for point in &points {
        let bytes = point.to_bytes();
        hasher.update(bytes);
    }
    let bytes = hasher.finalize().to_vec();
    assert_eq!(
        hex::encode(bytes),
        "1fcaea10bf24f750200e06fa473c76ff0468007291fa548e2d99f09ba9256fdb",
        "unexpected point encountered"
    );
}


#[test]
fn test_load_crs() {
    let CRS = CRS::load_points_from_file("./src/precomputed_points.bin");
}
