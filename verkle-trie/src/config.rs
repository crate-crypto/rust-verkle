use crate::committer::{precompute::PrecomputeLagrange, test::TestCommitter};
use crate::constants::CRS;
use ark_ec::ProjectiveCurve;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::fs::File;
/// Generic configuration file to initialise a verkle trie struct
#[derive(Debug, Clone)]
pub struct Config<Storage, PolyCommit> {
    pub db: Storage,
    pub committer: PolyCommit,
}

// We store the precomputed points in a binary file, as they take quite a long time
// to pre-compute. The means that in production, one will not need to recompute
// them. It is possible to use this for tests too, one should ensure that the file exists
// before running the tests; which are ran in parallel.
const PRECOMPUTED_POINTS_PATH: &'static str = "precomputed_points.bin";

// TODO: These two functions return Strings, when they should return a result with an enum variant ideally
// TODO: This is an API change and will be done in the API refactor phase.

pub type VerkleConfig<Storage> = Config<Storage, PrecomputeLagrange>;
impl<Storage> VerkleConfig<Storage> {
    pub fn new(db: Storage) -> Result<Self, &'static str> {
        let file_exists = std::path::Path::new(PRECOMPUTED_POINTS_PATH).exists();
        if file_exists {
            return Err(
                "file with precomputed points already exists. Please call the `open` method",
            );
        }

        // File is not already precomputed, so we pre-compute the points and store them
        let mut file = File::create(PRECOMPUTED_POINTS_PATH).unwrap();
        let g_aff: Vec<_> = CRS.G.iter().map(|point| point.into_affine()).collect();
        let committer = PrecomputeLagrange::precompute(&g_aff);
        committer.serialize(&mut file).unwrap();
        Ok(Config { db, committer })
    }

    pub fn open(db: Storage) -> Result<Self, &'static str> {
        let file_exists = std::path::Path::new(PRECOMPUTED_POINTS_PATH).exists();
        if !file_exists {
            return Err(
                "file with precomputed points does not exist. Please call the `new` method",
            );
        }
        let mut file = File::open(PRECOMPUTED_POINTS_PATH).unwrap();
        let committer: PrecomputeLagrange = CanonicalDeserialize::deserialize(&mut file).unwrap();
        return Ok(Config { db, committer });
    }
}

pub type TestConfig<Storage> = Config<Storage, TestCommitter>;
impl<Storage> TestConfig<Storage> {
    pub fn new(db: Storage) -> Self {
        let committer = TestCommitter;
        Config { db, committer }
    }
}
