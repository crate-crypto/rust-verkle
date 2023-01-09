use crate::{
    committer::{precompute::PrecomputeLagrange, test::TestCommitter},
    constants::CRS,
    errors::ConfigError,
};
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
const PRECOMPUTED_POINTS_PATH: &str = "precomputed_points.bin";

pub type VerkleConfig<Storage> = Config<Storage, PrecomputeLagrange>;

impl<Storage> VerkleConfig<Storage> {
    pub fn new(db: Storage) -> Result<Self, ConfigError> {
        let file_exists = std::path::Path::new(PRECOMPUTED_POINTS_PATH).exists();

        if file_exists {
            return Err(ConfigError::PrecomputedPointsFileExists);
        }

        // File is not already precomputed, so we pre-compute the points and store them
        let mut file = match File::create(PRECOMPUTED_POINTS_PATH) {
            Ok(v) => v,
            Err(e) => return Err(ConfigError::FileError(e)),
        };

        let committer = PrecomputeLagrange::precompute(&CRS.G);
        let serialization_result = committer.serialize_unchecked(&mut file);
        if let Err(e) = serialization_result {
            return Err(ConfigError::SerializationError(e));
        }

        Ok(Config { db, committer })
    }

    pub fn open(db: Storage) -> Result<Self, ConfigError> {
        let file_exists = std::path::Path::new(PRECOMPUTED_POINTS_PATH).exists();
        if !file_exists {
            return Err(ConfigError::PrecomputedPointsNotFound);
        }
        let mut file = match File::create(PRECOMPUTED_POINTS_PATH) {
            Ok(v) => v,
            Err(e) => return Err(ConfigError::FileError(e)),
        };

        let committer: PrecomputeLagrange =
            match CanonicalDeserialize::deserialize_unchecked(&mut file) {
                Ok(v) => v,
                Err(e) => return Err(ConfigError::SerializationError(e)),
            };

        Ok(Config { db, committer })
    }
}

pub type TestConfig<Storage> = Config<Storage, TestCommitter>;
impl<Storage> TestConfig<Storage> {
    pub fn new(db: Storage) -> Self {
        let committer = TestCommitter;
        Config { db, committer }
    }
}
