use crate::{BareMetalDiskDb, BareMetalKVDb};
pub use sled::Db as DB;

impl BareMetalDiskDb for sled::Db {
    fn from_path<P: AsRef<std::path::Path>>(path: P) -> Self {
        let _config = sled::Config::default().path(path);
        _config.open().unwrap()
    }

    const DEFAULT_PATH: &'static str = "./db/verkle_db";
}

impl BareMetalKVDb for sled::Db {
    fn fetch(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get(key).unwrap().map(|i_vec| i_vec.to_vec())
    }
    // Create a database given the default path
    fn new() -> Self {
        Self::from_path(Self::DEFAULT_PATH)
    }
}
