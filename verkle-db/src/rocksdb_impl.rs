use crate::{BareMetalDiskDb, BareMetalKVDb};
pub use rocksdb::DB;

impl BareMetalDiskDb for DB {
    fn from_path<P: AsRef<std::path::Path>>(path: P) -> Self {
        // use rusty_leveldb::{CompressionType, Options};
        // let mut opt = Options::default();
        // opt.compression_type = CompressionType::CompressionSnappy;
        let db = DB::open_default(path).unwrap();
        db
    }

    const DEFAULT_PATH: &'static str = "./db/verkle_db";
}

impl BareMetalKVDb for DB {
    fn fetch(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get(key).unwrap()
    }
    // Create a database given the default path
    fn new() -> Self {
        Self::from_path(Self::DEFAULT_PATH)
    }
}

use crate::{BatchDB, BatchWriter};
use rocksdb::WriteBatch;

impl BatchWriter for WriteBatch {
    fn new() -> Self {
        WriteBatch::default()
    }

    fn batch_put(&mut self, key: &[u8], val: &[u8]) {
        self.put(key, val)
    }
}

impl BatchDB for DB {
    type BatchWrite = WriteBatch;

    fn flush(&mut self, batch: Self::BatchWrite) {
        self.write(batch).unwrap();
    }
}
