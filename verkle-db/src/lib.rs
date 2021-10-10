// TODO impl SqLite as a key value and make the database optional
// TODO One can also impl Sqlite in verkle repo and use tables

mod sled_impl;
pub use sled_impl::DB as SledDb;

mod rocksdb_impl;
pub use rocksdb_impl::DB as RocksDb;

// Bare metal database assumes the most basic functionality for a key value database
pub trait BareMetalKVDb {
    // Get the value stored at this key
    fn fetch(&self, key: &[u8]) -> Option<Vec<u8>>;

    // Create a database given the default path
    // This cannot be implemented here since Self is not sized.
    fn new() -> Self;
}

pub trait BareMetalDiskDb {
    fn from_path<P: AsRef<std::path::Path>>(path: P) -> Self;

    const DEFAULT_PATH: &'static str;
}

pub trait BatchWriter {
    fn new() -> Self;

    fn batch_put(&mut self, key: &[u8], val: &[u8]);
}

pub trait BatchDB {
    type BatchWrite: BatchWriter;

    fn flush(&mut self, batch: Self::BatchWrite);
}
