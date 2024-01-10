use banderwagon::trait_defs::*;
use thiserror::Error;

// Right now there are lots of unwraps which are immediately switched to Results, but in the future
// We likely be moved back to unwraps with safety comments

#[derive(Debug, Error)]
pub enum HintError {
    #[error("General IO Error")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Invalid proof supplied")]
    InvalidProof,
    #[error("Invalid Length for Updated Values")]
    UnexpectedUpdatedLength(usize, usize),
    #[error("Mismatched Length of Supplied Keys from expected")]
    MismatchedKeyLength,
    #[error("All Keys must be unique")]
    DuplicateKeys,
    #[error("Since the extension was not present in the trie, the suffix cannot have any previous values")]
    OldValueIsPopulated,
    #[error("Prefix Cannot be Empty")]
    EmptyPrefix,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Precomputed Points Exist Already")]
    PrecomputedPointsFileExists,
    #[error("Issue opening PrecomputedPointsFile")]
    FileError(std::io::Error),
    #[error("Precomputed Lagrange Points File Couldn't not be found")]
    PrecomputedPointsNotFound,
    #[error("Serialization Either Failed or Data is Invalid")]
    SerializationError(#[from] SerializationError),
}

#[derive(Debug, Error)]
pub enum ProofCreationError {
    #[error("Empty Key Set")]
    EmptyKeySet,
    #[error("Expected to have atleast one query, which will be against the root")]
    ExpectedOneQueryAgainstRoot,
}
