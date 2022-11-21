use ark_serialize::SerializationError;
use thiserror::Error;

// A Wrapper Type for all errors that can occur within the Verkle Library
// Provides Single Error Enum for consumers of the library to match against
// Right now there are lots of unwraps which are immediately switched to Results, but in the future
// We likely be moved back to unwraps with safety comments
#[derive(Error, Debug)]
pub enum VerkleError {
    #[error("Issue Occured Converting Type to Bytes")]
    SerializationError(#[from] SerializationError),
    #[error("Precomputed Points Exist Already")]
    PrecomputedPointsFileExists,
    #[error("Unable to Create Precomputed Points File")]
    CannotCreatePrecomputedPoints(std::io::Error),
    #[error("Precomputed Lagrage Points File Couldn't not be found")]
    PrecomputedPointsNotFound,
    #[error("Issue opening PrecomputedPointsFile")]
    FileError(std::io::Error),

    #[error("Invalid proof supplied")]
    InvalidProof,
    #[error("Invalid Length for Updated Values")]
    UnexpectedUpdatedLength,
    #[error("Mismatched Length of Supplied Keys from expected")]
    MismatchedKeyLength,
    #[error("All Keys must be unique")]
    DuplicateKeys,
    #[error("Since the extension was not present in the trie, the suffix cannot have any previous values")]
    OldValueIsPopulated,

    #[error("Prefix Cannot be Empty")]
    EmptyPrefix,

    #[error("Child Branch is Empty/Doesn't exist")]
    NoChildBranch,
    #[error("BranchMeta was not serialised properly")]
    BranchMetaSerializedFaulty(String),
} // TODO group erros by assosiation, and break out into sub error enums
