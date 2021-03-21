use crate::Key;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NodeError {
    #[error("cannot insert into a hashed node")]
    HashedNodeInsert,
    #[error("invalid child read")]
    InvalidChildRead,
    #[error("leaf node key mismatch")]
    LeafNodeKeyMismatch,
    #[error("node is not a branch node")]
    NotABranchNode,
    #[error("unexpected empty node")]
    UnexpectedEmptyNode,
    #[error("unexpected hash node")]
    UnexpectedHashNode,
    #[error("key path only contains branch nodes and no leaf/empty nodes")]
    BranchNodePath,
    #[error("key not found in trie, instead found {}", leaf_found.as_string())]
    WrongLeafNode { leaf_found: Key },
}
