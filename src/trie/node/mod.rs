use crate::Value;

use self::{hashed::HashedNode, internal::InternalNode, leaf::LeafExtensionNode};

pub mod empty;
pub mod errors;
pub mod hashed;
pub mod internal;
pub mod leaf;
#[derive(Debug, Copy, Clone)]
pub enum Node {
    Internal(InternalNode),
    Hashed(HashedNode),
    LeafExt(LeafExtensionNode),
    Value(Value),
    Empty,
}

pub const EMPTY_NODE_TYPE: u8 = 0;
pub const LEAF_EXT_NODE_TYPE: u8 = 1;
pub const INTERNAL_NODE_TYPE: u8 = 2;
pub const HASHED_NODE_TYPE: u8 = 3;
pub const VALUE_NODE_TYPE: u8 = 4;

impl Node {
    pub const fn node_type(&self) -> u8 {
        match self {
            Node::Empty => EMPTY_NODE_TYPE,
            Node::LeafExt(_) => LEAF_EXT_NODE_TYPE,
            Node::Internal(_) => INTERNAL_NODE_TYPE,
            Node::Hashed(_) => HASHED_NODE_TYPE,
            Node::Value(_) => VALUE_NODE_TYPE,
        }
    }
}
impl Node {
    // XXX: Investigate a better way of doing the as conversions
    pub fn internal(self) -> InternalNode {
        if let Node::Internal(internal) = self {
            internal
        } else {
            panic!("not an internal node")
        }
    }
    pub fn as_internal(&self) -> &InternalNode {
        if let Node::Internal(internal) = self {
            internal
        } else {
            panic!("not an internal node")
        }
    }

    pub fn as_mut_internal(&mut self) -> &mut InternalNode {
        if let Node::Internal(internal) = self {
            internal
        } else {
            panic!("not an internal node")
        }
    }
    pub fn as_leaf_ext(&self) -> &LeafExtensionNode {
        if let Node::LeafExt(leaf) = self {
            leaf
        } else {
            panic!("not an internal node")
        }
    }
}

impl Default for Node {
    fn default() -> Node {
        Node::Empty
    }
}
