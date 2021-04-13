use slotmap::{new_key_type, SlotMap};

use super::node::Node;

pub type DataIndex = NodeIndex;

impl NodeSlotMap {
    pub fn get(&self, index: &DataIndex) -> &Node {
        self.0.get(*index).unwrap()
    }

    pub fn get_mut(&mut self, index: DataIndex) -> &mut Node {
        self.0.get_mut(index).unwrap()
    }

    pub fn index(&mut self, node: Node) -> DataIndex {
        self.0.insert(node)
    }
}

// NodeIndex is used to refer to Nodes in the arena allocator.
// A better name might be DataIndex.
new_key_type! {pub struct NodeIndex;}

pub struct NodeSlotMap(slotmap::SlotMap<DataIndex, super::node::Node>);

impl NodeSlotMap {
    pub fn new() -> Self {
        let sm = SlotMap::with_key();
        NodeSlotMap(sm)
    }
}
