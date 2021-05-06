use std::collections::BTreeMap;

use slotmap::{new_key_type, SlotMap};

// ChildMap stores the relations for all of the InternalNode children in
// this map.
pub struct ChildMap {
    inner: BTreeMap<(ParentDataIndex, usize), ChildDataIndex>,
}

impl ChildMap {
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::default(),
        }
    }

    // XXX: We assume that all of the child_indices are within the correct range
    // We could store it in ChildMap Possibly, and return an Option
    //
    // XXX: We could possibly rename this to index_child, to distinguish between adding a node
    // into the slotmap and simply indexing it(adding a relation)
    pub fn add_child(
        &mut self,
        parent: ParentDataIndex,
        child_index: usize,
        child: ChildDataIndex,
    ) {
        // XXX: Check the child_index is in bound
        self.inner.insert((parent, child_index), child);
    }

    pub fn child(
        &self,
        parent: ParentDataIndex,
        child_node_index: usize,
    ) -> Option<ChildDataIndex> {
        self.inner.get(&(parent, child_node_index)).copied()
    }

    pub fn children(&self, parent: ParentDataIndex) -> Vec<(usize, ChildDataIndex)> {
        use std::ops::Bound::Included;
        let mut children = Vec::new();
        for ((_, path_bit), child_data_index) in self
            .inner
            .range((Included(&(parent, 0)), Included(&(parent, usize::MAX))))
        {
            children.push((*path_bit, *child_data_index))
        }
        children
    }
}
#[test]
fn example() {
    let mut map = NodeSlotMap::new();
    let a = map.index(Node::Empty);
    let b = map.index(Node::Empty);
    let c = map.index(Node::Empty);

    let internal_node = InternalNode::new();
    let i_node = map.index(Node::Internal(internal_node));
    let internal_node2 = InternalNode::new();
    let i_node2 = map.index(Node::Internal(internal_node2));

    let mut child_map = ChildMap {
        inner: BTreeMap::new(),
    };

    child_map.inner.insert((i_node, 0), a);
    child_map.inner.insert((i_node2, 0), c);
    child_map.inner.insert((i_node, 1), b);
    child_map.inner.insert((i_node2, 2), c);
    child_map.inner.insert((i_node, 2), c);

    use std::ops::Bound::Included;
    for x in child_map
        .inner
        .range((Included(&(i_node2, 0)), Included(&(i_node2, usize::MAX))))
    {
        println!("{:?}", x)
    }
}

use crate::trie::node::{internal::InternalNode, Node};

pub type ParentDataIndex = NodeIndex;
pub type ChildDataIndex = NodeIndex;
pub type DataIndex = NodeIndex;

impl NodeSlotMap {
    pub fn get(&self, index: DataIndex) -> Node {
        *self.0.get(index).unwrap()
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

pub struct NodeSlotMap(slotmap::SlotMap<DataIndex, crate::trie::node::Node>);

impl NodeSlotMap {
    pub fn new() -> Self {
        let sm = SlotMap::with_key();
        NodeSlotMap(sm)
    }
}
