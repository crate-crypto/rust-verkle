use crate::trie::indexer::DataIndex;

// XXX: This can be placed in a internal submodule

#[derive(Debug, Clone)]
pub struct Children {
    inner: Vec<Option<DataIndex>>,
    // XXX: try Vec<Option<I>> and HashMap<usize, I>
}
impl Children {
    // XXX: Maybe change index to be of type `VerkleIndex` or `PathIndex`
    pub fn get_child(&self, index: usize) -> &Option<DataIndex> {
        self.inner.get(index).unwrap()
    }
    pub fn iter(&self) -> impl Iterator<Item = &Option<DataIndex>> {
        self.inner.iter()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Children {
    pub fn new(num_children: usize) -> Children {
        Children {
            inner: vec![None; num_children],
        }
    }

    pub fn replace_child(&mut self, index: usize, new_data_index: DataIndex) {
        self.inner[index] = Some(new_data_index);
    }
}

impl IntoIterator for Children {
    type Item = Option<DataIndex>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}
