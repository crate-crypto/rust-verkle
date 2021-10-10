// XXX: We can remove this method, since width is fixed to 8
// pub fn bit_extraction(bytes: &[u8]) -> Vec<u8> {
//     bytes.to_vec()
// }

// Remove duplicate code below and move into trie module
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Key(ByteArr);

impl Key {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    // XXX: Lets add a test for this incase the key is ever changed
    pub const fn size_in_bits() -> usize {
        256
    }
    // Returns the maximum number of paths that a given
    // key and width will produce.
    // 256 bits with a width of 10 will produce 26
    // 256 bits with a width of 8 will produce 32
    pub fn max_num_paths(width: usize) -> usize {
        let key_size = Key::size_in_bits();
        (key_size / width) + (key_size % width != 0) as usize
    }
    pub fn as_string(&self) -> String {
        self.0.as_string()
    }
    pub const fn from_arr(arr: [u8; 32]) -> Key {
        Key(ByteArr(arr))
    }
    pub const fn zero() -> Key {
        Key(ByteArr::zero())
    }
    pub const fn one() -> Key {
        Key(ByteArr::one())
    }
    pub const fn max() -> Key {
        Key(ByteArr::max())
    }

    pub fn path_indices(&self) -> impl Iterator<Item = u8> + '_ {
        let bytes = self.as_bytes();
        bytes.to_vec().into_iter()
    }

    // Returns a list of all of the path indices where the two stems
    // are the same and the next path index where they both differ for each
    // key.
    // XXX: Clean up
    pub fn path_difference(key_a: [u8; 31], key_b: [u8; 31]) -> (Vec<u8>, Option<u8>, Option<u8>) {
        const AVERAGE_NUMBER_OF_SHARED_INDICES: usize = 3;

        let path_indice_a = &key_a;
        let path_indice_b = &key_b;

        let mut same_path_indices = Vec::with_capacity(AVERAGE_NUMBER_OF_SHARED_INDICES);

        for (p_a, p_b) in path_indice_a.into_iter().zip(path_indice_b) {
            if p_a != p_b {
                return (same_path_indices, Some(*p_a), Some(*p_b));
            }
            same_path_indices.push(*p_a)
        }

        (same_path_indices, None, None)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Value(ByteArr);

impl Value {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub const fn from_arr(arr: [u8; 32]) -> Value {
        Value(ByteArr(arr))
    }
    pub const fn zero() -> Value {
        Value(ByteArr::zero())
    }
    pub const fn one() -> Value {
        Value(ByteArr::one())
    }
    pub const fn max() -> Value {
        Value(ByteArr::max())
    }
}
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct ByteArr(pub [u8; 32]);

impl ByteArr {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn as_string(&self) -> String {
        hex::encode(self.0)
    }

    pub const fn zero() -> ByteArr {
        ByteArr([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
    }
    pub const fn one() -> ByteArr {
        ByteArr([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
    }
    pub const fn max() -> ByteArr {
        ByteArr([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ])
    }
}

#[test]
fn basic() {
    let a = [0u8; 31];
    let b = [
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    dbg!(Key::path_difference(a, b));
}
