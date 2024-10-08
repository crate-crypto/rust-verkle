use banderwagon::{CanonicalDeserialize, Element, Fr};
use jni::sys::{jbyteArray, jobjectArray};
use jni::JNIEnv;
use std::collections::BTreeSet;
use verkle_trie::proof::ExtPresent;

/// Converts a 32-byte array into an `Element` object.
///
/// This function attempts to convert a fixed-size byte array into an `Element`.
/// returns `Some(Element)`. Otherwise, it returns `None`.
///
/// # Arguments
///
/// * `bytes` - A 32-byte array representing the binary representation of an `Element`.
///
/// # Returns
///
/// An `Option<Element>` which is `Some` if the conversion is successful, otherwise `None`.
pub fn bytes32_to_element(bytes: [u8; 32]) -> Option<Element> {
    Element::from_bytes(&bytes)
}

/// Converts a 32-byte array into a scalar value `Fr`.
///
/// This function reverses the byte array and attempts to deserialize it into a scalar
/// value of type `Fr`, which is used in cryptographic operations. The deserialization
/// uses a compressed format. If successful, it returns `Some(Fr)`. Otherwise, it returns `None`.
///
/// # Arguments
///
/// * `bytes` - A 32-byte array representing the binary representation of a scalar value.
///
/// # Returns
///
/// An `Option<Fr>` which is `Some` if the deserialization is successful, otherwise `None`.
pub fn bytes32_to_scalar(bytes: [u8; 32]) -> Option<Fr> {
    let mut bytes = bytes;
    bytes.reverse();
    CanonicalDeserialize::deserialize_compressed(&bytes[..]).ok()
}

/// Extracts extension presence and depth information from a byte.
///
/// This function interprets the lower 3 bits of the input byte as the extension
/// presence status and the remaining higher bits as the depth. It returns a tuple
/// containing the `ExtPresent` status and the depth as an `u8`.
///
/// # Arguments
///
/// * `value` - A byte containing encoded extension presence and depth information.
///
/// # Returns
///
/// A tuple `(ExtPresent, u8)` where the first element represents the extension presence
/// status and the second element represents the depth.
pub fn byte_to_depth_extension_present(value: u8) -> (ExtPresent, u8) {
    let ext_status = value & 3;
    let ext_status = match ext_status {
        0 => ExtPresent::None,
        1 => ExtPresent::DifferentStem,
        2 => ExtPresent::Present,
        _ => return (ExtPresent::None, 0), // Handle unexpected value gracefully
    };
    let depth = value >> 3;
    (ext_status, depth)
}

/// Converts a `jobjectArray` into a `Vec<T>` by applying a conversion function to each element.
///
/// This function iterates over each element of the input `jobjectArray`, applies a conversion
/// function to convert each element into type `T`, and collects the results into a `Vec<T>`.
/// If any conversion fails, it returns `None`.
///
/// # Type Parameters
///
/// * `T` - The target type to which the byte arrays are converted.
/// * `F` - The type of the conversion function.
///
/// # Arguments
///
/// * `env` - The JNI environment.
/// * `array` - The input `jobjectArray` containing the elements to be converted.
/// * `converter` - A function that converts a `[u8; 32]` array into `Option<T>`.
///
/// # Returns
///
/// An `Option<Vec<T>>` which is `Some` containing the converted elements if all conversions
/// are successful, otherwise `None`.
pub fn jobjectarray_to_vec<T, F>(
    env: &JNIEnv,
    array: jobjectArray,
    mut converter: F,
) -> Option<Vec<T>>
where
    F: FnMut([u8; 32]) -> Option<T>,
{
    let length = env.get_array_length(array).ok()? as i32;
    let mut result = Vec::with_capacity(length as usize);
    for i in 0..length {
        let array_element = get_array(env, array, i)?;
        if let Some(converted) = converter(array_element) {
            result.push(converted);
        } else {
            return None; // Return None if conversion fails
        }
    }
    Some(result)
}

/// Converts a `jbyteArray` into a fixed-size `[u8; 32]` array.
///
/// This function attempts to convert a JNI `jbyteArray` into a Rust fixed-size byte array.
/// If the conversion is successful and the size is exactly 32 bytes, it returns `Some([u8; 32])`.
/// Otherwise, it returns `None`.
///
/// # Arguments
///
/// * `env` - The JNI environment.
/// * `byte_array` - The input `jbyteArray` to be converted.
///
/// # Returns
///
/// An `Option<[u8; 32]>` which is `Some` containing the converted byte array if successful,
/// otherwise `None`.
pub fn convert_byte_array_to_fixed_array(env: &JNIEnv, byte_array: jbyteArray) -> Option<[u8; 32]> {
    let bytes = env.convert_byte_array(byte_array).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Retrieves a fixed-size `[u8; 32]` array from a `jobjectArray` at a specified index.
///
/// This function attempts to extract a byte array from a given index within a `jobjectArray`,
/// convert it into a `[u8; 32]` array, and return it. If the operation fails or the size
/// does not match, it returns `None`.
///
/// # Arguments
///
/// * `env` - The JNI environment.
/// * `array` - The `jobjectArray` from which to retrieve the byte array.
/// * `index` - The index within the array from which to retrieve the byte array.
///
/// # Returns
///
/// An `Option<[u8; 32]>` which is `Some` containing the byte array if successful, otherwise `None`.
pub fn get_array(env: &JNIEnv, array: jobjectArray, index: i32) -> Option<[u8; 32]> {
    let obj = env.get_object_array_element(array, index).ok()?;
    let bytes = env.convert_byte_array(obj.into_inner()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Retrieves an optional fixed-size `[u8; 32]` array from a `jobjectArray` at a specified index.
///
/// Similar to `get_array`, but allows for `null` elements within the `jobjectArray`, representing
/// them as `None` in the resulting `Option<Option<[u8; 32]>>`. This is useful for arrays that
/// may contain optional elements.
///
/// # Arguments
///
/// * `env` - The JNI environment.
/// * `array` - The `jobjectArray` from which to retrieve the optional byte array.
/// * `index` - The index within the array from which to retrieve the byte array.
///
/// # Returns
///
/// An `Option<Option<[u8; 32]>>` which is `Some(None)` if the element is `null`, `Some(Some([u8; 32]))`
/// if the element is successfully converted, or `None` if the operation fails.
pub fn get_optional_array(
    env: &JNIEnv,
    array: jobjectArray,
    index: i32,
) -> Option<Option<[u8; 32]>> {
    let obj_result = env.get_object_array_element(array, index).ok()?;
    if obj_result.is_null() {
        return Some(None);
    }
    let bytes_result = env.convert_byte_array(obj_result.into_inner()).ok()?;
    if bytes_result.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes_result);
        Some(Some(arr))
    } else {
        Some(None)
    }
}

/// Converts a `jobjectArray` into a `BTreeSet<[u8; 31]>`.
///
/// This function iterates over each element of the input `jobjectArray`, attempts to convert
/// each element into a `[u8; 31]` array, and inserts the result into a `BTreeSet`. If any
/// conversion fails or if the size does not match, it returns `None`.
///
/// # Arguments
///
/// * `env` - The JNI environment.
/// * `array` - The `jobjectArray` containing the elements to be converted.
///
/// # Returns
///
/// An `Option<BTreeSet<[u8; 31]>>` which is `Some` containing the converted elements as a set
/// if all conversions are successful, otherwise `None`.
pub fn convert_to_btree_set(env: &JNIEnv, array: jobjectArray) -> Option<BTreeSet<[u8; 31]>> {
    let num_element = env.get_array_length(array).ok()? as i32;
    let mut set = BTreeSet::new();
    for i in 0..num_element {
        let array_obj = env.get_object_array_element(array, i).ok()?;
        let array_bytes = env.convert_byte_array(array_obj.into_inner()).ok()?;
        if array_bytes.len() != 31 {
            return None;
        }
        let mut arr = [0u8; 31];
        arr.copy_from_slice(&array_bytes);
        set.insert(arr);
    }
    Some(set)
}
