use ffi_interface::CommitmentBytes;
use jni::{objects::JByteArray, JNIEnv};
use std::convert::TryFrom;

pub fn parse_scalars<'a>(env: &'a JNIEnv<'a>, values: JByteArray<'a>) -> Result<Vec<u8>, String> {
    let input_elements = env
        .convert_byte_array(values)
        .map_err(|_| "cannot convert byte array to vector")?;

    if input_elements.len() % 32 != 0 {
        return Err("Wrong input size: should be a multiple of 32 bytes".to_string());
    };
    Ok(input_elements)
}

pub fn parse_indices<'a>(env: &JNIEnv, values: JByteArray<'a>) -> Result<Vec<usize>, String> {
    let input_elements = env
        .convert_byte_array(values)
        .map_err(|_| "could not convert byte array to vector".to_string())?;
    Ok(input_elements.into_iter().map(|x| x as usize).collect())
}

pub fn parse_commitment<'a>(
    env: &JNIEnv,
    commitment: JByteArray<'a>,
) -> Result<CommitmentBytes, String> {
    let commitment_bytes = env
        .convert_byte_array(commitment)
        .map_err(|_| "cannot convert byte vector to vector")?;

    let result: CommitmentBytes = CommitmentBytes::try_from(commitment_bytes)
        .map_err(|_| "Wrong commitment size: should be 64 bytes".to_string())?;
    Ok(result)
}

pub fn parse_commitments<'a>(
    env: &JNIEnv<'a>,
    commitment: JByteArray<'a>,
) -> Result<Vec<u8>, String> {
    let commitment_bytes = env
        .convert_byte_array(commitment)
        .map_err(|_| "cannot convert byte vector to vector")?;

    if commitment_bytes.len() % 64 != 0 {
        return Err("Wrong input size: should be a multiple of 64 bytes".to_string());
    };

    Ok(commitment_bytes)
}
