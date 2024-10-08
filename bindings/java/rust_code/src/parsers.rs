use jni::objects::ReleaseMode;
use jni::sys::jbyteArray;
use jni::JNIEnv;

use std::convert::TryFrom;

use ffi_interface::CommitmentBytes;

pub fn parse_scalars<'a>(env: &'a JNIEnv<'a>, values: jbyteArray) -> Result<&'a [u8], String> {
    let input_len = env
        .get_array_length(values)
        .map_err(|_| "Cannot get array lenght".to_string())? as usize;
    if input_len % 32 != 0 {
        return Err("Wrong input size: should be a mulitple of 32 bytes".to_string());
    };
    let input_elements = env
        .get_primitive_array_critical(values, ReleaseMode::NoCopyBack)
        .map_err(|_| "Cannot get array elements".to_string())?;
    let input_slice =
        unsafe { std::slice::from_raw_parts(input_elements.as_ptr() as *const u8, input_len) };
    Ok(input_slice)
}

pub fn parse_indices(env: &JNIEnv, values: jbyteArray) -> Result<Vec<usize>, String> {
    let input_len = env
        .get_array_length(values)
        .map_err(|_| "Cannot get array lenght".to_string())? as usize;
    let input_elements = env
        .get_primitive_array_critical(values, ReleaseMode::NoCopyBack)
        .map_err(|_| "Cannot get array elements".to_string())?;
    let input_slice =
        unsafe { std::slice::from_raw_parts(input_elements.as_ptr() as *const u8, input_len) };
    let result: Vec<usize> = input_slice.iter().map(|&x| x as usize).collect();
    Ok(result)
}

pub fn parse_commitment(env: &JNIEnv, commitment: jbyteArray) -> Result<CommitmentBytes, String> {
    let input_len = env
        .get_array_length(commitment)
        .map_err(|_| "Cannot get commitment lenght".to_string())? as usize;
    let input_elements = env
        .get_primitive_array_critical(commitment, ReleaseMode::NoCopyBack)
        .map_err(|_| "Cannot get array elements".to_string())?;
    let input_slice =
        unsafe { std::slice::from_raw_parts(input_elements.as_ptr() as *const u8, input_len) };
    let result: CommitmentBytes = CommitmentBytes::try_from(input_slice)
        .map_err(|_| "Wrong commitment size: should be 64 bytes".to_string())?;
    Ok(result)
}

pub fn parse_commitments<'a>(
    env: &'a JNIEnv<'a>,
    commitment: jbyteArray,
) -> Result<&'a [u8], String> {
    let input_len = env
        .get_array_length(commitment)
        .map_err(|_| "Cannot get commitment lenght".to_string())? as usize;
    if input_len % 64 != 0 {
        return Err("Wrong input size: should be a mulitple of 64 bytes".to_string());
    };
    let input_elements = env
        .get_primitive_array_critical(commitment, ReleaseMode::NoCopyBack)
        .map_err(|_| "Cannot get array elements".to_string())?;
    let input_slice =
        unsafe { std::slice::from_raw_parts(input_elements.as_ptr() as *const u8, input_len) };
    Ok(input_slice)
}
