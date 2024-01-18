pub mod committer;
pub mod crs;
mod default_crs;
pub mod ipa; // follows the BCMS20 scheme
pub mod math_utils;
pub mod multiproof;
pub mod transcript;

pub mod lagrange_basis;

// TODO: We use the IO Result while we do not have a dedicated Error enum
pub(crate) type IOResult<T> = std::io::Result<T>;
pub(crate) type IOError = std::io::Error;
pub(crate) type IOErrorKind = std::io::ErrorKind;
