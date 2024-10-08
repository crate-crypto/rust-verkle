use c_eth_kzg::Error as KZGError;

#[derive(Debug)]
pub enum Error {
    Jni(jni::errors::Error),
    IncorrectSize {
        expected: usize,
        got: usize,
        name: &'static str,
    },
    Cryptography(KZGError),
}

impl From<jni::errors::Error> for Error {
    fn from(err: jni::errors::Error) -> Self {
        Error::Jni(err)
    }
}

impl From<KZGError> for Error {
    fn from(err: KZGError) -> Self {
        Error::Cryptography(err)
    }
}
