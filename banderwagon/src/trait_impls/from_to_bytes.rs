use ark_serialize::SerializationError;

pub trait ToBytes<T> {
    fn to_bytes(&self) -> Result<T, SerializationError>;
}

pub trait FromBytes<T> {
    fn from_bytes(bytes: T) -> Result<Self, SerializationError>
    where
        Self: Sized;
}
