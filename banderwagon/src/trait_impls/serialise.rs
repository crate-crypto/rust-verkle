use crate::Element;
use ark_ec::ProjectiveCurve;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use bandersnatch::EdwardsProjective;

impl CanonicalSerialize for Element {
    fn serialize<W: ark_serialize::Write>(
        &self,
        mut writer: W,
    ) -> Result<(), ark_serialize::SerializationError> {
        match writer.write(&self.to_bytes()) {
            Ok(_) => Ok(()),
            Err(err) => Err(SerializationError::IoError(err)),
        }
    }

    fn serialized_size(&self) -> usize {
        Element::compressed_serialised_size()
    }

    fn serialize_uncompressed<W: ark_serialize::Write>(
        &self,
        writer: W,
    ) -> Result<(), SerializationError> {
        // Convert point to affine and serialise affine format
        // This serialisation strategy is the same for both
        // banderwagon and bandersnatch -- Ignoring serialise Long
        self.0.into_affine().serialize_uncompressed(writer)
    }

    fn serialize_unchecked<W: ark_serialize::Write>(
        &self,
        writer: W,
    ) -> Result<(), SerializationError> {
        self.0.into_affine().serialize_unchecked(writer)
    }

    fn uncompressed_size(&self) -> usize {
        self.0.uncompressed_size()
    }
}

impl CanonicalDeserialize for Element {
    fn deserialize<R: ark_serialize::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let mut bytes = [0u8; Element::compressed_serialised_size()];
        if let Err(err) = reader.read_exact(&mut bytes) {
            return Err(SerializationError::IoError(err));
        }

        match Element::from_bytes(&bytes) {
            Some(element) => Ok(element),
            None => Err(SerializationError::InvalidData),
        }
    }

    fn deserialize_uncompressed<R: ark_serialize::Read>(
        reader: R,
    ) -> Result<Self, SerializationError> {
        let point = EdwardsProjective::deserialize_uncompressed(reader)?;
        Ok(Element(point))
    }

    fn deserialize_unchecked<R: ark_serialize::Read>(
        reader: R,
    ) -> Result<Self, SerializationError> {
        let point = EdwardsProjective::deserialize_unchecked(reader)?;
        Ok(Element(point))
    }
}
