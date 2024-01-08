use crate::Element;
use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::EdwardsProjective;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid};
impl CanonicalSerialize for Element {
    fn serialize_with_mode<W: std::io::prelude::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        match compress {
            ark_serialize::Compress::Yes => {
                writer.write_all(&self.to_bytes())?;
                Ok(())
            }
            ark_serialize::Compress::No => self.0.into_affine().serialize_uncompressed(writer),
        }
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        match compress {
            ark_serialize::Compress::Yes => Element::compressed_serialized_size(),
            ark_serialize::Compress::No => self.0.uncompressed_size(),
        }
    }
}

impl Valid for Element {
    // TODO: Arkworks has split up validation from serialization
    // TODO Element doesnt currently work like this though
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for Element {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        fn deserialize_with_no_validation<R: std::io::prelude::Read>(
            mut reader: R,
            compress: ark_serialize::Compress,
        ) -> Result<Element, SerializationError> {
            match compress {
                ark_serialize::Compress::Yes => {
                    let mut bytes = [0u8; Element::compressed_serialized_size()];
                    if let Err(err) = reader.read_exact(&mut bytes) {
                        return Err(SerializationError::IoError(err));
                    }

                    match Element::from_bytes(&bytes) {
                        Some(element) => Ok(element),
                        None => Err(SerializationError::InvalidData),
                    }
                }
                ark_serialize::Compress::No => {
                    let point = EdwardsProjective::deserialize_uncompressed(reader)?;
                    Ok(Element(point))
                }
            }
        }

        match validate {
            ark_serialize::Validate::Yes => deserialize_with_no_validation(reader, compress),
            ark_serialize::Validate::No => deserialize_with_no_validation(reader, compress),
        }
    }
}
