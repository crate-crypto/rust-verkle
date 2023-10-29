use ark_ff::PrimeField;
use banderwagon::{Element, Fr};
pub trait TranscriptProtocol {
    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Fr;
    fn append_point(&mut self, label: &'static [u8], point: &Element);
    fn append_scalar(&mut self, label: &'static [u8], point: &Fr);
    fn domain_sep(&mut self, label: &'static [u8]);
}

use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
pub struct Transcript {
    state: Sha256,
}

impl Transcript {
    pub fn new(label: &'static [u8]) -> Transcript {
        let mut state = Sha256::new();
        state.update(label);
        Transcript { state }
    }

    fn append_message(&mut self, message: &[u8], label: &'static [u8]) {
        self.state.update(label);
        self.state.update(message);
    }
    // TODO: Add this to the other implementations! or most likely, we just need to add
    // TODO sub protocol specific domain separators ipa_domain_sep(n) and under the roof
    // TODO it adds the ipa label and the argument size n
    pub fn append_u64(&mut self, label: &'static [u8], number: u64) {
        self.state.update(label);
        self.state.update(number.to_be_bytes());
    }
}

impl TranscriptProtocol for Transcript {
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Fr {
        self.domain_sep(label);

        let hash: Vec<u8> = self.state.finalize_reset().to_vec();

        let scalar = Fr::from_le_bytes_mod_order(&hash);

        self.append_scalar(label, &scalar);

        scalar
    }

    fn append_point(&mut self, label: &'static [u8], point: &Element) {
        let mut bytes = [0u8; 32];
        point.serialize(&mut bytes[..]).unwrap();
        self.append_message(&bytes, label)
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &Fr) {
        let mut bytes = [0u8; 32];
        scalar.serialize(&mut bytes[..]).unwrap();
        self.append_message(&bytes, label)
    }

    fn domain_sep(&mut self, label: &'static [u8]) {
        self.state.update(label)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vector_0() {
        let mut tr = Transcript::new(b"simple_protocol");
        let first_challenge = tr.challenge_scalar(b"simple_challenge");
        let second_challenge = tr.challenge_scalar(b"simple_challenge");
        // We can never even accidentally, generate the same challenge
        assert_ne!(first_challenge, second_challenge)
    }
    #[test]
    fn test_vector_1() {
        let mut tr = Transcript::new(b"simple_protocol");
        let first_challenge = tr.challenge_scalar(b"simple_challenge");

        let expected = "c2aa02607cbdf5595f00ee0dd94a2bbff0bed6a2bf8452ada9011eadb538d003";

        let got = scalar_to_hex(&first_challenge);
        assert_eq!(got, expected)
    }
    #[test]
    fn test_vector_2() {
        let mut tr = Transcript::new(b"simple_protocol");
        let five = Fr::from(5 as u128);

        tr.append_scalar(b"five", &five);
        tr.append_scalar(b"five again", &five);

        let challenge = tr.challenge_scalar(b"simple_challenge");

        let expected = "498732b694a8ae1622d4a9347535be589e4aee6999ffc0181d13fe9e4d037b0b";

        let got = scalar_to_hex(&challenge);
        assert_eq!(got, expected)
    }
    #[test]
    fn test_vector_3() {
        let mut tr = Transcript::new(b"simple_protocol");
        let one = Fr::from(1 as u128);
        let minus_one = -one;

        tr.append_scalar(b"-1", &minus_one);
        tr.domain_sep(b"separate me");
        tr.append_scalar(b"-1 again", &minus_one);
        tr.domain_sep(b"separate me again");
        tr.append_scalar(b"now 1", &one);

        let challenge = tr.challenge_scalar(b"simple_challenge");

        let expected = "14f59938e9e9b1389e74311a464f45d3d88d8ac96adf1c1129ac466de088d618";

        let got = scalar_to_hex(&challenge);
        assert_eq!(got, expected)
    }
    #[test]
    fn test_vector_4() {
        use ark_ec::ProjectiveCurve;
        let mut tr = Transcript::new(b"simple_protocol");
        let generator = Element::prime_subgroup_generator();

        tr.append_point(b"generator", &generator);

        let challenge = tr.challenge_scalar(b"simple_challenge");

        let expected = "8c2dafe7c0aabfa9ed542bb2cbf0568399ae794fc44fdfd7dff6cc0e6144921c";

        let got = scalar_to_hex(&challenge);
        assert_eq!(got, expected)
    }

    fn scalar_to_hex(s: &Fr) -> String {
        let mut bytes = [0u8; 32];
        s.serialize(&mut bytes[..]).unwrap();
        hex::encode(bytes)
    }
}
