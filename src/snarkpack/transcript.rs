use ark_ff::fields::Field;
use ark_serialize::{CanonicalSerialize, Compress};
use merlin::Transcript as Merlin;

/// must be specific to the application.
pub fn new_merlin_transcript(label: &'static [u8]) -> impl Transcript {
    Merlin::new(label)
}

/// Transcript is the application level transcript to derive the challenges
/// needed for Fiat Shamir during aggregation. It is given to the
/// prover/verifier so that the transcript can be fed with any other data first.
pub trait Transcript {
    fn domain_sep(&mut self);
    fn append<S: CanonicalSerialize>(&mut self, label: &'static [u8], point: &S);
    fn challenge_scalar<F: Field>(&mut self, label: &'static [u8]) -> F;
}

impl Transcript for Merlin {
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"groth16-aggregation-snarkpack");
    }

    fn append<S: CanonicalSerialize>(&mut self, label: &'static [u8], element: &S) {
        let mut buff: Vec<u8> = vec![0; element.serialized_size(Compress::Yes)];
        element
            .serialize_compressed(&mut buff)
            .expect("serialization failed");
        self.append_message(label, &buff);
    }

    fn challenge_scalar<F: Field>(&mut self, label: &'static [u8]) -> F {
        // Reduce a double-width scalar to ensure a uniform distribution
        let mut buf = [0; 64];
        self.challenge_bytes(label, &mut buf);
        let mut counter = 0;
        loop {
            match F::from_random_bytes(&buf) {
                Some(e) => {
                    if let Some(_) = e.inverse() {
                        return e;
                    } else {
                        continue;
                    }
                }
                None => {
                    buf[0] = counter;
                    counter += 1;
                    self.challenge_bytes(label, &mut buf);
                    continue;
                }
            }
        }
    }
}


