#[macro_use]
mod macros;

mod commitment;
mod errors;
mod ip;
mod pairing_check;
pub mod proof;
mod prover;
pub mod srs;
pub mod transcript;
mod verifier;

pub use errors::*;
pub use verifier::*;


use ark_ff::Field;

/// Returns the vector used for the linear combination fo the inner pairing product
/// between A and B for the Groth16 aggregation: A^r * B. It is required as it
/// is not enough to simply prove the ipp of A*B, we need a random linear
/// combination of those.
pub(crate) fn structured_scalar_power<F: Field>(num: usize, s: &F) -> Vec<F> {
    let mut powers = vec![F::one()];
    for i in 1..num {
        powers.push(powers[i - 1] * s);
    }
    powers
}

