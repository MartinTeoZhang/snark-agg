
// msm::FixedBaseMSM;
use ark_ec::{pairing::Pairing};
// {AffineCurve, PairingEngine, ProjectiveCurve};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize,};


use std::clone::Clone;

use super::commitment::{VKey, WKey};

///
/// https://github.com/nikkolasg/taupipp/blob/baca1426266bf39416c45303e35c966d69f4f8b4/src/bin/assemble.rs#L12
pub const MAX_SRS_SIZE: usize = (2 << 19) + 1;


#[derive(Clone, Debug)]
pub struct GenericSRS<E: Pairing> {
    /// $\{g^a^i\}_{i=0}^{N}$ where N is the smallest size of the two Groth16 CRS.
    pub g_alpha_powers: Vec<E::G1Affine>,
    /// $\{h^a^i\}_{i=0}^{N}$ where N is the smallest size of the two Groth16 CRS.
    pub h_alpha_powers: Vec<E::G2Affine>,
    /// $\{g^b^i\}_{i=n}^{N}$ where N is the smallest size of the two Groth16 CRS.
    pub g_beta_powers: Vec<E::G1Affine>,
    /// $\{h^b^i\}_{i=0}^{N}$ where N is the smallest size of the two Groth16 CRS.
    pub h_beta_powers: Vec<E::G2Affine>,
}


#[derive(Clone, Debug)]
pub struct ProverSRS<E: Pairing> {
    /// number of proofs to aggregate
    pub n: usize,
    /// $\{g^a^i\}_{i=0}^{2n-1}$ where n is the number of proofs to be aggregated
    /// We take all powers instead of only ones from n -> 2n-1 (w commitment key
    /// is formed from these powers) since the prover will create a shifted
    /// polynomial of degree 2n-1 when doing the KZG opening proof.
    pub g_alpha_powers_table: Vec<E::G1Affine>,
    /// $\{h^a^i\}_{i=0}^{n-1}$ - here we don't need to go to 2n-1 since v
    /// commitment key only goes up to n-1 exponent.
    pub h_alpha_powers_table: Vec<E::G2Affine>,
    /// $\{g^b^i\}_{i=0}^{2n-1}$
    pub g_beta_powers_table: Vec<E::G1Affine>,
    /// $\{h^b^i\}_{i=0}^{n-1}$
    pub h_beta_powers_table: Vec<E::G2Affine>,
    /// commitment key using in MIPP and TIPP
    pub vkey: VKey<E>,
    /// commitment key using in TIPP
    pub wkey: WKey<E>,
}

/// Contains the necessary elements to verify an aggregated Groth16 proof; it is of fixed size
/// regardless of the number of proofs aggregated. However, a verifier SRS will be determined by
/// the number of proofs being aggregated.
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct VerifierSRS<E: Pairing> {
    pub n: usize,
    pub g: E::G1,
    pub h: E::G2,
    pub g_alpha: E::G1,
    pub g_beta: E::G1,
    pub h_alpha: E::G2,
    pub h_beta: E::G2,
}

impl<E: Pairing> PartialEq for GenericSRS<E> {
    fn eq(&self, other: &Self) -> bool {
        self.g_alpha_powers == other.g_alpha_powers
            && self.g_beta_powers == other.g_beta_powers
            && self.h_alpha_powers == other.h_alpha_powers
            && self.h_beta_powers == other.h_beta_powers
    }
}

impl<E: Pairing> PartialEq for VerifierSRS<E> {
    fn eq(&self, other: &Self) -> bool {
        self.g == other.g
            && self.h == other.h
            && self.g_alpha == other.g_alpha
            && self.g_beta == other.g_beta
            && self.h_alpha == other.h_alpha
            && self.h_beta == other.h_beta
    }
}

impl<E: Pairing> ProverSRS<E> {
    /// Returns true if commitment keys have the exact required length.
    /// It is necessary for the IPP scheme to work that commitment
    /// key have the exact same number of arguments as the number of proofs to
    /// aggregate.
    pub fn has_correct_len(&self, n: usize) -> bool {
        self.vkey.has_correct_len(n) && self.wkey.has_correct_len(n)
    }
}






