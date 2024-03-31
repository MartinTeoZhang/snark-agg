// use crate::ip;
// use crate::Error;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::CyclotomicMultSubgroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    fmt::Debug,
    ops::{AddAssign, MulAssign},
    vec::Vec,
};

use super::{
    ip,
    Error
};
use rayon::prelude::*;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Key<G: AffineRepr> {
    /// Exponent is a
    pub a: Vec<G>,
    /// Exponent is b
    pub b: Vec<G>,
}


pub type VKey<E> = Key<<E as Pairing>::G2Affine>;


pub type WKey<E> = Key<<E as Pairing>::G1Affine>;

impl<G> Key<G>
where
    G: AffineRepr,
{

    pub fn has_correct_len(&self, n: usize) -> bool {
        self.a.len() == n && self.b.len() == n
    }


    pub fn scale(&self, s_vec: &[G::ScalarField]) -> Result<Self, Error> {
        if self.a.len() != s_vec.len() {
            return Err(Error::InvalidKeyLength);
        }
        let (a, b) = self
            .a
            .par_iter()
            .zip(self.b.par_iter())
            .zip(s_vec.par_iter())
            .map(|((ap, bp), si)| {
                let v1s = ap.mul(si).into_affine();
                let v2s = bp.mul(si).into_affine();
                (v1s, v2s)
            })
            .unzip();

        Ok(Self { a: a, b: b })
    }

    /// Returns the left and right commitment key part. It makes copy.
    pub fn split(mut self, at: usize) -> (Self, Self) {
        let a_right = self.a.split_off(at);
        let b_right = self.b.split_off(at);
        (
            Self {
                a: self.a,
                b: self.b,
            },
            Self {
                a: a_right,
                b: b_right,
            },
        )
    }


    pub fn compress(&self, right: &Self, scale: &G::ScalarField) -> Result<Self, Error> {
        let left = self;
        if left.a.len() != right.a.len() {
            return Err(Error::InvalidKeyLength);
        }
        let (a, b): (Vec<G>, Vec<G>) = left
            .a
            .par_iter()
            .zip(left.b.par_iter())
            .zip(right.a.par_iter())
            .zip(right.b.par_iter())
            .map(|(((left_a, left_b), right_a), right_b)| {
                let mut ra = right_a.mul(scale);
                let mut rb = right_b.mul(scale);
                ra.add_assign(left_a);
                rb.add_assign(left_b);
                (ra.into_affine(), rb.into_affine())
            })
            .unzip();

        Ok(Self { a: a, b: b })
    }


    pub fn first(&self) -> (G, G) {
        (self.a[0], self.b[0])
    }
}

/// Both commitment outputs a pair of $F_q^k$ element.
#[derive(PartialEq, CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Output<F: CanonicalSerialize + CanonicalDeserialize + CyclotomicMultSubgroup>(
    pub F,
    pub F,
);


pub fn single_g1<E: Pairing>(
    vkey: &VKey<E>,
    a_vec: &[E::G1Affine],
) -> Result<Output<<E as Pairing>::TargetField>, Error> {
    try_par! {
        let a = ip::pairing::<E>(a_vec, &vkey.a),
        let b = ip::pairing::<E>(a_vec, &vkey.b)
    };
    Ok(Output(a.0, b.0))
}


pub fn pair<E: Pairing>(
    vkey: &VKey<E>,
    wkey: &WKey<E>,
    a: &[E::G1Affine],
    b: &[E::G2Affine],
) -> Result<Output<<E as Pairing>::TargetField>, Error> {
    try_par! {
        // (A * v)
        let t1 = ip::pairing::<E>(a, &vkey.a),
        // (w * B)
        let t2 = ip::pairing::<E>(&wkey.a, b),
        let u1 = ip::pairing::<E>(a, &vkey.b),
        let u2 = ip::pairing::<E>(&wkey.b, b)
    };
    // (A * v)(w * B)
    let mut t1 = t1.0;
    let mut u1 = u1.0;
    t1.mul_assign(&t2.0);
    u1.mul_assign(&u2.0);
    Ok(Output(t1, u1))
}


