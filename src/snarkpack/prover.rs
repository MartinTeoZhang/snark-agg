use ark_ff::{Field};


/// It returns the evaluation of the polynomial $\prod (1 + x_{l-j}(rX)^{2j}$ at
/// the point z, where transcript contains the reversed order of all challenges (the x).
/// THe challenges must be in reversed order for the correct evaluation of the
/// polynomial in O(logn)
pub(super) fn polynomial_evaluation_product_form_from_transcript<F: Field>(
    transcript: &[F],
    z: &F,
    r_shift: &F,
) -> F {
    // this is the term (rz) that will get squared at each step to produce the
    // $(rz)^{2j}$ of the formula
    let mut power_zr = *z;
    power_zr.mul_assign(r_shift);

    let one = F::one();

    let mut res = one + transcript[0] * &power_zr;
    for x in &transcript[1..] {
        power_zr = power_zr.square();
        res.mul_assign(one + *x * &power_zr);
    }

    res
}

