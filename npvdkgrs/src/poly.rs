use core::ops::{Add, Mul};

use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_std::{end_timer, rand, start_timer, vec::Vec, Zero};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// A polynomial with coefficients of Group elements.
#[derive(Clone, PartialEq, Eq)]
pub struct DenseGPolynomial<G> {
    coeffs: Vec<G>,
}

impl<G: CurveGroup> core::fmt::Debug for DenseGPolynomial<G> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (i, coeff) in self.coeffs.iter().enumerate().filter(|(_, c)| !Zero::is_zero(*c)) {
            if i == 0 {
                write!(f, "\n{:?}", coeff)?;
            } else if i == 1 {
                write!(f, " + \n{:?} * x", coeff)?;
            } else {
                write!(f, " + \n{:?} * x^{}", coeff, i)?;
            }
        }
        Ok(())
    }
}

impl<G> DenseGPolynomial<G> {
    pub fn coeffs(&self) -> &[G] {
        &self.coeffs
    }

    pub fn into_coeffs(self) -> Vec<G> {
        self.coeffs
    }
}

impl<G: CurveGroup> DenseGPolynomial<G> {
    /// Constructs a new polynomial from a list of coefficients.
    pub fn from_coefficients_slice(coeffs: &[G]) -> Self {
        Self::from_coefficients_vec(coeffs.to_vec())
    }

    /// Constructs a new polynomial from a list of coefficients.
    pub fn from_coefficients_vec(coeffs: Vec<G>) -> Self {
        let mut result = Self { coeffs };
        // While there are zeros at the end of the coefficient vector, pop them off.
        result.truncate_leading_zeros();
        // Check that either the coefficients vec is empty or that the last coeff is
        // non-zero.
        assert!(result.coeffs.last().map_or(true, |coeff| !coeff.is_zero()));
        result
    }

    /// Outputs a univariate polynomial of degree `d` where each non-leading
    /// coefficient is sampled uniformly at random from `G` and the leading
    /// coefficient is sampled uniformly at random from among the non-zero
    /// elements of `G`.
    pub fn rand<R: rand::Rng>(d: usize, rng: &mut R) -> Self {
        let mut random_coeffs = Vec::new();

        if d > 0 {
            // d - 1 overflows when d = 0
            for _ in 0..=(d - 1) {
                random_coeffs.push(G::rand(rng));
            }
        }

        let mut leading_coefficient = G::rand(rng);

        while leading_coefficient.is_zero() {
            leading_coefficient = G::rand(rng);
        }

        random_coeffs.push(leading_coefficient);

        Self::from_coefficients_vec(random_coeffs)
    }

    /// Returns the total degree of the polynomial
    pub fn degree(&self) -> usize {
        if self.is_zero() {
            0
        } else {
            assert!(self.coeffs.last().map_or(false, |coeff| !coeff.is_zero()));
            self.coeffs.len() - 1
        }
    }

    #[cfg(not(feature = "parallel"))]
    pub fn evaluate(&self, point: &G::ScalarField) -> G {
        if self.is_zero() {
            return G::zero();
        } else if point.is_zero() {
            return self.coeffs[0];
        }
        Self::horner_evaluate(self.coeffs(), point)
    }

    #[cfg(feature = "parallel")]
    pub fn evaluate(&self, point: &G::ScalarField) -> G {
        use ark_ff::Field;

        if self.is_zero() {
            return G::zero();
        } else if point.is_zero() {
            return self.coeffs[0];
        }

        // Set some minimum number of field elements to be worked on per thread
        // to avoid per-thread costs dominating parallel execution time.
        const MIN_ELEMENTS_PER_THREAD: usize = 16;
        // Horners method - parallel method
        // compute the number of threads we will be using.
        let num_cpus_available = rayon::current_num_threads();
        let num_coeffs = self.coeffs.len();
        let num_elem_per_thread = core::cmp::max(num_coeffs / num_cpus_available, MIN_ELEMENTS_PER_THREAD);

        // run Horners method on each thread as follows:
        // 1) Split up the coefficients across each thread evenly.
        // 2) Do polynomial evaluation via horner's method for the thread's coefficients
        // 3) Scale the result point^{thread coefficient start index}
        // Then obtain the final polynomial evaluation by summing each threads result.
        let result: G = self
            .coeffs
            .par_chunks(num_elem_per_thread)
            .enumerate()
            .map(|(i, chunk)| {
                let mut thread_result = Self::horner_evaluate(&chunk, point);
                thread_result = thread_result.mul_bigint(point.pow(&[(i * num_elem_per_thread) as u64]).into_bigint());
                thread_result
            })
            .sum();
        result
    }

    #[inline]
    fn truncate_leading_zeros(&mut self) {
        while self.coeffs.last().map_or(false, |c| c.is_zero()) {
            self.coeffs.pop();
        }
    }

    // Horner's method for polynomial evaluation
    #[inline]
    fn horner_evaluate(poly_coeffs: &[G], point: &G::ScalarField) -> G {
        poly_coeffs
            .iter()
            .rfold(G::zero(), move |result, coeff| (result.mul_bigint(point.into_bigint()) + coeff))
    }
}

impl<G: CurveGroup> Add<&DenseGPolynomial<G>> for &DenseGPolynomial<G> {
    type Output = DenseGPolynomial<G>;

    fn add(self, other: &DenseGPolynomial<G>) -> DenseGPolynomial<G> {
        let mut result = if self.is_zero() {
            other.clone()
        } else if other.is_zero() {
            self.clone()
        } else if self.degree() >= other.degree() {
            let mut result = self.clone();
            result.coeffs.iter_mut().zip(&other.coeffs).for_each(|(a, b)| {
                *a = a.add(b);
            });
            result
        } else {
            let mut result = other.clone();
            result.coeffs.iter_mut().zip(&self.coeffs).for_each(|(a, b)| {
                *a = a.add(b);
            });
            result
        };
        result.truncate_leading_zeros();
        result
    }
}

impl<G: CurveGroup> Add<DenseGPolynomial<G>> for DenseGPolynomial<G> {
    type Output = DenseGPolynomial<G>;

    fn add(self, other: DenseGPolynomial<G>) -> DenseGPolynomial<G> {
        &self + &other
    }
}

impl<G: CurveGroup> Zero for DenseGPolynomial<G> {
    /// Returns the zero polynomial.
    fn zero() -> Self {
        Self { coeffs: Vec::new() }
    }

    /// Checks if the given polynomial is zero.
    fn is_zero(&self) -> bool {
        self.coeffs.is_empty() || self.coeffs.iter().all(|coeff| coeff.is_zero())
    }
}

/// An error that can occur during polynomial interpolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum InterpolationError {
    /// The input slices have different lengths ({0} != {1}).
    InvalidInputLengths(usize, usize),
    /// An attempt was made to invert zero.
    TriedToInvertZero,
}

/// Performs polynomial interpolation over a set of points where x-coordinates are field elements
/// and y-coordinates are points.
///
/// This function implements an optimized version of Lagrange interpolation with O(n) time complexity,
/// where n is the number of points. It's particularly useful in cryptographic protocols such as
/// threshold signatures or distributed key generation.
///
/// # Arguments
///
/// * `x` - A slice of field elements representing x-coordinates.
/// * `y` - A slice of points on y-coordinates.
///
/// # Returns
///
/// * `Ok(Vec<C>)` - A vector of elements representing the coefficients
///   of the interpolated polynomial, in ascending order of degree.
/// * `Err(InterpolationError)` - An error if the input slices have different lengths or if
///   a zero element is encountered during inversion.
///
/// # Type Parameters
///
/// * `C`: A type that could be multiplied by a field element and added to another element of the same type.
/// * `O`: The output type of the multiplication operation.
/// * `F`: A field element type.
///
/// # Note
///
/// This implementation is optimized for efficiency but may still be computationally expensive
/// due to operations on curve points. The interpolation is exact only at the given x points.
// TODO: revisit this implementation to make it more efficient
pub fn interpolate<C, O, F: Field>(x: &[F], y: &[C]) -> Result<Vec<C>, InterpolationError>
where
    C: Mul<F, Output = O> + Copy + Default + zeroize::Zeroize,
    C: Add<C, Output = O>,
    O: Into<C>,
{
    if x.len() != y.len() {
        return Err(InterpolationError::InvalidInputLengths(x.len(), y.len()));
    }

    let n = x.len();
    let mut s = vec![F::zero(); n];
    let mut coeffs = vec![C::default(); n];

    // Initialize the s polynomial
    s.push(F::one());
    s[n - 1] = -x[0];

    let start = start_timer!(|| "Computing Lagrange interpolation");

    let t1 = start_timer!(|| "Compute coefficients of the s polynomial");
    compute_coeffs(&x, &mut s);
    end_timer!(t1);

    // Compute the coefficients of the interpolation polynomial
    let t2 = start_timer!(|| "Compute coefficients of the interpolation polynomial");
    for i in 0..n {
        let x_i = x[i];
        let t3 = start_timer!(|| "Compute phi^-1");
        let ff = compute_phi_inv(x_i, &s)?;
        end_timer!(t3);
        let mut b = F::one();
        let t5 = start_timer!(|| "Update coefficients");
        update_coeffs(&mut coeffs, &y[i], &x_i, &s, &mut b, ff);
        end_timer!(t5);
    }
    end_timer!(t2);
    end_timer!(start);

    Ok(coeffs)
}

/// Compute coefficients of the s polynomial: s(X) = Π(X - x_i)
#[inline(always)]
fn compute_coeffs<F: Field>(x: &[F], s: &mut [F]) {
    let n = x.len();
    for (i, &x_elem) in x.iter().enumerate().skip(1) {
        for j in n - 1 - i..n - 1 {
            let s_j_1 = s[j + 1];
            s[j] -= x_elem * s_j_1;
        }
        s[n - 1] -= x_elem;
    }
}

/// Compute the Lagrange basis polynomial: φ_i(X) = Π(X - x_j) / (x_i - x_j)
#[inline(always)]
fn compute_phi_inv<F: Field>(x_i: F, s: &[F]) -> Result<F, InterpolationError> {
    let n = s.len() - 1;
    let mut phi = F::zero();
    for j in (1..=n).rev() {
        phi *= x_i;
        phi += F::from(j as u64) * s[j];
    }
    phi.inverse().ok_or(InterpolationError::TriedToInvertZero)
}

/// Compute the Lagrange basis polynomial: φ_i(X) = Π(X - x_j) / (x_i - x_j)
/// Update the coefficients of the interpolation polynomial using the Lagrange basis polynomial.
fn update_coeffs<C, O, F: Field>(coeffs: &mut [C], y_i: &C, x_i: &F, s: &[F], b: &mut F, ff: F)
where
    C: Mul<F, Output = O> + Copy,
    C: Add<C, Output = O>,
    O: Into<C>,
{
    let n = coeffs.len();
    for j in (0..n).rev() {
        // Update each coefficient using the Lagrange basis polynomial
        let bff = *b * ff;
        let ybbf = *y_i * bff;
        coeffs[j] = (coeffs[j] + ybbf.into()).into();
        *b *= x_i;
        *b += s[j];
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fr, G2Affine, G2Projective};
    use ark_ec::AffineRepr;
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

    use super::*;

    #[test]
    fn arithmetic_check_evaluate() {
        let gen = G2Affine::generator();
        let secret_key = Fr::from(123456789_u64);

        // p(x) = 111 + 222x
        let secret_coeffs = vec![Fr::from(111_u64), Fr::from(222_u64)];

        // pg(x) = g^(111) + (g^(222))^x = g^(111 + 222x)
        let public_coeffs = secret_coeffs
            .iter()
            .map(|coeff| gen * coeff)
            .map(Into::into)
            .collect::<Vec<G2Projective>>();

        let secret_poly = DensePolynomial::from_coefficients_vec(secret_coeffs);
        let public_poly = DenseGPolynomial::from_coefficients_vec(public_coeffs);

        let secret_eval = secret_poly.evaluate(&secret_key);
        let public_eval = public_poly.evaluate(&secret_key);

        assert_eq!(gen * secret_eval, public_eval);
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn arithmetic_check_evaluate_parallel() {
        let gen = G2Affine::generator();
        let secret_key = Fr::from(123456789_u64);

        // p(x) = 111 + 222x
        let secret_coeffs = vec![Fr::from(111_u64), Fr::from(222_u64)];

        // pg(x) = g^(111) + (g^(222))^x = g^(111 + 222x)
        let public_coeffs = secret_coeffs
            .iter()
            .map(|coeff| gen * coeff)
            .map(Into::into)
            .collect::<Vec<G2Projective>>();

        let secret_poly = DensePolynomial::from_coefficients_vec(secret_coeffs);
        let public_poly = DenseGPolynomial::from_coefficients_vec(public_coeffs);

        let secret_eval = secret_poly.evaluate(&secret_key);
        let public_eval = public_poly.evaluate(&secret_key);

        assert_eq!(gen * secret_eval, public_eval);
    }
}
