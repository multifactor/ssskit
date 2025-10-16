// A module which contains necessary algorithms to compute Shamir's shares and recover secrets

use alloc::vec::Vec;

use rand::distr::{Distribution, Uniform};

use super::field::GF256;
use super::share::Share;

// Finds the [root of the Lagrange polynomial](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach).
// The expected `shares` argument format is the same as the output by the `get_evaluator´ function.
// Where each (key, value) pair corresponds to one share, where the key is the `x` and the value is a vector of `y`,
// where each element corresponds to one of the secret's byte chunks.
pub fn interpolate<const POLY: u16>(shares: &[Share<POLY>]) -> Vec<u8> {
    (0..shares[0].y.len())
        .map(|s| {
            shares
                .iter()
                .map(|s_i| {
                    shares
                        .iter()
                        .filter(|s_j| s_j.x != s_i.x)
                        .map(|s_j| s_j.x.clone() / (s_j.x.clone() - s_i.x.clone()))
                        .product::<GF256<POLY>>()
                        * s_i.y[s].clone()
                })
                .sum::<GF256<POLY>>()
                .0
        })
        .collect()
}

/// Takes N sample points and returns the value at a given x using Lagrange interpolation over GF(256).
pub fn interpolate_polynomial<const POLY: u16>(
    x_samples: &[GF256<POLY>],
    y_samples: &[GF256<POLY>],
    x: GF256<POLY>,
) -> GF256<POLY> {
    assert!(
        x_samples.len() == y_samples.len(),
        "sample length mistmatch"
    );

    let limit = x_samples.len();
    let mut result = GF256(0);

    for i in 0..limit {
        let mut basis = GF256(1);

        for j in 0..limit {
            if i == j {
                continue;
            }

            let num = x.clone() + x_samples[j].clone();
            let denom = x_samples[i].clone() + x_samples[j].clone();
            let term = num / denom;
            basis = basis * term;
        }

        result = result + (y_samples[i].clone() * basis);
    }

    result
}

pub fn reshare<const POLY: u16>(shares: &[Share<POLY>], index: usize) -> Share<POLY> {
    // assert that atleast 2 shares exist
    assert!(
        shares.len() >= 2 && shares.len() <= 255,
        "atleast 2 shares and atmost 255 shares are required"
    );

    let secret_length = shares[0].y.len();

    let mut new_secret = Vec::new();
    for i in 0..secret_length {
        let mut x_values = Vec::new();
        let mut y_values = Vec::new();
        for share in shares {
            x_values.push(share.x.clone());
            y_values.push(share.y[i].clone());
        }
        new_secret.push(interpolate_polynomial(
            &x_values,
            &y_values,
            GF256(index as u8),
        ));
    }

    Share {
        x: GF256(index as u8),
        y: new_secret,
    }
}

// Generates `k` polynomial coefficients, being the last one `s` and the others randomly generated between `[1, 255]`.
// Coefficient degrees go from higher to lower in the returned vector order.
pub fn random_polynomial<R: rand::Rng, const POLY: u16>(
    s: GF256<POLY>,
    k: u8,
    rng: &mut R,
) -> Vec<GF256<POLY>> {
    let k = k as usize;
    let mut poly = Vec::with_capacity(k);
    let between = Uniform::new_inclusive(1, 255).unwrap();

    for _ in 1..k {
        poly.push(GF256(between.sample(rng)));
    }
    poly.push(s);

    poly
}

// Returns an iterator over the points of the `polys` polynomials passed as argument.
// Each item of the iterator is a tuple `(x, [f_1(x), f_2(x)..])` where eaxh `f_i` is the result for the ith polynomial.
// Each polynomial corresponds to one byte chunk of the original secret.
// The iterator will start at `x = 1` and end at `x = 255`.
pub fn get_evaluator<const POLY: u16>(
    polys: Vec<Vec<GF256<POLY>>>,
) -> impl Iterator<Item = Share<POLY>> {
    (1..=u8::MAX).map(GF256).map(move |x| Share {
        x: x.clone(),
        y: polys
            .iter()
            .map(|p| {
                p.iter()
                    .fold(GF256(0), |acc, c| acc * x.clone() + c.clone())
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::{get_evaluator, interpolate, random_polynomial, Share, GF256};
    use alloc::{vec, vec::Vec};
    use rand_chacha::rand_core::SeedableRng;

    const POLY: u16 = 0x11d_u16;

    #[test]
    fn random_polynomial_works() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
        let poly = random_polynomial::<_, POLY>(GF256(1), 3, &mut rng);
        assert_eq!(poly.len(), 3);
        assert_eq!(poly[2], GF256(1));
    }

    #[test]
    fn evaluator_works() {
        let iter = get_evaluator::<POLY>(vec![vec![GF256(3), GF256(2), GF256(5)]]);
        let values: Vec<_> = iter.take(2).map(|s| (s.x.clone(), s.y.clone())).collect();
        assert_eq!(
            values,
            vec![(GF256(1), vec![GF256(4)]), (GF256(2), vec![GF256(13)])]
        );
    }

    #[test]
    fn interpolate_works() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
        let poly = random_polynomial(GF256(185), 10, &mut rng);
        let iter = get_evaluator(vec![poly]);
        let shares: Vec<Share<POLY>> = iter.take(10).collect();
        let root = interpolate(&shares);
        assert_eq!(root, vec![185]);
    }
}
