// A module which contains necessary algorithms to compute Shamir's shares and recover secrets

use alloc::vec;
use alloc::vec::Vec;

use crate::field::GF256;
use crate::share::Share;
use crate::share::ShareWithX;

// Finds the [root of the Lagrange polynomial](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach).
// The expected `shares` argument format is the same as the output by the `get_evaluator´ function.
// Where each (key, value) pair corresponds to one share, where the key is the `x` and the value is a vector of `y`,
// where each element corresponds to one of the secret's byte chunks.
pub fn interpolate<const POLY: u16>(shares: &[ShareWithX<POLY>]) -> Vec<u8> {
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

/// Resharing a share at a given index.
pub fn reshare<const POLY: u16>(
    shares: &[(GF256<POLY>, Share<POLY>)],
    index: usize,
) -> Share<POLY> {
    // assert that atleast 2 shares exist
    assert!(
        shares.len() >= 2 && shares.len() <= 255,
        "atleast 2 shares and atmost 255 shares are required"
    );

    let secret_length = shares[0].1.y.len();

    let mut new_secret = Vec::new();
    for i in 0..secret_length {
        let mut x_values = Vec::new();
        let mut y_values = Vec::new();
        for share in shares {
            x_values.push(share.0.clone());
            y_values.push(share.1.y[i].clone());
        }
        new_secret.push(interpolate_polynomial(
            &x_values,
            &y_values,
            GF256(index as u8),
        ));
    }

    #[cfg(feature = "share_x")]
    {
        Share {
            x: GF256(index as u8),
            y: new_secret,
        }
    }
    #[cfg(not(feature = "share_x"))]
    {
        Share { y: new_secret }
    }
}

/// Generates `k` polynomial coefficients, being the last one `s` and the others randomly generated between `[1, 255]`.
/// Coefficient degrees go from higher to lower in the returned vector order.
pub fn random_polynomial<R: rand::Rng, const POLY: u16>(
    s: GF256<POLY>,
    k: u8,
    rng: &mut R,
) -> Vec<GF256<POLY>> {
    let k = k as usize;
    let mut poly = Vec::with_capacity(k);

    let mut random_bytes = vec![0u8; k - 1];

    rng.fill(random_bytes.as_mut_slice());
    for random_byte in random_bytes.iter().rev() {
        poly.push(GF256(*random_byte));
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
    (1..=u8::MAX).map(GF256).map(move |x| {
        let y = polys
            .iter()
            .map(|p| {
                p.iter()
                    .fold(GF256(0), |acc, c| acc * x.clone() + c.clone())
            })
            .collect();
        #[cfg(feature = "share_x")]
        {
            Share { x: x.clone(), y }
        }
        #[cfg(not(feature = "share_x"))]
        {
            Share { y }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{get_evaluator, interpolate, random_polynomial, reshare, Share, ShareWithX, GF256};
    use alloc::{vec, vec::Vec};
    use rand_chacha::rand_core::SeedableRng;
    use rstest::rstest;

    const POLY: u16 = 0x11d_u16;

    #[rstest]
    #[case([0x90; 32], 3)]
    #[case([0x10; 32], 8)]
    #[case([0x20; 32], 16)]
    fn random_polynomial_works(#[case] seed: [u8; 32], #[case] k: usize) {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);
        let poly = random_polynomial::<_, POLY>(GF256(1), k as u8, &mut rng);
        assert_eq!(poly.len(), k);
    }

    #[test]
    fn evaluator_works() {
        let iter = get_evaluator::<POLY>(vec![vec![GF256(3), GF256(2), GF256(5)]]);
        let values: Vec<_> = iter.take(2).map(|s| s.y.clone()).collect();
        assert_eq!(values, vec![(vec![GF256(4)]), (vec![GF256(13)])]);
    }

    #[rstest]
    #[case([0x90; 32], 10)]
    #[case([0x10; 32], 8)]
    #[case([0x20; 32], 16)]
    fn interpolate_works(#[case] seed: [u8; 32], #[case] k: usize) {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);
        let poly = random_polynomial(GF256(185), k as u8, &mut rng);
        let iter = get_evaluator(vec![poly]);
        let shares: Vec<ShareWithX<POLY>> = iter
            .take(k)
            .enumerate()
            .map(|(i, s)| ShareWithX {
                x: GF256(i as u8 + 1),
                y: s.y.clone(),
            })
            .collect();
        let root = interpolate(&shares);
        assert_eq!(root, vec![185]);
    }

    #[rstest]
    #[case([0x90; 32], 10, 2)]
    #[case([0x90; 32], 10, 5)]
    #[case([0x10; 32], 8, 7)]
    #[case([0x10; 32], 8, 8)]
    fn reshare_works(#[case] seed: [u8; 32], #[case] k: usize, #[case] index: usize) {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);
        let poly = random_polynomial(GF256(185), k as u8, &mut rng);
        let iter = get_evaluator(vec![poly]);
        let shares: Vec<(GF256<POLY>, Share<POLY>)> = iter
            .take(k)
            .enumerate()
            .map(|(i, s)| (GF256(i as u8 + 1), s))
            .collect();
        let share = reshare(&shares, index);
        assert_eq!(share.y, shares[index - 1].1.y);
    }
}
