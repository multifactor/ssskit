//! Fast, small and secure [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) library crate
//!
//! # Usage
//! ## (std)
//!
//! ```
//! use ssskit::{ SecretSharing, Share };
//!
//! # const POLY: u16 = 0x11d_u16;
//! // Set a minimum threshold of 10 shares for an irreducible polynomial POLY
//! let sss = SecretSharing::<POLY>(10);
//! // Obtain an iterator over the shares for secret [1, 2, 3, 4]
//! # #[cfg(feature = "std")]
//! # {
//! let dealer = sss.dealer(&[1, 2, 3, 4]);
//! // Get 10 shares
//! let shares = dealer
//!     .take(10)
//!     .map(Some)
//!     .collect::<Vec<Option<Share<POLY>>>>();
//! // Recover the original secret!
//! let secret = sss.recover(&shares).unwrap();
//! assert_eq!(secret, vec![1, 2, 3, 4]);
//! # }
//! ```
//!
//! ## (no std)
//!
//! ```
//! use ssskit::{ SecretSharing, Share };
//! use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
//!
//! # const POLY: u16 = 0x11d_u16;
//! // Set a minimum threshold of 10 shares
//! let sss = SecretSharing::<POLY>(10);
//! // Obtain an iterator over the shares for secret [1, 2, 3, 4]
//! let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
//! let dealer = sss.dealer_rng::<ChaCha8Rng>(&[1, 2, 3, 4], &mut rng);
//! // Get 10 shares
//! let shares = dealer
//!     .take(10)
//!     .map(Some)
//!     .collect::<Vec<Option<Share<POLY>>>>();
//! // Recover the original secret!
//! let secret = sss.recover(&shares).unwrap();
//! assert_eq!(secret, vec![1, 2, 3, 4]);
//! ```
//!
//! # Irreducible Polynomials
//!
//! This crate supports all 30 degree-8 irreducible polynomials over GF(2).
//! See the exported list [`PRIMITIVE_POLYS`] (defined in `field.rs`).
//!
//! Commonly used polynomials:
//! - 0x11B — used in AES (Rijndael)
//! - 0x11D — commonly used in Reed–Solomon (e.g., QR codes)
//!
//! # Feature flags and share variants
//!
//! This crate exposes compile-time feature flags to select the share representation and
//! other behavior:
//!
//! - `std` — enables `dealer` convenience (uses `rand::thread_rng`). Without `std`, use `dealer_rng`.
//! - `zeroize_memory` — enables `Zeroize` on share types to clear memory on drop.
//! - default (no `share_x`) — `Share` stores only `y` values. The `x` coordinate is implicit
//!   and derived from the iteration order (1-based) when generating or consuming shares.
//! - `share_x` — `Share` stores both `x` and `y`. The `x` is carried with each share.
//!
//! By default, `share_x` is disabled (no-x). To use `share_x`, enable `share_x` explicitly.
//!
//! Example (Cargo.toml):
//!
//! ```toml
//! ssskit = { version = "0.1", default-features = false, features = ["std", "zeroize_memory", "share_x"] }
//! ```
//!
//! Serialization format:
//! - Default (no x-coordinate): `Vec<u8>` representation contains only `y` bytes.
//! - With `share_x`: `Vec<u8>` representation is `[x, y...]` (first byte is `x`).
//!
//! API notes:
//! - `recover`: pass an iterator of `Option<Share>`; use `Some(share)` for known shares.
//!   This supports both variants uniformly (with or without `x`).
//! - `recover_shares`: fill a target of size `n` using `Option` positions (`None` for
//!   unknowns). Positions map to indices `1..=n`.
//!
//! In `share_x`, `x` in each `Share` is used directly. Without x-coordinate, the iterator index
//! is used as `x` (1-based) during interpolation and resharing.
#![cfg_attr(not(feature = "std"), no_std)]

mod field;
mod math;
mod share;

extern crate alloc;

use alloc::vec::Vec;
use hashbrown::HashSet;

use field::GF256;
pub use field::PRIMITIVE_POLYS;
pub use share::Share;

use crate::share::ShareWithX;

/// Tuple struct which implements methods to generate shares and recover secrets over a 256 bits Galois Field.
/// Its only parameter is the minimum shares threshold.
///
/// Usage example:
/// ```
/// # use ssskit::{ SecretSharing, Share };
/// # const POLY: u16 = 0x11d_u16;
/// // Set a minimum threshold of 10 shares
/// let sss = SecretSharing::<POLY>(10);
/// // Obtain an iterator over the shares for secret [1, 2, 3, 4]
/// # #[cfg(feature = "std")]
/// # {
/// let dealer = sss.dealer(&[1, 2, 3, 4]);
/// // Get 10 shares
/// let shares = dealer
///     .take(10)
///     .map(Some)
///     .collect::<Vec<Option<Share<POLY>>>>();
/// // Recover the original secret!
/// let secret = sss.recover(&shares).unwrap();
/// assert_eq!(secret, vec![1, 2, 3, 4]);
/// # }
/// ```
pub struct SecretSharing<const POLY: u16>(pub u8);

impl<const POLY: u16> SecretSharing<POLY> {
    /// This method is useful when `std` is not available. For typical usage
    /// see the `dealer` method.
    ///
    /// Given a `secret` byte slice, returns an `Iterator` along new shares.
    /// The maximum number of shares that can be generated is 256.
    /// A random number generator has to be provided.
    ///
    /// Example:
    /// ```
    /// # use ssskit::{ SecretSharing, Share };
    /// # use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
    /// # const POLY: u16 = 0x11d_u16;
    /// # let sss = SecretSharing::<POLY>(3);
    /// // Obtain an iterator over the shares for secret [1, 2]
    /// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
    /// let dealer = sss.dealer_rng::<ChaCha8Rng>(&[1, 2], &mut rng);
    /// // Get 3 shares
    /// let shares = dealer.take(3).collect::<Vec<Share<POLY>>>();
    pub fn dealer_rng<R: rand::Rng>(
        &self,
        secret: &[u8],
        rng: &mut R,
    ) -> impl Iterator<Item = Share<POLY>> {
        let mut polys = Vec::with_capacity(secret.len());

        for chunk in secret {
            polys.push(math::random_polynomial(GF256(*chunk), self.0, rng))
        }

        math::get_evaluator(polys)
    }

    /// Given a `secret` byte slice, returns an `Iterator` along new shares.
    /// The maximum number of shares that can be generated is 256.
    ///
    /// Example:
    /// ```
    /// # use ssskit::{ SecretSharing, Share };
    /// # const POLY: u16 = 0x11d_u16;
    /// # let sss = SecretSharing::<POLY>(3);
    /// // Obtain an iterator over the shares for secret [1, 2]
    /// let dealer = sss.dealer(&[1, 2]);
    /// // Get 3 shares
    /// let shares = dealer.take(3).collect::<Vec<Share<POLY>>>();
    #[cfg(feature = "std")]
    pub fn dealer(&self, secret: &[u8]) -> impl Iterator<Item = Share<POLY>> {
        let mut rng = rand::thread_rng();
        self.dealer_rng(secret, &mut rng)
    }

    /// Given an iterable collection of shares, recovers the original secret.
    /// If the number of distinct shares is less than the minimum threshold an `Err` is returned,
    /// otherwise an `Ok` containing the secret.
    ///
    /// Example:
    /// ```
    /// # use ssskit::{ SecretSharing, Share };
    /// # use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
    /// # const POLY: u16 = 0x11d_u16;
    /// # let sss = SecretSharing::<POLY>(3);
    /// # let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
    /// # let mut shares = sss
    /// #     .dealer_rng::<ChaCha8Rng>(&[1], &mut rng)
    /// #     .take(3)
    /// #     .map(Some)
    /// #     .collect::<Vec<Option<Share<POLY>>>>();
    /// // Recover original secret from shares
    /// let mut secret = sss.recover(&shares);
    /// // Secret correctly recovered
    /// assert!(secret.is_ok());
    /// // Remove shares for demonstration purposes
    /// shares.clear();
    /// secret = sss.recover(&shares);
    /// // Not enough shares to recover secret
    /// assert!(secret.is_err());
    pub fn recover<'a, T>(&self, shares: T) -> Result<Vec<u8>, &str>
    where
        T: IntoIterator<Item = &'a Option<Share<POLY>>>,
        T::IntoIter: Iterator<Item = &'a Option<Share<POLY>>>,
    {
        let mut share_length: Option<usize> = None;
        let mut keys: HashSet<Vec<u8>> = HashSet::new();
        let mut values: Vec<ShareWithX<POLY>> = Vec::new();

        #[allow(unused_variables)]
        for (i, share) in shares.into_iter().enumerate() {
            if share.is_none() {
                continue;
            }

            let share = share.as_ref().unwrap();

            if share_length.is_none() {
                share_length = Some(share.y.len());
            }

            if Some(share.y.len()) != share_length {
                return Err("All shares must have the same length");
            } else {
                keys.insert(Vec::from(share));
                #[cfg(feature = "share_x")]
                {
                    values.push(share.clone());
                }
                #[cfg(not(feature = "share_x"))]
                {
                    values.push(ShareWithX {
                        x: GF256(i as u8 + 1),
                        y: share.y.clone(),
                    });
                }
            }
        }

        if keys.is_empty() || (keys.len() < self.0 as usize) {
            Err("Not enough shares to recover original secret")
        } else {
            Ok(math::interpolate(&values))
        }
    }

    /// Given an iterable collection of shares (optionally with None for unknown shares), recovers the original shares up to the threshold.
    /// If the number of distinct shares is less than the minimum threshold an `Err` is returned,
    /// otherwise an `Ok` containing the desired number of shares.
    ///
    /// Example:
    /// ```
    /// # use ssskit::{ SecretSharing, Share };
    /// # use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
    /// # const POLY: u16 = 0x11d_u16;
    /// # let sss = SecretSharing::<POLY>(2);
    /// # let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
    /// # let shares = sss.dealer_rng::<ChaCha8Rng>(&[1, 2, 3, 4], &mut rng).take(3).collect::<Vec<Share<POLY>>>();
    /// // Recover original shares from original shares up to threshold shares
    /// let recovered_shares = sss.recover_shares(
    ///     [Some(&shares[0]), None, Some(&shares[2])],
    ///     3,
    /// );
    /// // Shares correctly recovered
    /// assert!(recovered_shares.is_ok());
    /// let recovered_shares = recovered_shares.unwrap();
    /// assert_eq!(recovered_shares.len(), 3);
    /// // Remove shares for demonstration purposes
    /// let recovered_shares = sss.recover_shares([Some(&shares[0]), None, None], 3);
    /// // Not enough shares to recover shares
    /// assert!(recovered_shares.is_err());
    pub fn recover_shares<'a, T>(&self, shares: T, n: usize) -> Result<Vec<Share<POLY>>, &str>
    where
        T: IntoIterator<Item = Option<&'a Share<POLY>>>,
        T::IntoIter: Iterator<Item = Option<&'a Share<POLY>>>,
    {
        let mut share_length: Option<usize> = None;
        let mut keys: HashSet<Vec<u8>> = HashSet::new();
        let mut values: Vec<(GF256<POLY>, Share<POLY>)> = Vec::new();

        let mut count = 0;
        #[allow(unused_variables)]
        for (i, share) in shares.into_iter().enumerate() {
            if share.is_none() {
                count += 1;
                continue;
            }

            let share = share.unwrap();

            if share_length.is_none() {
                share_length = Some(share.y.len());
            }

            if Some(share.y.len()) != share_length {
                return Err("All shares must have the same length");
            } else {
                keys.insert(Vec::from(share));
                #[cfg(feature = "share_x")]
                {
                    values.push((share.x.clone(), share.clone()));
                }
                #[cfg(not(feature = "share_x"))]
                {
                    values.push((GF256(i as u8 + 1), share.clone()));
                }
                count += 1;
            }
        }

        if count != n {
            return Err("provide a shares array of size n; use None for unknown shares");
        }

        if keys.is_empty() || (keys.len() < self.0 as usize) {
            Err("Not enough shares to recover original shares")
        } else if self.0 == 1 {
            // if threshold is 1, return the shares as is n times
            Ok(values
                .iter()
                .map(|(_, share)| share.clone())
                .cycle()
                .take(n)
                .collect())
        } else {
            Ok((1..=n).map(|i| math::reshare(&values, i)).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretSharing, Share};
    use alloc::{vec, vec::Vec};

    const POLY: u16 = 0x11b_u16;

    impl<const POLY: u16> SecretSharing<POLY> {
        #[cfg(not(feature = "std"))]
        fn make_shares(&self, secret: &[u8]) -> impl Iterator<Item = Share<POLY>> {
            use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

            let mut rng = ChaCha20Rng::from_seed([10; 32]);
            self.dealer_rng(secret, &mut rng)
        }

        #[cfg(feature = "std")]
        fn make_shares(&self, secret: &[u8]) -> impl Iterator<Item = Share<POLY>> {
            self.dealer(secret)
        }
    }

    #[test]
    fn test_insufficient_shares_err() {
        let sss = SecretSharing::<POLY>(255);
        let shares: Vec<Share<POLY>> = sss.make_shares(&[1]).take(254).collect();
        let shares: Vec<Option<Share<POLY>>> = shares.iter().map(|s| Some(s.clone())).collect();
        let secret = sss.recover(&shares);
        assert!(secret.is_err());
    }

    #[test]
    fn test_duplicate_shares_err() {
        let sss = SecretSharing::<POLY>(255);
        let mut shares: Vec<Share<POLY>> = sss.make_shares(&[1]).take(255).collect();
        #[cfg(not(feature = "share_x"))]
        {
            shares[1] = Share {
                y: shares[0].y.clone(),
            };
        }
        #[cfg(feature = "share_x")]
        {
            shares[1] = Share {
                x: shares[0].x.clone(),
                y: shares[0].y.clone(),
            };
        }
        let shares: Vec<Option<Share<POLY>>> = shares.iter().map(|s| Some(s.clone())).collect();
        let secret = sss.recover(&shares);
        assert!(secret.is_err());
    }

    #[test]
    fn test_integration_works() {
        let sss = SecretSharing::<POLY>(255);
        let shares: Vec<Share<POLY>> = sss.make_shares(&[1, 2, 3, 4]).take(255).collect();
        let shares: Vec<Option<Share<POLY>>> = shares.iter().map(|s| Some(s.clone())).collect();
        let secret = sss.recover(&shares).unwrap();
        assert_eq!(secret, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_reshare_works() {
        let sss = SecretSharing::<POLY>(3);
        let shares: Vec<Share<POLY>> = sss.make_shares(&[1, 2, 3, 4]).take(4).collect();

        let recovered_shares = sss
            .recover_shares(
                [Some(&shares[0]), None, Some(&shares[2]), Some(&shares[3])],
                4,
            )
            .unwrap();
        assert_eq!(recovered_shares.len(), 4);

        for (recovered_share, share) in recovered_shares.iter().zip(shares.iter()) {
            #[cfg(feature = "share_x")]
            {
                assert_eq!(recovered_share.x, share.x);
            }

            assert_eq!(recovered_share.y, share.y);
        }

        let recovered_shares = sss
            .recover_shares(
                [None, Some(&shares[1]), Some(&shares[2]), Some(&shares[3])],
                4,
            )
            .unwrap();
        assert_eq!(recovered_shares.len(), 4);

        for (recovered_share, share) in recovered_shares.iter().zip(shares.iter()) {
            #[cfg(feature = "share_x")]
            {
                assert_eq!(recovered_share.x, share.x);
            }

            assert_eq!(recovered_share.y, share.y);
        }

        let recovered_shares = sss
            .recover_shares(
                [Some(&shares[0]), Some(&shares[1]), Some(&shares[2]), None],
                4,
            )
            .unwrap();
        assert_eq!(recovered_shares.len(), 4);

        for (recovered_share, share) in recovered_shares.iter().zip(shares.iter()) {
            #[cfg(feature = "share_x")]
            {
                assert_eq!(recovered_share.x, share.x);
            }

            assert_eq!(recovered_share.y, share.y);
        }

        let recovered_shares =
            sss.recover_shares([Some(&shares[0]), None, None, Some(&shares[3])], 4);
        assert!(recovered_shares.is_err());
    }

    #[test]
    fn test_k_of_n() {
        let sharks = SecretSharing::<POLY>(2);
        let shares: Vec<Share<POLY>> = sharks.make_shares(&[18, 52, 86, 120]).take(4).collect();

        let recovered_shares = sharks
            .recover_shares(
                [Some(&shares[0]), Some(&shares[1]), Some(&shares[2]), None],
                4,
            )
            .unwrap();
        assert_eq!(recovered_shares.len(), 4);

        for (recovered_share, share) in recovered_shares.iter().zip(shares.iter()) {
            #[cfg(feature = "share_x")]
            {
                assert_eq!(recovered_share.x, share.x);
            }

            assert_eq!(recovered_share.y, share.y);
        }
    }

    #[cfg(feature = "share_x")]
    #[test]
    fn test_recover_order_independent_with_x() {
        let sss = SecretSharing::<POLY>(3);
        let shares: Vec<Share<POLY>> = sss.make_shares(&[7, 8, 9]).take(5).collect();

        let shuffled: Vec<Share<POLY>> =
            vec![shares[2].clone(), shares[4].clone(), shares[0].clone()];

        let shares_opt: Vec<Option<Share<POLY>>> = shuffled.into_iter().map(Some).collect();
        let secret = sss.recover(&shares_opt).unwrap();
        assert_eq!(secret, vec![7, 8, 9]);
    }

    #[test]
    fn test_threshold_one_recover_shares() {
        let sss = SecretSharing::<POLY>(1);
        let shares: Vec<Share<POLY>> = sss.make_shares(&[42, 43]).take(1).collect();
        let recovered = sss
            .recover_shares([Some(&shares[0]), None, None], 3)
            .unwrap();
        assert_eq!(recovered.len(), 3);
        for r in &recovered {
            assert_eq!(r.y, shares[0].y);
        }
        #[cfg(feature = "share_x")]
        {
            for r in &recovered {
                assert_eq!(r.x, shares[0].x);
            }
        }
    }
}
