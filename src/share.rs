use alloc::vec::Vec;

use super::field::GF256;

#[cfg(feature = "fuzzing")]
use arbitrary::Arbitrary;

#[cfg(feature = "zeroize_memory")]
use zeroize::Zeroize;

#[derive(Clone)]
#[cfg_attr(feature = "fuzzing", derive(Arbitrary, Debug))]
#[cfg_attr(feature = "zeroize_memory", derive(Zeroize))]
#[cfg_attr(feature = "zeroize_memory", zeroize(drop))]
pub struct ShareNoX<const POLY: u16> {
    /// The y coordinates of the share.
    pub y: Vec<GF256<POLY>>,
}

#[derive(Clone)]
#[cfg_attr(feature = "fuzzing", derive(Arbitrary, Debug))]
#[cfg_attr(feature = "zeroize_memory", derive(Zeroize))]
#[cfg_attr(feature = "zeroize_memory", zeroize(drop))]
pub struct ShareWithX<const POLY: u16> {
    /// The x coordinate of the share.
    pub x: GF256<POLY>,
    /// The y coordinates of the share.
    pub y: Vec<GF256<POLY>>,
}

/// A share used to reconstruct the secret. Can be serialized to and from a byte array.
///
/// Usage example:
/// ```
/// use ssskit::{SecretSharing, Share};
/// use core::convert::TryFrom;
/// # use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
/// # fn send_to_printer(_: Vec<u8>) {}
/// # fn ask_shares() -> Vec<Vec<u8>> {vec![vec![1, 2, 3], vec![2, 3, 4], vec![3, 4, 5]]}
///
/// // Transmit the share bytes to a printer
/// # const POLY: u16 = 0x11d_u16;
/// let sss = SecretSharing::<POLY>(3);
/// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
/// let dealer = sss.dealer_rng::<ChaCha8Rng>(&[1, 2, 3], &mut rng);
///
/// // Get 5 shares and print paper keys
/// for s in dealer.take(5) {
///     send_to_printer(Vec::from(&s));
/// };
///
/// // Get share bytes from an external source and recover secret
/// let shares_bytes: Vec<Vec<u8>> = ask_shares();
/// let shares: Vec<Option<Share<POLY>>> = shares_bytes
///     .iter()
///     .map(|s| Some(Share::<POLY>::try_from(s.as_slice()).unwrap()))
///     .collect();
/// let secret = sss.recover(&shares).unwrap();
/// #[cfg(feature = "share_nox")]
/// {
///     assert_eq!(secret, vec![0, 5, 2]);
/// }
/// #[cfg(feature = "share_x")]
/// {
///     assert_eq!(secret, vec![5, 2]);
/// }
/// ```
///
/// # Serialization format:
/// - Default (no x-coordinate): `Vec<u8>` representation contains only `y` bytes.
/// - With `share_x`: `Vec<u8>` representation is `[x, y...]` (first byte is `x`).
#[cfg(not(feature = "share_x"))]
pub type Share<const POLY: u16> = ShareNoX<POLY>;
/// A share used to reconstruct the secret. Can be serialized to and from a byte array.
///
/// Usage example (when share_x is enabled):
/// ```
/// use ssskit::{SecretSharing, Share};
/// use core::convert::TryFrom;
/// # use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
/// # fn send_to_printer(_: Vec<u8>) {}
/// # fn ask_shares() -> Vec<Vec<u8>> {vec![vec![1, 2, 3], vec![2, 3, 4], vec![3, 4, 5]]}
///
/// // Transmit the share bytes to a printer
/// # const POLY: u16 = 0x11d_u16;
/// let sss = SecretSharing::<POLY>(3);
/// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
/// let dealer = sss.dealer_rng::<ChaCha8Rng>(&[1, 2, 3], &mut rng);
///
/// // Get 5 shares and print paper keys
/// for s in dealer.take(5) {
///     send_to_printer(Vec::from(&s));
/// };
///
/// // Get share bytes from an external source and recover secret
/// let shares_bytes: Vec<Vec<u8>> = ask_shares();
/// let shares: Vec<Option<Share<POLY>>> = shares_bytes
///     .iter()
///     .map(|s| Some(Share::<POLY>::try_from(s.as_slice()).unwrap()))
///     .collect();
/// let secret = sss.recover(&shares).unwrap();
/// #[cfg(feature = "share_x")]
/// {
///     assert_eq!(secret, vec![5, 2]);
/// }
/// #[cfg(feature = "share_nox")]
/// {
///     assert_eq!(secret, vec![0, 5, 2]);
/// }
/// ```
///
/// # Serialization format:
/// - Default (no x-coordinate): `Vec<u8>` representation contains only `y` bytes.
/// - With `share_x`: `Vec<u8>` representation is `[x, y...]` (first byte is `x`).
#[cfg(feature = "share_x")]
pub type Share<const POLY: u16> = ShareWithX<POLY>;

/// Converts a ShareNoX to a vector of bytes, where the bytes are the y values.
impl<const POLY: u16> From<&ShareNoX<POLY>> for Vec<u8> {
    fn from(s: &ShareNoX<POLY>) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(s.y.len());
        bytes.extend(s.y.iter().map(|p| p.0));
        bytes
    }
}

impl<const POLY: u16> core::convert::TryFrom<&[u8]> for ShareNoX<POLY> {
    type Error = &'static str;

    fn try_from(s: &[u8]) -> Result<ShareNoX<POLY>, Self::Error> {
        if s.len() < 2 {
            Err("A Share must be at least 2 bytes long")
        } else {
            let y = s.iter().map(|p| GF256(*p)).collect();
            Ok(ShareNoX { y })
        }
    }
}

/// Converts a ShareWithX to a vector of bytes, where the first byte is the x value and the rest are the y values.
impl<const POLY: u16> From<&ShareWithX<POLY>> for Vec<u8> {
    fn from(s: &ShareWithX<POLY>) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(s.y.len() + 1);
        bytes.push(s.x.0);
        bytes.extend(s.y.iter().map(|p| p.0));
        bytes
    }
}

impl<const POLY: u16> core::convert::TryFrom<&[u8]> for ShareWithX<POLY> {
    type Error = &'static str;

    fn try_from(s: &[u8]) -> Result<ShareWithX<POLY>, Self::Error> {
        if s.len() < 2 {
            Err("A Share must be at least 2 bytes long")
        } else {
            let x = GF256(s[0]);
            let y = s[1..].iter().map(|p| GF256(*p)).collect();
            Ok(ShareWithX { x, y })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Share, GF256};
    use alloc::{vec, vec::Vec};
    use core::convert::TryFrom;
    const POLY: u16 = 0x11d_u16;

    #[cfg(not(feature = "share_x"))]
    #[test]
    fn vec_from_share_works() {
        let share = Share::<POLY> {
            y: vec![GF256(2), GF256(3)],
        };
        let bytes = Vec::from(&share);
        assert_eq!(bytes, vec![2, 3]);
    }

    #[cfg(feature = "share_x")]
    #[test]
    fn vec_from_share_works() {
        let share = Share::<POLY> {
            x: GF256(1),
            y: vec![GF256(2), GF256(3)],
        };
        let bytes = Vec::from(&share);
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[cfg(not(feature = "share_x"))]
    #[test]
    fn share_from_u8_slice_works() {
        let bytes = [1, 2, 3];
        let share = Share::<POLY>::try_from(&bytes[..]).unwrap();
        assert_eq!(share.y, vec![GF256(1), GF256(2), GF256(3)]);
    }

    #[cfg(feature = "share_x")]
    #[test]
    fn share_from_u8_slice_works() {
        let bytes = [1, 2, 3];
        let share = Share::<POLY>::try_from(&bytes[..]).unwrap();
        assert_eq!(share.x, GF256(1));
        assert_eq!(share.y, vec![GF256(2), GF256(3)]);
    }
}
