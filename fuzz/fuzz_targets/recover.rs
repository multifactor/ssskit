#![no_main]
use libfuzzer_sys::fuzz_target;

use arbitrary::Arbitrary;
use ssskit::{SecretSharing, Share};

const POLY: u16 = 0x11d_u16;
#[derive(Debug, Arbitrary)]
struct Parameters {
    pub threshold: u8,
    pub shares: Vec<Share<POLY>>,
}

fuzz_target!(|params: Parameters| {
    let sss = SecretSharing::<POLY>(params.threshold);
    let _secret = sss.recover(&params.shares);
});
