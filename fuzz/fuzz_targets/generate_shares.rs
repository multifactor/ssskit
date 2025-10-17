#![no_main]
use libfuzzer_sys::fuzz_target;

use arbitrary::Arbitrary;
use gf256sss::{Share, Sharks};

#[derive(Debug, Arbitrary)]
struct Parameters {
    pub threshold: u8,
    pub secret: Vec<u8>,
    pub n_shares: usize,
}

fuzz_target!(|params: Parameters| {
    const POLY: u16 = 0x11d_u16;
    let sharks = Sharks::<POLY>(params.threshold);
    let dealer = sharks.dealer(&params.secret);

    let _shares = dealer.take(params.n_shares).collect::<Vec<Share<POLY>>>();
});
