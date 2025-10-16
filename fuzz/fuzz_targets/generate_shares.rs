#![no_main]
use libfuzzer_sys::fuzz_target;

use arbitrary::Arbitrary;
use sharks::{Share, Sharks};

#[derive(Debug, Arbitrary)]
struct Parameters {
    pub threshold: u8,
    pub secret: Vec<u8>,
    pub n_shares: usize,
}

fuzz_target!(|params: Parameters| {
    const POLY: u16 = 0x11d_u16;
    let sharks = Sharks(params.threshold);
    let dealer = sharks.dealer::<POLY>(&params.secret);

    let _shares: Vec<Share<POLY>> = dealer.take(params.n_shares).collect();
});
