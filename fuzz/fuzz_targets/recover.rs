#![no_main]
use libfuzzer_sys::fuzz_target;

use arbitrary::Arbitrary;
use sharks::{Share, Sharks};

const POLY: u16 = 0x11d_u16;
#[derive(Debug, Arbitrary)]
struct Parameters {
    pub threshold: u8,
    pub shares: Vec<Share<POLY>>,
}

fuzz_target!(|params: Parameters| {
    let sharks = Sharks::<POLY>(params.threshold);
    let _secret = sharks.recover(&params.shares);
});
