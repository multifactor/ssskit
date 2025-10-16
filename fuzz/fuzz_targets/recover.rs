#![no_main]
use libfuzzer_sys::fuzz_target;

use arbitrary::Arbitrary;
use sharks::{Share, Sharks};

#[derive(Debug, Arbitrary)]
struct Parameters<const POLY: u16> {
    pub threshold: u8,
    pub shares: Vec<Share<POLY>>,
}

fuzz_target!(|params: Parameters<0x11d>| {
    let sharks = Sharks(params.threshold);
    let _secret = sharks.recover(&params.shares);
});
