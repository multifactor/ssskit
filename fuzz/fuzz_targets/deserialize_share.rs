#![no_main]
use core::convert::TryFrom;
use libfuzzer_sys::fuzz_target;
use sharks::Share;

fuzz_target!(|data: &[u8]| {
    const POLY: u16 = 0x11d_u16;
    let _share = Share::<POLY>::try_from(data);
});
