#![no_main]
use libfuzzer_sys::fuzz_target;

use ssskit::Share;

const POLY: u16 = 0x11d_u16;
fuzz_target!(|share: Share<POLY>| {
    let _data: Vec<u8> = (&share).into();
});
