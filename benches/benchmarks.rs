use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

use ssskit::{SecretSharing, Share};

const POLY: u16 = 0x11d_u16;

fn dealer<const POLY: u16>(c: &mut Criterion) {
    let sss = SecretSharing::<POLY>(255);
    let mut dealer = sss.dealer(&[1]);

    c.bench_function("obtain_shares_dealer", |b| {
        b.iter(|| sss.dealer(black_box(&[1])))
    });
    c.bench_function("step_shares_dealer", |b| b.iter(|| dealer.next()));
}

fn recover<const POLY: u16>(c: &mut Criterion) {
    let sss = SecretSharing::<POLY>(255);
    let dealer = sss.dealer(&[1]);
    let shares = dealer.take(255).collect::<Vec<Share<POLY>>>();

    c.bench_function("recover_secret", |b| {
        b.iter(|| {
            sss.recover(black_box(
                &shares
                    .iter()
                    .map(|s| Some(s.clone()))
                    .collect::<Vec<Option<Share<POLY>>>>(),
            ))
        })
    });
}

fn share<const POLY: u16>(c: &mut Criterion) {
    let bytes_vec = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let bytes = bytes_vec.as_slice();
    let share = Share::<POLY>::try_from(bytes).unwrap();

    c.bench_function("share_from_bytes", |b| {
        b.iter(|| Share::<POLY>::try_from(black_box(bytes)))
    });

    c.bench_function("share_to_bytes", |b| {
        b.iter(|| Vec::from(black_box(&share)))
    });
}

criterion_group!(benches, dealer::<POLY>, recover::<POLY>, share::<POLY>);
criterion_main!(benches);
