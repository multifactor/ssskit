# SSSKit

[![Rust](https://github.com/multifactor/ssskit/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/multifactor/ssskit/actions/workflows/rust.yml)
[![Crates](https://img.shields.io/crates/v/ssskit.svg)](https://crates.io/crates/ssskit)
[![Docs](https://docs.rs/ssskit/badge.svg)](https://docs.rs/ssskit)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)

Fast, small, generic and secure [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) library crate

> [!Note] 
> This repository is a fork of [c0dearm/sharks](https://github.com/c0dearm/sharks), but will be actively developed and maintained by Multifactor.

Documentation:
- [API reference (docs.rs)](https://docs.rs/ssskit)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
ssskit = "0.1"
```

If your environment doesn't support `std`:

```toml
[dependencies]
ssskit = { version = "0.1", default-features = false }
```

To get started using ssskit, see the [Rust docs](https://docs.rs/ssskit)

## Features

### Developer friendly
The API is simple and to the point, with minimal configuration.

### Fast and small
The code is as idiomatic and clean as possible, with minimum external dependencies.

### Generic on irreducible polynomial
GF256 field support largely used primitive irreducible polynomials like 0x11B (AES), 0x11D (RS codes), 0x12B (Reed-Solomon codes), and more.

### Compile time asserts
Any operation on the field with a non-whitelisted polynomial will fail to build due to const assertions done at compile time.

### Secure by design
The implementation forbids the user to choose parameters that would result in an insecure application,
like generating more shares than what's allowed by the finite field length.

## Limitations

Because the Galois finite field it uses is [GF256](https://en.wikipedia.org/wiki/Finite_field#GF(p2)_for_an_odd_prime_p),
only up to 255 shares can be generated for a given secret. A larger number would be insecure as shares would start duplicating.
Nevertheless, the secret can be arbitrarily long as computations are performed on single byte chunks.

## Testing

This crate contains both unit and benchmark tests (as well as the examples included in the docs).
You can run them with `cargo test` and `cargo bench`.

### Benchmark results [min mean max]

| CPU          | obtain_shares_dealer            | step_shares_dealer              | recover_secret                  | share_from_bytes                | share_to_bytes                  |
| ------------ | ------------------------------- | ------------------------------- | ------------------------------- | ------------------------------- | ------------------------------- |
| Apple M1 Pro | [2.6976 µs 2.7007 µs 2.7039 µs] | [938.79 ps 939.83 ps 941.04 ps] | [190.00 µs 190.46 µs 191.06 µs] | [31.176 ns 31.311 ns 31.529 ns] | [23.196 ns 23.211 ns 23.230 ns] |

# Contributing

If you find a vulnerability, bug or would like a new feature, [open a new issue](https://github.com/multifactor/ssskit/issues/new).

To introduce your changes into the codebase, submit a Pull Request.

Many thanks!

# License

ssskit is distributed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.

# Acknowledgments

This project is derived from the excellent work in the original [sharks](https://github.com/c0dearm/sharks) repository by Aitor Ruano (`c0dearm`). We appreciate Aitor's foundational contributions, on which this crate is based.
