<!--
SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: CC0-1.0
-->

# rpgpie-sop-oct

`rpgpie-sop-oct` is a thin wrapper on top of [rpgpie](https://crates.io/crates/rpgpie). `rpgpie-sop-oct` implements a subset of the ["sop" Rust interface](https://crates.io/crates/sop). It exclusively implements operations that require private key material, and exclusively uses private key material on OpenPGP card devices. It is used in the [rsop-oct](https://crates.io/crates/rsop) CLI tool.

The foundation of `rpgpie-sop` consists of:

- [rpgp](https://github.com/rpgp/rpgp/), a production-grade implementation of low-level OpenPGP functionality.
- [openpgp-card-rpgp](https://codeberg.org/openpgp-card/rpgp), a wrapper for the openpgp-card crate to use OpenPGP card functionality with rPGP.
- [rpgpie 🦀️🔐🥧](https://crates.io/crates/rpgpie), an experimental higher level OpenPGP library based on rPGP.
