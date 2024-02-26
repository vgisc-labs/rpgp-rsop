<!--
SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: CC0-1.0
-->

# rpgpie-sop

`rpgpie-sop` is a very thin wrapper on top of [rpgpie](https://crates.io/crates/rpgpie). `rpgpie-sop` implements the excellent ["sop" Rust interface](https://crates.io/crates/sop) and is used to build the [rsop](https://crates.io/crates/rsop) CLI tool.

The foundation of `rpgpie-sop` consists of:

- [rpgp](https://github.com/rpgp/rpgp/), a production-grade implementation of low-level OpenPGP functionality.
- [rpgpie 🦀️🔐🥧](https://crates.io/crates/rpgpie), an experimental higher level OpenPGP library based on rpgp.
