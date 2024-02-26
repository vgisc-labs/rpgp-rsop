<!--
SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: CC0-1.0
-->

# rsop

`rsop` is a "Stateless OpenPGP" CLI tool.

rsop is based on a stack of [rpgp](https://github.com/rpgp/rpgp/), [rpgpie 🦀️🔐🥧](https://crates.io/crates/rpgpie) and the [rpgpie-sop](https://crates.io/crates/rpgpie-sop) wrapper library.

## Stateless OpenPGP Command Line Interface

The stateless OpenPGP command line interface (SOP) is an implementation-agnostic standard for handling OpenPGP messages and key material.

For more background and details about SOP, see <https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/>.

## Example rsop run

Installation with cargo, and use of the `rsop` binary:

```
$ cargo install rsop
[..]

$ rsop generate-key "<alice@example.org>" > alice.pgp
$ echo "hello world" | rsop inline-sign alice.pgp
-----BEGIN PGP MESSAGE-----

xA0DAAoWRkwnBKe7uWYByxJiAGXLjm9oZWxsbyB3b3JsZArCdQQAFgoAHRYhBGdn
Wt8kdsJqcSYzsUZMJwSnu7lmBQJly45vAAoJEEZMJwSnu7lmrxYBAIlPPn7R2ScC
Qo9s06ebeI/zilJ9vNB7hi4t3Yw6oxbIAP0ddnO5tP2SJRDx+5eWd0slp3G6+AEz
FhrH5HCHKSvQAg==
=bnER
-----END PGP MESSAGE-----
```

Or, alternatively, you can run `rsop` directly from this repository:

```
$ cargo run -- generate-key "<alice@example.org>"
```

## Rust SOP interface

The `rsop` CLI tool is built using the excellent <https://crates.io/crates/sop> framework. The `rsop` binary is trivially derived from [rpgpie-sop](https://crates.io/crates/rpgpie-sop).

## License

The (trivial) code of `rsop` is CC0 licensed.

Note, however, that when building a binary package from it, the binary's license is (of course) dictated by the licenses of its dependencies.

# Warning, early-stage project!

rsop and rpgpie are currently in an experimental, early development stage and are *NOT yet intended for production use*.
