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

## OpenPGP card support

`rsop` supports use of secret key material on [OpenPGP card](https://en.wikipedia.org/wiki/OpenPGP_card) devices.

### User PIN

OpenPGP card devices require a *User
PIN* to perform cryptographic operations. `rsop` uses the [openpgp-card-state](https://crates.io/crates/openpgp-card-state) for User PIN handling. This means the User PIN must be available to `rsop` via one of the backends supported by openpgp-card-state.

### Example test run

To demonstrate this feature, we'll perform a test run here. In addition to `rsop`, this test run requires the `oct` tool from the [openpgp-card-tools](https://crates.io/crates/openpgp-card-tools) crate.

#### Generating a test key

First we generate a new private key for our test user, Alice (using the file extension `tsk` to signify that the file contains a [Transferable Secret Key](https://www.rfc-editor.org/rfc/rfc4880.html#section-11.2)). We also extract a certificate (that is, an equivalent "public key" file that omits the private key material) with the file extension `cert`:

```
$ rsop generate-key "<alice@example.org>" > alice.tsk
$ rsop extract-cert < alice.tsk > alice.cert
```

#### Setting up our OpenPGP card for testing

Now, we plug in our test OpenPGP card and check its identity:

```
$ oct list
Available OpenPGP cards:
FFFE:57011137
```

The card we're using in this example has the identity `FFFE:57011137`.

Optionally, we may want to factory-reset the card (this removes any key material from the card, and resets the User and Admin PIN to their default values):

```
$ oct system factory-reset --card FFFE:57011137
Resetting Card FFFE:57011137
```

Now we import Alice's key material onto our test-card:

```
$ oct admin --card FFFE:57011137 import alice.tsk
Enter Admin PIN:
```

The default Admin PIN on most OpenPGP card devices is `12345678`, so you need to enter this PIN at the prompt.

If you're curious, you can have a look at the newly imported key material on your card now:

```
$ oct status
OpenPGP card FFFE:57011137 (card version 2.0)

Signature key:
  Fingerprint: 26FD 6C05 D8AB 6D9A 7A27  A5CA DB2E 1E31 FB8E 9EA7
  Creation Time: 2024-04-08 16:26:54 UTC
  Algorithm: Ed25519 (EdDSA)
  Signatures made: 0

Decryption key:
  Fingerprint: 4B8D 7AE1 D4DE 65CE F0A8  4D2E A60A B338 5999 2476
  Creation Time: 2024-04-08 16:26:54 UTC
  Algorithm: Cv25519 (ECDH)

Authentication key:
  Fingerprint: [unset]
  Algorithm: RSA 2048 [e 32]

Remaining PIN attempts: User: 3, Admin: 3, Reset Code: 3
```

#### Configuring the User PIN for this card on our host

Now we need to store the User PIN for our test card in a mechanism that [openpgp-card-state](https://crates.io/crates/openpgp-card-state) can access. For this test, we'll just store the User PIN in a plain text config file. On Linux systems, you can use an editor to add the following content to the config file `~/.config/openpgp-card-state/config.toml`, using your card's ident:

```
[[cards]]
ident = "FFFE:57011137"

[cards.pin_storage]
Direct = "123456"
```

After the `factory-reset` above, the User PIN `123456` should be correct for your device.

When using an OpenPGP card in production, with non-toy key material on it, you might want to consider using a different PIN storage backend (see the documentation for [openpgp-card-state](https://crates.io/crates/openpgp-card-state) for more details about this).

#### Decryption on the card

Now our setup is complete, and we can encrypt a message to Alice (by using Alice's public key material, from `alice.cert`):

```
$ echo "hello alice" | rsop encrypt alice.cert > alice.msg
```

Now, `rsop` can decrypt the message based on just the public key material for Alice. Notice that we're giving `rsop` the file `alice.cert`:

```
$ cat alice.msg | rsop decrypt alice.cert
hello alice
```

Note that when not using an OpenPGP card, this would not work! (For software key-based operation decryption needs the private key material from `alice.tsk`)

When using `rsop` to perform private key operations on an OpenPGP card, like this decryption operation, a number of things happen in the background:

- Enumerate all OpenPGP cards that are plugged into your system and tries to find one that contains key material that matches with the relevant subkey for the operation.
- Check for this card's identifier in the `openpgp-card-state` config file and learns if/which PIN backend contains the User PIN for this card, and obtains the PIN.
- Verify the User PIN with the card, to authorize performing the requested cryptographic operation.
- Perform the cryptographic operation on the card.

#### Signing on the card

Analogously, it's possible to issue a cryptographic signature with an OpenPGP card, using `rsop`:

```
$ echo "hello world" | rsop inline-sign alice.cert  > sig.alice
```

Note that, as above, the public key data in `alice.cert` is not sufficient to issue a signature. In the background, `rsop` again searches for an OpenPGP card device that contains the private signing key material that corresponds to Alice's public key material, and uses that.

We can verify this signature as usual, by checking its validity against Alice's public key material:

```
$ cat sig.alice | rsop inline-verify alice.cert
hello world
```

## OpenPGP interoperability test suite

`rsop` is included in the [OpenPGP interoperability test suite](https://tests.sequoia-pgp.org/), which tests the features of implementations, adherence to expectations, as well as interoperation between a large set of implementations.

## Rust SOP interface

The `rsop` CLI tool is built using the excellent <https://crates.io/crates/sop> framework. The `rsop` binary is trivially derived from [rpgpie-sop](https://crates.io/crates/rpgpie-sop).

## License

The (trivial) code of `rsop` is CC0 licensed.

Note, however, that when building a binary package from it, the binary's license is (of course) dictated by the licenses of its dependencies.

# Warning, early-stage project!

rsop and rpgpie are currently in an experimental, early development stage and are *NOT yet intended for production use*.
