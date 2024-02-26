// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Cursor, Read};
use std::time::SystemTime;

use pgp::packet::SignatureType;
use pgp::Signature;
use rpgpie::key::component::ComponentKeyPub;
use rpgpie::key::Certificate;
use rpgpie::msg::MessageResult;

/// Helper to load all data from a file, and wrap it in a Cursor.
/// Cursors are convenient for reading with rpgp's reader functions.
///
/// FIXME: However, this approach doesn't scale to large input files
/// (files that don't conveniently fit into RAM must be processed in streaming mode).
pub(crate) fn load(source: &mut (dyn Read + Send + Sync)) -> sop::Result<Cursor<Vec<u8>>> {
    let mut input = vec![];
    source.read_to_end(&mut input)?;

    Ok(Cursor::new(input))
}

pub(crate) fn to_verification(
    signature: &Signature,
    cert: &Certificate,
    key: &ComponentKeyPub,
) -> sop::ops::Verification {
    let ct: SystemTime = (*signature.created().expect("FIXME")).into();

    let key_fp = hex::encode(key.fingerprint());
    let cert_fp = hex::encode(cert.fingerprint());

    let mode = match signature.typ() {
        SignatureType::Binary => sop::ops::SignatureMode::Binary,
        SignatureType::Text => sop::ops::SignatureMode::Text,
        _ => panic!("unexpected data signature type"),
    };

    sop::ops::Verification::new(ct, key_fp, cert_fp, mode, None).expect("FIXME")
}

pub(crate) fn result_to_verifications(mr: &MessageResult) -> Vec<sop::ops::Verification> {
    mr.validated
        .iter()
        .map(|(cert, key, sig)| to_verification(sig, cert, key))
        .collect()
}
