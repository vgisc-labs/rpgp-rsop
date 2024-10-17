// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::time::SystemTime;

use pgp::packet::SignatureType;
use pgp::types::Fingerprint;
use pgp::Signature;
use rpgpie::certificate::Certificate;
use rpgpie::message::MessageResult;

pub(crate) fn to_verification(
    signature: &Signature,
    cert: &Certificate,
    key_fp: Fingerprint,
) -> sop::ops::Verification {
    let ct: SystemTime = (*signature.created().expect("FIXME")).into();

    let key_fp = hex::encode(key_fp.as_bytes());
    let cert_fp = hex::encode(cert.fingerprint().as_bytes());

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
        .map(|(cert, key, sig)| to_verification(sig, cert, key.fingerprint()))
        .collect()
}
