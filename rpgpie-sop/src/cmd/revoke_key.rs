// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::SubsecRound;
use pgp::packet::{RevocationCode, SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::PublicKeyTrait;
use pgp::types::{KeyVersion, SecretKeyTrait};
use pgp::{Signature, SignedPublicKey};
use rand::thread_rng;
use sop::plumbing::PasswordsAreHumanReadable;

use crate::{Certs, Keys, RPGSOP};

pub(crate) struct RevokeKey {
    key_passwords: Vec<sop::Password>, // Passwords for asymmetric component key material
}

impl RevokeKey {
    pub(crate) fn new() -> Self {
        let empty_pw = sop::Password::new_unchecked(vec![]);

        Self {
            key_passwords: vec![empty_pw],
        }
    }
}

impl<'a> sop::ops::RevokeKey<'a, RPGSOP, Certs, Keys> for RevokeKey {
    fn with_key_password(
        mut self: Box<Self>,
        password: sop::Password,
    ) -> sop::Result<Box<dyn sop::ops::RevokeKey<'a, RPGSOP, Certs, Keys>>> {
        self.key_passwords.push(password);
        Ok(self)
    }

    fn keys(self: Box<Self>, keys: &Keys) -> sop::Result<Certs> {
        let mut rng = thread_rng();

        let mut results = vec![];
        for tsk in &keys.keys {
            let primary = &tsk.key().primary_key;

            // Make a revocation signature
            let mut config = match primary.version() {
                KeyVersion::V4 => SignatureConfig::v4(
                    SignatureType::KeyRevocation,
                    primary.algorithm(),
                    primary.hash_alg(),
                ),
                KeyVersion::V6 => SignatureConfig::v6(
                    &mut rng,
                    SignatureType::KeyRevocation,
                    primary.algorithm(),
                    primary.hash_alg(),
                )
                .expect("FIXME"),
                v => panic!("unsupported key version {:?}", v),
            };

            config.hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(
                    chrono::Utc::now().trunc_subsecs(0),
                )),
                Subpacket::regular(SubpacketData::Issuer(primary.key_id())),
                Subpacket::regular(SubpacketData::RevocationReason(
                    RevocationCode::NoReason,
                    "unspecified".into(),
                )),
                Subpacket::regular(SubpacketData::IssuerFingerprint(primary.fingerprint())),
            ];

            let mut rev: Option<Signature> = None;

            for pw in &self.key_passwords {
                let pw = String::from_utf8_lossy(pw.normalized()).to_string();

                match config.clone().sign_key(&primary, || pw, &primary) {
                    Ok(sig) => {
                        rev = Some(sig);
                        break;
                    }
                    Err(e) => eprintln!("e: {:?}", e),
                };
            }

            let Some(rev) = rev else {
                return Err(sop::errors::Error::KeyCannotSign);
            };

            let mut revoked = tsk.key().clone();
            revoked.details.revocation_signatures.push(rev);

            let spk = SignedPublicKey::from(revoked);
            results.push(spk.into());
        }

        Ok(Certs { certs: results })
    }
}
