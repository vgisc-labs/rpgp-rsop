// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io;

use chrono::{DateTime, Utc};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::LiteralData;
use pgp::Message;
use rpgpie::key::checked::CheckedCertificate;
use rpgpie::key::{Certificate, Tsk};

use crate::{Keys, Sigs, RPGSOP};

pub(crate) struct Sign {
    pub(crate) mode: sop::ops::SignAs,
    pub(crate) hash_algos: Vec<HashAlgorithm>,
    pub(crate) with_key_password: Vec<sop::Password>,
    pub(crate) signers: Vec<Tsk>,
}

impl Sign {
    pub(crate) fn new() -> Self {
        Self {
            mode: Default::default(),
            hash_algos: rpgpie::policy::PREFERRED_HASH_ALGORITHMS.into(),
            with_key_password: Default::default(),
            signers: Default::default(),
        }
    }
}

impl Sign {
    pub(crate) fn add_signing_keys(&mut self, keys: &Keys) -> sop::Result<()> {
        for key in &keys.keys {
            self.add_signing_key(key)?;
        }
        Ok(())
    }

    fn add_signing_key(&mut self, tsk: &Tsk) -> sop::Result<()> {
        let cert = Certificate::from(tsk);
        let ccert: CheckedCertificate = (&cert).into();

        let now: DateTime<Utc> = chrono::offset::Utc::now();

        // Limit hash algorithms to what the signer prefers
        if let Some(p) = ccert.preferred_hash_algorithms(&now) {
            self.hash_algos.retain(|a| p.contains(a));
        }

        self.signers.push(tsk.clone());

        Ok(())
    }
}

impl<'a> sop::ops::Sign<'a, RPGSOP, Keys, Sigs> for Sign {
    fn mode(
        mut self: Box<Self>,
        mode: sop::ops::SignAs,
    ) -> Box<dyn sop::ops::Sign<'a, RPGSOP, Keys, Sigs> + 'a> {
        self.mode = mode;
        self
    }

    fn keys(
        mut self: Box<Self>,
        keys: &Keys,
    ) -> sop::Result<Box<dyn sop::ops::Sign<'a, RPGSOP, Keys, Sigs> + 'a>> {
        self.add_signing_keys(keys)?;
        Ok(self)
    }

    fn with_key_password(
        mut self: Box<Self>,
        password: sop::Password,
    ) -> sop::Result<Box<dyn sop::ops::Sign<'a, RPGSOP, Keys, Sigs> + 'a>> {
        self.with_key_password.push(password);
        Ok(self)
    }

    fn data(
        self: Box<Self>,
        input: &mut (dyn io::Read + Send + Sync),
    ) -> sop::Result<(sop::ops::Micalg, Sigs)> {
        if self.signers.is_empty() {
            return Err(sop::errors::Error::MissingArg);
        }

        let hash_algo = self.hash_algos.first().cloned().unwrap_or_default();

        let mut data = vec![];
        input.read_to_end(&mut data)?;

        let lit = match self.mode {
            sop::ops::SignAs::Binary => LiteralData::from_bytes("".into(), &data),
            sop::ops::SignAs::Text => {
                LiteralData::from_str("", &String::from_utf8(data).expect("FIXME"))
            }
        };

        let msg = Message::Literal(lit);

        let mut sigs = vec![];

        // Passwords to try
        let pws: Vec<&[u8]> = if self.with_key_password.is_empty() {
            vec![&[]]
        } else {
            self.with_key_password
                .iter()
                .map(sop::plumbing::PasswordsAreHumanReadable::normalized)
                .collect()
        };

        for tsk in self.signers {
            for signer in tsk.signing_capable_component_keys() {
                log::info!(
                    "Trying to sign data with signer: {:02x?}",
                    signer.fingerprint()
                );
                let sig = pws
                    .iter()
                    .flat_map(|pw| {
                        let result = signer.sign_msg(
                            msg.clone(),
                            || String::from_utf8_lossy(pw).to_string(),
                            hash_algo,
                        );

                        if result.is_err() {
                            log::warn!("Signing failed: {result:?}");
                        }

                        result
                    })
                    .next();

                match sig {
                    Some(Message::Signed { signature, .. }) => sigs.push(signature),
                    Some(_) => panic!("Unexpected message type while signing: {:?}", sig),
                    None => {
                        log::warn!(
                            "Couldn't sign with signer key {:02x?}",
                            signer.fingerprint()
                        );

                        // signing with this signing key failed but let's continue
                    }
                };
            }
        }

        if sigs.is_empty() {
            // FIXME: probably the password(s) were wrong, but this is a bit of a guess
            return Err(sop::errors::Error::KeyIsProtected);
        }

        let hash_algo_id = u8::from(hash_algo);

        Ok((
            hash_algo_id.into(),
            Sigs {
                sigs,
                source_name: None,
            },
        ))
    }
}
