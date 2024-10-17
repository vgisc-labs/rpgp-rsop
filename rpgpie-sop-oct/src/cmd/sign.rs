// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io;

use chrono::{DateTime, Utc};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::LiteralData;
use pgp::Message;
use rpgpie::certificate::{Certificate, Checked};

use crate::{card, Keys, Sigs, RPGSOPOCT};

pub(crate) struct Sign {
    pub(crate) mode: sop::ops::SignAs,
    pub(crate) hash_algos: Vec<HashAlgorithm>,
    pub(crate) with_key_password: Vec<sop::Password>,
    pub(crate) signers: Vec<Certificate>,
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

    fn add_signing_key(&mut self, cert: &Certificate) -> sop::Result<()> {
        let ccert: Checked = cert.into();

        let now: DateTime<Utc> = chrono::offset::Utc::now();

        // Limit hash algorithms to what the signer prefers
        if let Some(p) = ccert.preferred_hash_algorithms(&now) {
            self.hash_algos.retain(|a| p.contains(a));
        }

        self.signers.push(cert.clone());

        Ok(())
    }
}

impl<'a> sop::ops::Sign<'a, RPGSOPOCT, Keys, Sigs> for Sign {
    fn mode(
        mut self: Box<Self>,
        mode: sop::ops::SignAs,
    ) -> Box<dyn sop::ops::Sign<'a, RPGSOPOCT, Keys, Sigs> + 'a> {
        self.mode = mode;
        self
    }

    fn keys(
        mut self: Box<Self>,
        keys: &Keys,
    ) -> sop::Result<Box<dyn sop::ops::Sign<'a, RPGSOPOCT, Keys, Sigs> + 'a>> {
        self.add_signing_keys(keys)?;
        Ok(self)
    }

    fn with_key_password(
        mut self: Box<Self>,
        password: sop::Password,
    ) -> sop::Result<Box<dyn sop::ops::Sign<'a, RPGSOPOCT, Keys, Sigs> + 'a>> {
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

        for cert in self.signers {
            let ccert: Checked = (&cert).into();

            let keys: Vec<_> = ccert
                .valid_signing_capable_component_keys_at(&chrono::offset::Utc::now())
                .iter()
                .map(|x| x.as_componentkey().clone())
                .collect();

            for signer in keys {
                log::info!(
                    "Trying to sign data with signer: {:02x?}",
                    signer.fingerprint()
                );

                let pp = signer.public_params();
                let sig = card::sign_on_card(&msg, pp, hash_algo, &|| {}).ok();

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

        Ok((hash_algo_id.into(), Sigs { sigs }))
    }
}
