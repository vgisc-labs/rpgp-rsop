// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io;

use chrono::{DateTime, Utc};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use rpgpie::key::checked::CheckedCertificate;
use rpgpie::key::component::ComponentKeyPub;
use rpgpie::key::Certificate;
use rpgpie::msg;

use crate::cmd::sign::Sign;
use crate::{Certs, Keys, RPGSOP};

pub(crate) struct Encrypt {
    armor: bool,
    profile: &'static str,
    mode: sop::ops::EncryptAs,
    symmetric_algorithms: Vec<SymmetricKeyAlgorithm>,
    recipients: Vec<ComponentKeyPub>,
    skesk_passwords: Vec<sop::Password>,
    sign: Sign, // Signing infrastructure, including private keys
}

impl Encrypt {
    const PROFILE_RFC4880: &'static str = "rfc4880";
    const PROFILES: &'static [(&'static str, &'static str)] =
        &[(Self::PROFILE_RFC4880, "use algorithms from RFC 4880")];

    pub(crate) fn new() -> Self {
        Self {
            armor: true,
            profile: Self::PROFILE_RFC4880,
            mode: Default::default(),
            symmetric_algorithms: rpgpie::policy::PREFERRED_SYMMETRIC_KEY_ALGORITHMS.into(),
            recipients: Default::default(),
            skesk_passwords: Default::default(),
            sign: Sign::new(),
        }
    }

    fn add_cert(mut self: Box<Self>, cert: &Certificate) -> sop::Result<Box<Self>> {
        let ccert: CheckedCertificate = cert.into();
        let now: DateTime<Utc> = chrono::offset::Utc::now();

        // Handle recipient preferences, if any
        // (calculate intersection with our defaults)
        if let Some(p) = ccert.preferred_symmetric_key_algo(&now) {
            self.symmetric_algorithms.retain(|a| p.contains(a));
        }

        let keys = ccert.valid_encryption_capable_component_keys();
        match !keys.is_empty() {
            true => {
                keys.into_iter().for_each(|key| self.recipients.push(key));
                Ok(self)
            }
            false => Err(sop::errors::Error::CertCannotEncrypt),
        }
    }
}

impl<'a> sop::ops::Encrypt<'a, RPGSOP, Certs, Keys> for Encrypt {
    fn no_armor(mut self: Box<Self>) -> Box<dyn sop::ops::Encrypt<'a, RPGSOP, Certs, Keys> + 'a> {
        self.armor = false;
        self
    }

    fn list_profiles(&self) -> Vec<(String, String)> {
        Self::PROFILES
            .iter()
            .map(|(p, d)| (p.to_string(), d.to_string()))
            .collect()
    }

    fn profile(
        mut self: Box<Self>,
        profile: &str,
    ) -> sop::Result<Box<dyn sop::ops::Encrypt<'a, RPGSOP, Certs, Keys> + 'a>> {
        self.profile = match profile {
            Self::PROFILE_RFC4880 | "default" => Self::PROFILE_RFC4880,
            _ => return Err(sop::errors::Error::UnsupportedProfile),
        };
        Ok(self)
    }

    fn mode(
        mut self: Box<Self>,
        mode: sop::ops::EncryptAs,
    ) -> Box<dyn sop::ops::Encrypt<'a, RPGSOP, Certs, Keys> + 'a> {
        self.sign.mode = mode.into();
        self.mode = mode;
        self
    }

    fn sign_with_keys(
        mut self: Box<Self>,
        keys: &Keys,
    ) -> sop::Result<Box<dyn sop::ops::Encrypt<'a, RPGSOP, Certs, Keys> + 'a>> {
        self.sign.add_signing_keys(keys)?;
        Ok(self)
    }

    fn with_key_password(
        mut self: Box<Self>,
        password: sop::Password,
    ) -> sop::Result<Box<dyn sop::ops::Encrypt<'a, RPGSOP, Certs, Keys> + 'a>> {
        self.sign.with_key_password.push(password);
        Ok(self)
    }

    fn with_password(
        mut self: Box<Self>,
        password: sop::Password,
    ) -> sop::Result<Box<dyn sop::ops::Encrypt<'a, RPGSOP, Certs, Keys> + 'a>> {
        self.skesk_passwords.push(password);
        Ok(self)
    }

    fn with_certs(
        mut self: Box<Self>,
        certs: &Certs,
    ) -> sop::Result<Box<dyn sop::ops::Encrypt<'a, RPGSOP, Certs, Keys> + 'a>> {
        for cert in &certs.certs {
            self = self.add_cert(cert)?;
        }
        Ok(self)
    }

    fn plaintext<'p>(
        self: Box<Self>,
        plaintext: &'p mut (dyn io::Read + Send + Sync),
    ) -> sop::Result<Box<dyn sop::ops::Ready<Option<sop::SessionKey>> + 'p>>
    where
        'a: 'p,
    {
        Ok(Box::new(EncryptReady {
            encrypt: *self,
            plaintext,
        }))
    }
}

struct EncryptReady<'a> {
    encrypt: Encrypt,
    plaintext: &'a mut (dyn io::Read + Send + Sync),
}

impl<'a> sop::ops::Ready<Option<sop::SessionKey>> for EncryptReady<'a> {
    fn to_writer(
        self: Box<Self>,
        sink: &mut (dyn io::Write + Send + Sync),
    ) -> sop::Result<Option<sop::SessionKey>> {
        if self.encrypt.recipients.is_empty() && self.encrypt.skesk_passwords.is_empty() {
            return Err(sop::errors::Error::MissingArg);
        }

        let symmetric_algo = *self
            .encrypt
            .symmetric_algorithms
            .first()
            .unwrap_or(&SymmetricKeyAlgorithm::default());

        let skesk_passwords = self
            .encrypt
            .skesk_passwords
            .iter()
            .map(sop::plumbing::PasswordsAreHumanReadable::normalized)
            .collect();

        let session_key: Vec<u8> = msg::encrypt(
            self.encrypt.recipients,
            skesk_passwords,
            self.encrypt.sign.signers,
            self.encrypt.sign.hash_algos.first(),
            symmetric_algo,
            self.plaintext,
            sink,
            self.encrypt.armor,
        )
        .expect("FIXME");

        let alg_id = u8::from(symmetric_algo);
        let session_key = sop::SessionKey::new(alg_id, session_key).expect("FIXME");

        Ok(Some(session_key))
    }
}