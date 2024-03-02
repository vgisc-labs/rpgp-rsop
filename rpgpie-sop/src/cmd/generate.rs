// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::VecDeque;

use rpgpie::key::Tsk;

use crate::{Keys, RPGSOP};

const PROFILE_EDDSA: &str = "draft-koch-eddsa-for-openpgp-00";
const PROFILE_RFC4880: &str = "rfc4880";

const PROFILES: &[(&str, &str)] = &[
    (PROFILE_EDDSA, "use EdDSA & ECDH over Cv25519"),
    (PROFILE_RFC4880, "use algorithms from RFC 4880"),
];

pub(crate) struct GenerateKey {
    profile: &'static str,
    signing_only: bool,
    key_password: Option<sop::Password>,
    user_ids: VecDeque<String>,
}

impl GenerateKey {
    pub(crate) fn new() -> Self {
        Self {
            profile: PROFILE_EDDSA,
            signing_only: false,
            key_password: Default::default(),
            user_ids: Default::default(),
        }
    }
}

impl<'a> sop::ops::GenerateKey<'a, RPGSOP, Keys> for GenerateKey {
    fn list_profiles(&self) -> Vec<(String, String)> {
        PROFILES
            .iter()
            .map(|(p, d)| (p.to_string(), d.to_string()))
            .collect()
    }

    fn profile(
        mut self: Box<Self>,
        profile: &str,
    ) -> sop::Result<Box<dyn sop::ops::GenerateKey<'a, RPGSOP, Keys>>> {
        self.profile = match profile {
            PROFILE_EDDSA | "default" => PROFILE_EDDSA,
            PROFILE_RFC4880 => PROFILE_RFC4880,
            _ => return Err(sop::errors::Error::UnsupportedProfile),
        };
        Ok(self)
    }

    fn signing_only(mut self: Box<Self>) -> Box<dyn sop::ops::GenerateKey<'a, RPGSOP, Keys>> {
        self.signing_only = true;
        self
    }

    fn with_key_password(
        mut self: Box<Self>,
        key_password: sop::Password,
    ) -> sop::Result<Box<dyn sop::ops::GenerateKey<'a, RPGSOP, Keys>>> {
        self.key_password = Some(key_password);
        Ok(self)
    }

    fn userid(
        mut self: Box<Self>,
        user_id: &str,
    ) -> Box<dyn sop::ops::GenerateKey<'a, RPGSOP, Keys>> {
        self.user_ids.push_back(user_id.into());
        self
    }

    fn generate(mut self: Box<Self>) -> sop::Result<Keys> {
        let (key_type_pri, key_type_enc) = match self.profile {
            // Curve 25519-based keys
            PROFILE_EDDSA => (pgp::KeyType::EdDSA, pgp::KeyType::ECDH),

            // RSA 4096 is compatible with Gnuk v1 (while RSA 3072 is not)
            PROFILE_RFC4880 => (pgp::KeyType::Rsa(4096), pgp::KeyType::Rsa(4096)),

            _ => return Err(sop::errors::Error::UnsupportedProfile),
        };

        let primary_user_id = self.user_ids.pop_front();
        let other_user_ids = self.user_ids.into();

        let tsk = Tsk::generate(key_type_pri, key_type_enc, primary_user_id, other_user_ids)
            .expect("FIXME");

        Ok(Keys { keys: vec![tsk] })
    }
}