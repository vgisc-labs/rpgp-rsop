// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::VecDeque;

use pgp::crypto::ecc_curve::ECCCurve;
use rpgpie::key::Tsk;

use crate::{Keys, RPGSOP};

const PROFILE_EDDSA: &str = "draft-koch-eddsa-for-openpgp-00";
const PROFILE_RFC4880: &str = "rfc4880";
const PROFILE_NISTP256: &str = "rfc6637-nistp256";
const PROFILE_NISTP384: &str = "rfc6637-nistp384";
const PROFILE_NISTP521: &str = "rfc6637-nistp521";

const PROFILE_RFC9580: &str = "rfc9580";
const PROFILE_RFC9580_LEGACY: &str = "rfc9580-legacy"; // FIXME: this combination is actually illegal. the test suite should check that implementations don't allow it.
const PROFILE_RFC9580_NISTP: &str = "rfc9580-nistp";
const PROFILE_RFC9580_RSA: &str = "rfc9580-rsa";

const PROFILES: &[(&str, &str)] = &[
    (PROFILE_EDDSA, "use EdDSA & ECDH over Cv25519"),
    (PROFILE_RFC9580, "use algorithms from RFC 9580"),
    (PROFILE_RFC9580_RSA, "use format from RFC 9580 with RSA"),
    (
        PROFILE_RFC9580_NISTP,
        "use format from RFC 9580 with NISTP256",
    ),
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
            PROFILE_NISTP256 => PROFILE_NISTP256,
            PROFILE_NISTP384 => PROFILE_NISTP384,
            PROFILE_NISTP521 => PROFILE_NISTP521,
            PROFILE_RFC9580 => PROFILE_RFC9580,
            PROFILE_RFC9580_LEGACY => PROFILE_RFC9580_LEGACY,
            PROFILE_RFC9580_NISTP => PROFILE_RFC9580_NISTP,
            PROFILE_RFC9580_RSA => PROFILE_RFC9580_RSA,
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
        let primary_user_id = self.user_ids.pop_front();
        let other_user_ids = self.user_ids.into();

        let (key_type_pri, key_type_enc) = match self.profile {
            // Curve 25519-based keys
            PROFILE_EDDSA => (
                pgp::KeyType::EdDSALegacy,
                pgp::KeyType::ECDH(ECCCurve::Curve25519),
            ),

            // RSA 4096 is compatible with Gnuk v1 (while RSA 3072 is not)
            PROFILE_RFC4880 => (pgp::KeyType::Rsa(4096), pgp::KeyType::Rsa(4096)),

            // Nist-P* -based keys
            PROFILE_NISTP256 => (
                pgp::KeyType::ECDSA(ECCCurve::P256),
                pgp::KeyType::ECDH(ECCCurve::P256),
            ),
            PROFILE_NISTP384 => (
                pgp::KeyType::ECDSA(ECCCurve::P384),
                pgp::KeyType::ECDH(ECCCurve::P384),
            ),
            PROFILE_NISTP521 => (
                pgp::KeyType::ECDSA(ECCCurve::P521),
                pgp::KeyType::ECDH(ECCCurve::P521),
            ),

            PROFILE_RFC9580 => {
                let tsk = Tsk::generate6(
                    pgp::KeyType::Ed25519,
                    pgp::KeyType::X25519,
                    primary_user_id,
                    other_user_ids,
                )
                .expect("FIXME");

                return Ok(Keys { keys: vec![tsk] });
            }

            PROFILE_RFC9580_LEGACY => {
                let tsk = Tsk::generate6(
                    pgp::KeyType::EdDSALegacy,
                    pgp::KeyType::ECDH(ECCCurve::Curve25519),
                    primary_user_id,
                    other_user_ids,
                )
                .expect("FIXME");

                return Ok(Keys { keys: vec![tsk] });
            }

            PROFILE_RFC9580_NISTP => {
                let tsk = Tsk::generate6(
                    pgp::KeyType::ECDSA(ECCCurve::P256),
                    pgp::KeyType::ECDH(ECCCurve::P256),
                    primary_user_id,
                    other_user_ids,
                )
                .expect("FIXME");

                return Ok(Keys { keys: vec![tsk] });
            }

            PROFILE_RFC9580_RSA => {
                let tsk = Tsk::generate6(
                    pgp::KeyType::Rsa(4096),
                    pgp::KeyType::Rsa(4096),
                    primary_user_id,
                    other_user_ids,
                )
                .expect("FIXME");

                return Ok(Keys { keys: vec![tsk] });
            }

            _ => return Err(sop::errors::Error::UnsupportedProfile),
        };

        let tsk = Tsk::generate(
            key_type_pri,
            if self.signing_only {
                None
            } else {
                Some(key_type_enc)
            },
            primary_user_id,
            other_user_ids,
        )
        .map_err(std::io::Error::other)?;

        Ok(Keys { keys: vec![tsk] })
    }
}
