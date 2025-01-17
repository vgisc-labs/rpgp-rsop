// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::VecDeque;

use pgp::crypto::ecc_curve::ECCCurve;
use rpgpie::key::Tsk;

use crate::{Keys, RPGSOP};

const PROFILE_EDDSA: &str = "draft-koch-eddsa-for-openpgp-00";
const PROFILE_RFC9580: &str = "rfc9580";

const PROFILE_RFC4880: &str = "interop-testing-rfc4880";
const PROFILE_NISTP256: &str = "interop-testing-rfc6637-nistp256";
const PROFILE_NISTP384: &str = "interop-testing-rfc6637-nistp384";
const PROFILE_NISTP521: &str = "interop-testing-rfc6637-nistp521";

const PROFILE_RFC9580_NISTP: &str = "interop-testing-rfc9580-nistp";
const PROFILE_RFC9580_RSA: &str = "interop-testing-rfc9580-rsa";
const PROFILE_RFC9580_CV448: &str = "interop-testing-rfc9580-cv448";

const PROFILES: &[(&str, &str)] = &[
    (PROFILE_EDDSA, "use EdDSA & ECDH over Cv25519"),
    (PROFILE_RFC9580, "use algorithms from RFC 9580"),
    //
    // -- the following profiles are for interop testing only --
    //
    (
        PROFILE_RFC9580_RSA,
        "Only for interop-testing: use algorithms from RFC 9580 with RSA",
    ),
    (
        PROFILE_RFC9580_NISTP,
        "Only for interop-testing: use algorithms from RFC 9580 with NIST P-256",
    ),
    (
        PROFILE_RFC9580_CV448,
        "Only for interop-testing: use algorithms from RFC 9580 with X448 and Ed25519",
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
            PROFILE_RFC9580_NISTP => PROFILE_RFC9580_NISTP,
            PROFILE_RFC9580_RSA => PROFILE_RFC9580_RSA,
            PROFILE_RFC9580_CV448 => PROFILE_RFC9580_CV448,
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

        let key_password: Option<&[u8]> = self
            .key_password
            .as_ref()
            .map(sop::plumbing::PasswordsAreHumanReadable::normalized);

        let key_password: Option<String> =
            key_password.map(String::from_utf8_lossy).map(Into::into);

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
                let tsk = Tsk::generate_v6(
                    pgp::KeyType::Ed25519,
                    pgp::KeyType::X25519,
                    primary_user_id,
                    other_user_ids,
                    key_password.as_deref(),
                )
                .expect("FIXME");

                return Ok(Keys {
                    keys: vec![tsk],
                    source_name: None,
                });
            }

            PROFILE_RFC9580_NISTP => {
                let tsk = Tsk::generate_v6(
                    pgp::KeyType::ECDSA(ECCCurve::P256),
                    pgp::KeyType::ECDH(ECCCurve::P256),
                    primary_user_id,
                    other_user_ids,
                    key_password.as_deref(),
                )
                .expect("FIXME");

                return Ok(Keys {
                    keys: vec![tsk],
                    source_name: None,
                });
            }

            PROFILE_RFC9580_RSA => {
                let tsk = Tsk::generate_v6(
                    pgp::KeyType::Rsa(4096),
                    pgp::KeyType::Rsa(4096),
                    primary_user_id,
                    other_user_ids,
                    key_password.as_deref(),
                )
                .expect("FIXME");

                return Ok(Keys {
                    keys: vec![tsk],
                    source_name: None,
                });
            }

            PROFILE_RFC9580_CV448 => {
                let tsk = Tsk::generate_v6(
                    pgp::KeyType::Ed25519, // FIXME: use Ed448 when rpgp supports it
                    pgp::KeyType::X448,
                    primary_user_id,
                    other_user_ids,
                    key_password.as_deref(),
                )
                .expect("FIXME");

                return Ok(Keys {
                    keys: vec![tsk],
                    source_name: None,
                });
            }

            _ => return Err(sop::errors::Error::UnsupportedProfile),
        };

        let tsk = Tsk::generate_v4(
            key_type_pri,
            if self.signing_only {
                None
            } else {
                Some(key_type_enc)
            },
            primary_user_id,
            other_user_ids,
            key_password.as_deref(),
        )
        .map_err(std::io::Error::other)?;

        Ok(Keys {
            keys: vec![tsk],
            source_name: None,
        })
    }
}
