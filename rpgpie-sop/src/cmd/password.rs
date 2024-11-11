// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use pgp::crypto::aead::AeadAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{KeyVersion, PublicKeyTrait, S2kParams, SecretKeyTrait, StringToKey};
use rand::{thread_rng, Rng};
use rpgpie::tsk::Tsk;
use sop::plumbing::PasswordsAreHumanReadable;
use sop::Password;

use crate::{Keys, RPGSOP};

pub(crate) struct ChangeKeyPassword {
    pw_old: Option<Password>,
    pw_new: Option<Password>,
}

impl ChangeKeyPassword {
    pub(crate) fn new() -> Self {
        Self {
            pw_old: None,
            pw_new: None,
        }
    }
}

impl<'a> sop::ops::ChangeKeyPassword<'a, RPGSOP, Keys> for ChangeKeyPassword {
    fn new_key_password(
        mut self: Box<Self>,
        password: Password,
    ) -> sop::Result<Box<dyn sop::ops::ChangeKeyPassword<'a, RPGSOP, Keys> + 'a>> {
        self.pw_new = Some(password);
        Ok(self)
    }

    fn old_key_password(
        mut self: Box<Self>,
        password: Password,
    ) -> sop::Result<Box<dyn sop::ops::ChangeKeyPassword<'a, RPGSOP, Keys> + 'a>> {
        self.pw_old = Some(password);
        Ok(self)
    }

    fn keys(self: Box<Self>, keys: &Keys) -> sop::Result<Keys> {
        fn s2k(version: KeyVersion) -> S2kParams {
            match version {
                KeyVersion::V4 => {
                    let mut rng = thread_rng();

                    let sym_alg = SymmetricKeyAlgorithm::AES256;

                    let mut iv = vec![0u8; sym_alg.block_size()];
                    rng.fill(&mut iv[..]);

                    S2kParams::Cfb {
                        sym_alg,
                        s2k: StringToKey::new_default(rng),
                        iv,
                    }
                }
                KeyVersion::V6 => {
                    let mut rng = thread_rng();

                    let sym_alg = SymmetricKeyAlgorithm::AES256;
                    let aead_mode = AeadAlgorithm::Ocb;

                    let mut nonce = vec![0u8; aead_mode.nonce_size()];
                    rng.fill(&mut nonce[..]);

                    let mut salt = [0u8; 16];
                    rng.fill(&mut salt[..]);

                    S2kParams::Aead {
                        sym_alg,
                        aead_mode,

                        s2k: StringToKey::Argon2 {
                            salt,
                            t: 1,
                            p: 4,
                            m_enc: 21, // 2 GB
                        },
                        nonce,
                    }
                }
                _ => unimplemented!(),
            }
        }

        let mut res: Vec<Tsk> = vec![];

        for key in &keys.keys {
            let pw_old = self
                .pw_old
                .as_ref()
                .map(|pw| String::from_utf8_lossy(pw.normalized()).to_string());

            let pw_new = self
                .pw_new
                .as_ref()
                .map(|pw| String::from_utf8_lossy(pw.normalized()).to_string());

            let mut ssk = key.key().clone();
            let pri = &mut ssk.primary_key;

            if let Some(pw_old) = &pw_old {
                pri.remove_password(|| pw_old.clone()).expect("FIXME");
            }

            if let Some(pw_new) = &pw_new {
                pri.set_password_with_s2k(|| pw_new.clone(), s2k(pri.public_key().version()))
                    .expect("FIXME");
            }

            for sub in &mut ssk.secret_subkeys {
                if let Some(pw_old) = &pw_old {
                    sub.key.remove_password(|| pw_old.clone()).expect("FIXME");
                }
                if let Some(pw_new) = &pw_new {
                    sub.key
                        .set_password_with_s2k(
                            || pw_new.clone(),
                            s2k(sub.key.public_key().version()),
                        )
                        .expect("FIXME");
                }
            }

            res.push(ssk.into());
        }

        Ok(Keys {
            keys: res,
            source_name: None,
        })
    }
}
