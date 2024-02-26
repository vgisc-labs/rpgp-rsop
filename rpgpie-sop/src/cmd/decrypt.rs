// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io;
use std::time::SystemTime;

use pgp::composed::{Deserializable, Message};
use rpgpie::key::Tsk;

use crate::cmd::verify::Verify;
use crate::{util, Certs, Keys, RPGSOP};

#[derive(Default)]
pub(crate) struct Decrypt {
    verify: Verify,
    _session_keys: Vec<sop::SessionKey>,
    decryption_keys: Vec<Tsk>,
    key_passwords: Vec<sop::Password>, // Passwords for asymmetric component key material
    skesk_passwords: Vec<sop::Password>,
}

impl Decrypt {
    pub(crate) fn new() -> Self {
        Default::default()
    }
}

impl<'a> sop::ops::Decrypt<'a, RPGSOP, Certs, Keys> for Decrypt {
    fn verify_not_before(
        self: Box<Self>,
        _t: SystemTime,
    ) -> Box<dyn sop::ops::Decrypt<'a, RPGSOP, Certs, Keys> + 'a> {
        todo!();

        // self.verify.not_before = Some(t);
        // self
    }

    fn verify_not_after(
        self: Box<Self>,
        _t: SystemTime,
    ) -> Box<dyn sop::ops::Decrypt<'a, RPGSOP, Certs, Keys> + 'a> {
        todo!()

        // self.verify.not_after = Some(t);
        // self
    }

    fn verify_with_certs(
        mut self: Box<Self>,
        certs: &Certs,
    ) -> sop::Result<Box<dyn sop::ops::Decrypt<'a, RPGSOP, Certs, Keys> + 'a>> {
        certs
            .certs
            .iter()
            .for_each(|c| self.verify.certs.push(c.clone()));
        Ok(self)
    }

    fn with_session_key(
        self: Box<Self>,
        _session_key: sop::SessionKey,
    ) -> sop::Result<Box<dyn sop::ops::Decrypt<'a, RPGSOP, Certs, Keys> + 'a>> {
        todo!()

        // self.session_keys.push(sk);
        // Ok(self)
    }

    fn with_password(
        mut self: Box<Self>,
        password: sop::Password,
    ) -> sop::Result<Box<dyn sop::ops::Decrypt<'a, RPGSOP, Certs, Keys> + 'a>> {
        self.skesk_passwords.push(password);
        Ok(self)
    }

    fn with_keys(
        mut self: Box<Self>,
        keys: &Keys,
    ) -> sop::Result<Box<dyn sop::ops::Decrypt<'a, RPGSOP, Certs, Keys> + 'a>> {
        keys.keys
            .iter()
            .for_each(|tsk| self.decryption_keys.push(tsk.clone()));
        Ok(self)
    }

    fn with_key_password(
        mut self: Box<Self>,
        password: sop::Password,
    ) -> sop::Result<Box<dyn sop::ops::Decrypt<'a, RPGSOP, Certs, Keys> + 'a>> {
        self.key_passwords.push(password);
        Ok(self)
    }

    fn ciphertext<'d>(
        self: Box<Self>,
        ciphertext: &'d mut (dyn io::Read + Send + Sync),
    ) -> sop::Result<
        Box<dyn sop::ops::Ready<(Option<sop::SessionKey>, Vec<sop::ops::Verification>)> + 'd>,
    >
    where
        'a: 'd,
    {
        Ok(Box::new(DecryptReady {
            decrypt: *self,
            ciphertext,
        }))
    }
}

struct DecryptReady<'a> {
    decrypt: Decrypt,
    ciphertext: &'a mut (dyn io::Read + Send + Sync),
}

impl<'a> sop::ops::Ready<(Option<sop::SessionKey>, Vec<sop::ops::Verification>)>
    for DecryptReady<'a>
{
    fn to_writer(
        self: Box<Self>,
        sink: &mut (dyn io::Write + Send + Sync),
    ) -> sop::Result<(Option<sop::SessionKey>, Vec<sop::ops::Verification>)> {
        let c = util::load(self.ciphertext)?; // FIXME: process the input data in streaming mode?
        let (mut iter, _header) = Message::from_armor_many(c).expect("FIXME");

        if let Some(Ok(msg)) = iter.next() {
            // FIXME: use provided session keys, if any

            let key_passwords = self
                .decrypt
                .key_passwords
                .iter()
                .map(sop::plumbing::PasswordsAreHumanReadable::normalized)
                .collect();

            let skesk_passwords = self
                .decrypt
                .skesk_passwords
                .iter()
                .map(sop::plumbing::PasswordsAreHumanReadable::normalized)
                .collect();

            let mr = rpgpie::msg::unpack(
                msg,
                &self.decrypt.decryption_keys,
                key_passwords,
                skesk_passwords,
                &self.decrypt.verify.certs,
            );

            let session_key = mr
                .session_key
                .as_ref()
                .map(|sk| sop::SessionKey::new(sk.0, &(sk.1)).expect("FIXME"));

            let verifications = util::result_to_verifications(&mr);

            assert!(
                iter.next().is_none(),
                "message must be empty at this point!"
            );

            sink.write_all(mr.cleartext.data()).expect("FIXME");

            Ok((session_key, verifications))
        } else {
            panic!("no message found");
        }
    }
}
