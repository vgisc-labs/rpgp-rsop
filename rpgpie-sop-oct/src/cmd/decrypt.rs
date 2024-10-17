// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io;
use std::time::SystemTime;

use openpgp_card_rpgp::CardSlot;
use pgp::composed::{Deserializable, Message};
use pgp::packet::PublicKeyEncryptedSessionKey;
use pgp::types::SecretKeyTrait;
use pgp::PlainSessionKey;
use rpgpie::certificate::{Certificate, Checked};
use rpgpie::message::PkeskDecryptor;

use crate::card::{card_by_pp, verify_pin_from_card_state};
use crate::{util, Certs, Keys, RPGSOPOCT};

#[derive(Default)]
pub(crate) struct Decrypt {
    verify: Vec<Certificate>,
    _session_keys: Vec<sop::SessionKey>,
    decryption_keys: Vec<Certificate>,
    key_passwords: Vec<sop::Password>, // Passwords for asymmetric component key material
    skesk_passwords: Vec<sop::Password>,
}

impl Decrypt {
    pub(crate) fn new() -> Self {
        Default::default()
    }
}

impl<'a> sop::ops::Decrypt<'a, RPGSOPOCT, Certs, Keys> for Decrypt {
    fn verify_not_before(
        self: Box<Self>,
        _t: SystemTime,
    ) -> Box<dyn sop::ops::Decrypt<'a, RPGSOPOCT, Certs, Keys> + 'a> {
        todo!();

        // self.verify.not_before = Some(t);
        // self
    }

    fn verify_not_after(
        self: Box<Self>,
        _t: SystemTime,
    ) -> Box<dyn sop::ops::Decrypt<'a, RPGSOPOCT, Certs, Keys> + 'a> {
        todo!()

        // self.verify.not_after = Some(t);
        // self
    }

    fn verify_with_certs(
        mut self: Box<Self>,
        certs: &Certs,
    ) -> sop::Result<Box<dyn sop::ops::Decrypt<'a, RPGSOPOCT, Certs, Keys> + 'a>> {
        certs.certs.iter().for_each(|c| self.verify.push(c.clone()));
        Ok(self)
    }

    fn with_session_key(
        self: Box<Self>,
        _session_key: sop::SessionKey,
    ) -> sop::Result<Box<dyn sop::ops::Decrypt<'a, RPGSOPOCT, Certs, Keys> + 'a>> {
        todo!()

        // self.session_keys.push(sk);
        // Ok(self)
    }

    fn with_password(
        mut self: Box<Self>,
        password: sop::Password,
    ) -> sop::Result<Box<dyn sop::ops::Decrypt<'a, RPGSOPOCT, Certs, Keys> + 'a>> {
        self.skesk_passwords.push(password);
        Ok(self)
    }

    fn with_keys(
        mut self: Box<Self>,
        keys: &Keys,
    ) -> sop::Result<Box<dyn sop::ops::Decrypt<'a, RPGSOPOCT, Certs, Keys> + 'a>> {
        keys.keys
            .iter()
            .for_each(|tsk| self.decryption_keys.push(tsk.clone()));
        Ok(self)
    }

    fn with_key_password(
        mut self: Box<Self>,
        password: sop::Password,
    ) -> sop::Result<Box<dyn sop::ops::Decrypt<'a, RPGSOPOCT, Certs, Keys> + 'a>> {
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

struct CardPkeskDecryptor<'cs, 't> {
    cardslot: CardSlot<'cs, 't>,
}

impl PkeskDecryptor for CardPkeskDecryptor<'_, '_> {
    fn decrypt(&self, pkesk: &PublicKeyEncryptedSessionKey) -> Option<PlainSessionKey> {
        if let Ok((session_key, session_key_algorithm)) = self
            .cardslot
            .unlock(String::new, |priv_key| priv_key.decrypt(pkesk.values()?))
        {
            Some(PlainSessionKey::V3_4 {
                key: session_key,
                sym_alg: session_key_algorithm,
            })
        } else {
            None
        }
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
        let (mut iter, _header) = Message::from_reader_many(self.ciphertext).expect("FIXME");

        if let Some(Ok(msg)) = iter.next() {
            for cert in &self.decrypt.decryption_keys {
                for dec in Checked::from(cert).valid_encryption_capable_component_keys() {
                    if let Some(mut card) = card_by_pp(
                        dec.public_params(),
                        openpgp_card::ocard::KeyType::Decryption,
                    )
                    .expect("fixme")
                    {
                        // FIXME: this calls unpack once per card, which is weird?

                        let mut tx = card.transaction().expect("fixme");
                        verify_pin_from_card_state(tx.card(), false).expect("fixme");

                        // FIXME: allow users to pass in a touch prompt?
                        let cs = CardSlot::init_from_card(
                            &mut tx,
                            openpgp_card::ocard::KeyType::Decryption,
                            &|| {},
                        )
                        .expect("fixme");

                        let card_decryptor = Box::new(CardPkeskDecryptor { cardslot: cs });

                        let Ok(mr) = rpgpie::message::unpack(
                            msg,
                            &[card_decryptor as Box<dyn PkeskDecryptor>],
                            vec![], // we don't do skesk
                            &self.decrypt.verify,
                        ) else {
                            // FIXME: we failed to use cards, for some reason, this error isn't appropriate here
                            return Err(sop::errors::Error::KeyIsProtected);
                        };

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

                        return Ok((session_key, verifications));
                    }
                }
            }

            unimplemented!();
        } else {
            panic!("no message found");
        }
    }
}
