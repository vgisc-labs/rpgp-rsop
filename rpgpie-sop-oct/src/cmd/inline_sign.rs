// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io;

use openpgp_card_rpgp::CardSlot;
use pgp::cleartext::CleartextSignedMessage;
use pgp::packet::{LiteralData, Packet};
use pgp::ser::Serialize;
use pgp::{ArmorOptions, Deserializable, Message};
use rand::thread_rng;
use rpgpie::certificate::Checked;
use rpgpie::ComponentKeyPub;

use crate::card::{card_by_pp, verify_pin_from_card_state};
use crate::cmd::sign::Sign;
use crate::{card, Keys, RPGSOPOCT};

pub(crate) struct InlineSign {
    armor: bool,
    sign: Sign,
    mode: sop::ops::InlineSignAs,
}

impl InlineSign {
    pub(crate) fn new() -> Self {
        Self {
            armor: true,
            sign: Sign::new(),
            mode: Default::default(),
        }
    }
}

impl<'a> sop::ops::InlineSign<'a, RPGSOPOCT, Keys> for InlineSign {
    fn no_armor(mut self: Box<Self>) -> Box<dyn sop::ops::InlineSign<'a, RPGSOPOCT, Keys> + 'a> {
        self.armor = false;
        self
    }

    fn mode(
        mut self: Box<Self>,
        mode: sop::ops::InlineSignAs,
    ) -> Box<dyn sop::ops::InlineSign<'a, RPGSOPOCT, Keys> + 'a> {
        self.mode = mode;
        self
    }

    fn keys(
        mut self: Box<Self>,
        keys: &Keys,
    ) -> sop::Result<Box<dyn sop::ops::InlineSign<'a, RPGSOPOCT, Keys> + 'a>> {
        self.sign.add_signing_keys(keys)?;
        Ok(self)
    }

    fn with_key_password(
        mut self: Box<Self>,
        password: sop::Password,
    ) -> sop::Result<Box<dyn sop::ops::InlineSign<'a, RPGSOPOCT, Keys> + 'a>> {
        self.sign.with_key_password.push(password);
        Ok(self)
    }

    fn data<'d>(
        self: Box<Self>,
        data: &'d mut (dyn io::Read + Send + Sync),
    ) -> sop::Result<Box<dyn sop::ops::Ready + 'd>>
    where
        'a: 'd,
    {
        if self.sign.signers.is_empty() {
            return Err(sop::errors::Error::MissingArg);
        }

        if !self.armor && matches!(self.mode, sop::ops::InlineSignAs::ClearSigned) {
            return Err(sop::errors::Error::IncompatibleOptions);
        }

        Ok(Box::new(InlineSignReady {
            inline_sign: *self,
            data,
        }))
    }
}

struct InlineSignReady<'a> {
    inline_sign: InlineSign,
    data: &'a mut (dyn io::Read + Send + Sync),
}

impl<'a> sop::ops::Ready for InlineSignReady<'a> {
    fn to_writer(self: Box<Self>, mut sink: &mut (dyn io::Write + Send + Sync)) -> sop::Result<()> {
        let mut data = vec![];
        self.data.read_to_end(&mut data)?;

        let hash_algo = self
            .inline_sign
            .sign
            .hash_algos
            .first()
            .cloned()
            .unwrap_or_default();

        assert!(!self.inline_sign.sign.signers.is_empty()); // FIXME

        let mut signers: Vec<ComponentKeyPub> = vec![];
        for cert in self.inline_sign.sign.signers {
            let ccert: Checked = (&cert).into();

            let mut keys: Vec<ComponentKeyPub> = ccert
                .valid_signing_capable_component_keys_at(&chrono::offset::Utc::now())
                .iter()
                .map(|x| x.as_componentkey().clone())
                .collect();

            if keys.is_empty() {
                panic!(
                    "no signing capable component key found for signer {:02x?}",
                    cert.fingerprint()
                );
            }

            signers.append(&mut keys);
        }

        let lit = match &self.inline_sign.mode {
            sop::ops::InlineSignAs::Binary => LiteralData::from_bytes("".into(), &data),
            sop::ops::InlineSignAs::Text => {
                LiteralData::from_str("", &String::from_utf8(data).expect("FIXME"))
            }
            sop::ops::InlineSignAs::ClearSigned => {
                let body = String::from_utf8(data).expect("foo");

                let sgnrs = |text: &[u8]| {
                    let lit = Message::Literal(LiteralData::from_str(
                        [],
                        core::str::from_utf8(text).expect("FIXME"),
                    ));

                    let mut sigs = vec![];

                    for ckp in signers {
                        if let Some(mut card) =
                            card_by_pp(ckp.public_params(), openpgp_card::ocard::KeyType::Signing)
                                .expect("FIXME")
                        {
                            let mut tx = card.transaction().expect("FIXME");
                            verify_pin_from_card_state(tx.card(), true).expect("FIXME");

                            // FIXME: allow users to pass in a touch prompt?
                            let cs = CardSlot::init_from_card(
                                &mut tx,
                                openpgp_card::ocard::KeyType::Signing,
                                &|| {},
                            )?;

                            let res =
                                lit.clone()
                                    .sign(&mut thread_rng(), &cs, String::new, hash_algo);

                            if let Ok(Message::Signed { signature, .. }) = res {
                                sigs.push(signature);
                            } else {
                                unimplemented!("failed to sign") // FIXME
                            }
                        } else {
                            panic!("Card not found")
                        }
                    }

                    Ok(sigs)
                };

                let csf = CleartextSignedMessage::new_many(&body, sgnrs).expect("FIXME");

                csf.to_armored_writer(&mut sink, ArmorOptions::default())
                    .expect("FIXME");

                return Ok(());
            }
        };

        let mut packets = vec![];
        packets.push(Packet::from(lit.clone()));

        let lit_msg = Message::Literal(lit);

        for signer in signers {
            let pp = signer.public_params();

            let sig = card::sign_on_card(&lit_msg, pp, hash_algo, &|| {}).ok();

            if let Some(sig) = sig {
                if let Message::Signed {
                    one_pass_signature,
                    signature,
                    ..
                } = sig
                {
                    if let Some(mut ops) = one_pass_signature {
                        if packets.len() > 1 {
                            // only the innermost signature should be marked "last",
                            // so we mark all others as non-last.
                            ops.last = 0;
                        }
                        packets.insert(0, Packet::from(ops));
                    }

                    packets.push(Packet::from(signature));
                }
            } else {
                panic!("foo");
            }
        }

        let signed = Message::from_packets(packets.into_iter().map(Ok).peekable())
            .next()
            .expect("should be a message")
            .expect("FIXME");

        match self.inline_sign.armor {
            true => signed
                .to_armored_writer(&mut sink, ArmorOptions::default())
                .expect("FIXME"),
            false => signed.to_writer(&mut sink).expect("FIXME"),
        }

        Ok(())
    }
}
