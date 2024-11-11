// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io;

use pgp::cleartext::CleartextSignedMessage;
use pgp::packet::{LiteralData, Packet};
use pgp::ser::Serialize;
use pgp::types::PublicKeyTrait;
use pgp::{ArmorOptions, Deserializable, Message};
use rpgpie::tsk::DataSigner;

use crate::cmd::sign::Sign;
use crate::{Keys, RPGSOP};

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

impl<'a> sop::ops::InlineSign<'a, RPGSOP, Keys> for InlineSign {
    fn no_armor(mut self: Box<Self>) -> Box<dyn sop::ops::InlineSign<'a, RPGSOP, Keys> + 'a> {
        self.armor = false;
        self
    }

    fn mode(
        mut self: Box<Self>,
        mode: sop::ops::InlineSignAs,
    ) -> Box<dyn sop::ops::InlineSign<'a, RPGSOP, Keys> + 'a> {
        self.mode = mode;
        self
    }

    fn keys(
        mut self: Box<Self>,
        keys: &Keys,
    ) -> sop::Result<Box<dyn sop::ops::InlineSign<'a, RPGSOP, Keys> + 'a>> {
        self.sign.add_signing_keys(keys)?;
        Ok(self)
    }

    fn with_key_password(
        mut self: Box<Self>,
        password: sop::Password,
    ) -> sop::Result<Box<dyn sop::ops::InlineSign<'a, RPGSOP, Keys> + 'a>> {
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

        // Passwords to try
        let pws: Vec<&[u8]> = if self.inline_sign.sign.with_key_password.is_empty() {
            vec![&[]]
        } else {
            self.inline_sign
                .sign
                .with_key_password
                .iter()
                .map(sop::plumbing::PasswordsAreHumanReadable::normalized)
                .collect()
        };

        let mut datasigners: Vec<DataSigner> = vec![];
        for tsk in self.inline_sign.sign.signers {
            let mut s: Vec<DataSigner> = tsk.signing_capable_component_keys().collect();

            if s.is_empty() {
                panic!(
                    "no signing capable component key found for signer {:02x?}",
                    tsk.key().fingerprint()
                );
            }

            datasigners.append(&mut s);
        }

        let lit = match &self.inline_sign.mode {
            sop::ops::InlineSignAs::Binary => LiteralData::from_bytes("".into(), &data),
            sop::ops::InlineSignAs::Text => {
                LiteralData::from_str("", &String::from_utf8(data).expect("FIXME"))
            }
            sop::ops::InlineSignAs::ClearSigned => {
                let signers = |text: &[u8]| {
                    let lit = Message::Literal(LiteralData::from_str(
                        [],
                        core::str::from_utf8(text).expect("FIXME"),
                    ));

                    let mut sigs = vec![];

                    for ds in datasigners {
                        let mut sig = None;

                        // try all passwords for this DataSigner
                        'pws: for pw in &pws {
                            let res = ds.sign_msg(
                                lit.clone(),
                                || String::from_utf8_lossy(pw).to_string(),
                                hash_algo,
                            );

                            if let Ok(Message::Signed { signature, .. }) = res {
                                sig = Some(signature);
                                break 'pws; // we found a working password for ds, stop trying more
                            }
                        }

                        if let Some(s) = sig {
                            sigs.push(s);
                        }
                    }

                    Ok(sigs)
                };

                let text = core::str::from_utf8(&data).expect("FIXME");
                let csf = CleartextSignedMessage::new_many(text, signers).expect("FIXME");

                csf.to_armored_writer(&mut sink, ArmorOptions::default())
                    .expect("FIXME");

                return Ok(());
            }
        };

        let mut packets = vec![];
        packets.push(Packet::from(lit.clone()));

        let lit_msg = Message::Literal(lit);

        for ds in datasigners {
            let sig = pws
                .iter()
                .flat_map(|pw| {
                    ds.sign_msg(
                        lit_msg.clone(),
                        || String::from_utf8_lossy(pw).to_string(),
                        hash_algo,
                    )
                })
                .next();

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
