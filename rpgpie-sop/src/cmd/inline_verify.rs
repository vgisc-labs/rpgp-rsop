// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::default::Default;
use std::io;
use std::io::BufRead;

use pgp::packet::LiteralData;
use pgp::{Any, Deserializable, Message};
use rpgpie::key::checked::CheckedCertificate;
use rpgpie::key::component::ComponentKeyPub;
use rpgpie::key::Certificate;
use rpgpie::msg::MessageResult;

use crate::{util, Certs, RPGSOP};

#[derive(Default)]
pub(crate) struct InlineVerify {
    _not_before: Option<std::time::SystemTime>,
    _not_after: Option<std::time::SystemTime>,
    certs: Vec<Certificate>,
}

impl InlineVerify {
    pub(crate) fn new() -> Self {
        Default::default()
    }
}

impl<'a> sop::ops::InlineVerify<'a, RPGSOP, Certs> for InlineVerify {
    fn not_before(
        self: Box<Self>,
        _t: std::time::SystemTime,
    ) -> Box<dyn sop::ops::InlineVerify<'a, RPGSOP, Certs> + 'a> {
        todo!()

        // self.not_before = Some(t);
        // self
    }

    fn not_after(
        self: Box<Self>,
        _t: std::time::SystemTime,
    ) -> Box<dyn sop::ops::InlineVerify<'a, RPGSOP, Certs> + 'a> {
        todo!()

        // self.not_after = Some(t);
        // self
    }

    fn certs(
        mut self: Box<Self>,
        certs: &Certs,
    ) -> sop::Result<Box<dyn sop::ops::InlineVerify<'a, RPGSOP, Certs> + 'a>> {
        certs
            .certs
            .iter()
            .for_each(|cert| self.certs.push(cert.clone()));

        Ok(self)
    }

    fn message<'d>(
        self: Box<Self>,
        data: &'d mut (dyn io::Read + Send + Sync),
    ) -> sop::Result<Box<dyn sop::ops::Ready<Vec<sop::ops::Verification>> + 'd>>
    where
        'a: 'd,
    {
        Ok(Box::new(InlineVerifyReady {
            inline_verify: *self,
            data,
        }))
    }
}

struct InlineVerifyReady<'a> {
    inline_verify: InlineVerify,
    data: &'a mut (dyn io::Read + Send + Sync),
}

fn verify_msg(
    msg: Message,
    sink: &mut (dyn io::Write + Send + Sync),
    certs: &[Certificate],
) -> sop::Result<Vec<sop::ops::Verification>> {
    let mr = rpgpie::msg::unpack(msg, &[], vec![], vec![], certs).expect("FIXME");

    if !mr.validated.is_empty() {
        sink.write_all(mr.cleartext.data()).expect("FIXME");

        Ok(util::result_to_verifications(&mr))
    } else {
        Err(sop::errors::Error::NoSignature)
    }
}

impl sop::ops::Ready<Vec<sop::ops::Verification>> for InlineVerifyReady<'_> {
    fn to_writer(
        self: Box<Self>,
        sink: &mut (dyn io::Write + Send + Sync),
    ) -> sop::Result<Vec<sop::ops::Verification>> {
        let mut reader = io::BufReader::new(self.data);

        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            panic!("empty input");
        }

        if buf[0] & 0x80 != 0 {
            // the input seems to be binary data - presumably an unarmored signed message
            let msg = Message::from_bytes(reader).expect("FIXME");

            verify_msg(msg, sink, &self.inline_verify.certs)
        } else {
            let (pgp, _) = pgp::Any::from_armor(reader).expect("foo");

            match pgp {
                Any::Cleartext(csf) => {
                    // CSF
                    let validated: Vec<(Certificate, ComponentKeyPub, pgp::Signature)> = self
                        .inline_verify
                        .certs
                        .iter()
                        .flat_map(|c| {
                            let cc: CheckedCertificate = c.into();
                            let verifiers = cc.valid_signing_capable_component_keys_at(
                                &chrono::offset::Utc::now(),
                            );
                            let verified: Vec<_> = verifiers
                                .iter()
                                .flat_map(|v| {
                                    v.verify_csf(&csf).ok().map(|s| {
                                        (
                                            c.clone(),
                                            v.as_componentkey().clone(),
                                            s.clone().signature,
                                        )
                                    })
                                })
                                .collect();
                            verified
                        })
                        .collect();

                    if !validated.is_empty() {
                        let text = csf.signed_text();
                        sink.write_all(text.as_bytes()).expect("FIXME");

                        let mr = MessageResult {
                            session_key: None,
                            cleartext: LiteralData::from_str("", &text),
                            validated,
                        };
                        Ok(util::result_to_verifications(&mr))
                    } else {
                        Err(sop::errors::Error::NoSignature)
                    }
                }
                Any::Message(msg) => verify_msg(msg, sink, &self.inline_verify.certs),
                _ => panic!("unexpected data type"),
            }
        }
    }
}
