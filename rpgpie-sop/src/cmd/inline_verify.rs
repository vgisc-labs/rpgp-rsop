// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::default::Default;
use std::io;

use pgp::{Deserializable, Message};
use rpgpie::key::Certificate;
use rpgpie::msg::{csf, MessageResult};

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

impl sop::ops::Ready<Vec<sop::ops::Verification>> for InlineVerifyReady<'_> {
    fn to_writer(
        self: Box<Self>,
        sink: &mut (dyn io::Write + Send + Sync),
    ) -> sop::Result<Vec<sop::ops::Verification>> {
        // FIXME: process input data in streaming mode
        let c = util::load(self.data)?;

        if let Ok(csf) = csf::CleartextSignedMessage::read(c.clone()) {
            // CSF
            let validated = csf.check(&self.inline_verify.certs);
            if validated.is_empty() {
                return Err(sop::errors::Error::NoSignature);
            }

            let cleartext = csf.text();
            sink.write_all(cleartext.data()).expect("FIXME");

            let mr = MessageResult {
                session_key: None,
                cleartext,
                validated,
            };
            Ok(util::result_to_verifications(&mr))
        } else {
            // Regular inline message
            let (msg, _header) = Message::from_reader_single(c).unwrap();

            let mr = rpgpie::msg::unpack(msg, &[], vec![], vec![], &self.inline_verify.certs)
                .expect("FIXME");
            sink.write_all(mr.cleartext.data()).expect("FIXME");

            if mr.validated.is_empty() {
                Err(sop::errors::Error::NoSignature)
            } else {
                Ok(util::result_to_verifications(&mr))
            }
        }
    }
}
