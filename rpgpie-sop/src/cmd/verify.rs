// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io;
use std::time::SystemTime;

use rpgpie::key::checked::CheckedCertificate;
use rpgpie::key::Certificate;

use crate::util::to_verification;
use crate::{Certs, Sigs, RPGSOP};

#[derive(Default)]
pub(crate) struct Verify {
    _not_before: Option<SystemTime>,
    _not_after: Option<SystemTime>,
    pub(crate) certs: Vec<Certificate>,
}

impl Verify {
    pub(crate) fn new() -> Self {
        Default::default()
    }
}

impl<'a> sop::ops::Verify<'a, RPGSOP, Certs, Sigs> for Verify {
    fn not_before(
        self: Box<Self>,
        _t: SystemTime,
    ) -> Box<dyn sop::ops::Verify<'a, RPGSOP, Certs, Sigs> + 'a> {
        todo!()

        // self.not_before = Some(t);
        // self
    }

    fn not_after(
        self: Box<Self>,
        _t: SystemTime,
    ) -> Box<dyn sop::ops::Verify<'a, RPGSOP, Certs, Sigs> + 'a> {
        todo!()

        // self.not_after = Some(t);
        // self
    }

    fn certs(
        mut self: Box<Self>,
        cert: &Certs,
    ) -> sop::Result<Box<dyn sop::ops::Verify<'a, RPGSOP, Certs, Sigs> + 'a>> {
        cert.certs.iter().for_each(|c| self.certs.push(c.clone()));

        Ok(self)
    }

    fn signatures<'s>(
        self: Box<Self>,
        signatures: &'s Sigs,
    ) -> sop::Result<Box<dyn sop::ops::VerifySignatures<'s> + 's>>
    where
        'a: 's,
    {
        Ok(Box::new(VerifySignatures {
            verify: *self,
            signatures,
        }))
    }
}

struct VerifySignatures<'s> {
    verify: Verify,
    signatures: &'s Sigs,
}

impl sop::ops::VerifySignatures<'_> for VerifySignatures<'_> {
    fn data(
        self: Box<Self>,
        data: &mut (dyn io::Read + Send + Sync),
    ) -> sop::Result<Vec<sop::ops::Verification>> {
        if self.verify.certs.is_empty() {
            return Err(sop::errors::Error::MissingArg);
        }

        let mut verifications = vec![];

        // FIXME: stream input data?
        let mut payload = vec![];
        data.read_to_end(&mut payload)?;

        for sig in &self.signatures.sigs {
            for cert in &self.verify.certs {
                let ccert: CheckedCertificate = cert.into();

                // Verify at signature creation time.
                // FIXME: does the signature need to be valid "now", as well?
                let reference = sig.created().expect("FIXME");

                ccert
                    .valid_signing_capable_component_keys_at(reference)
                    .iter()
                    .filter(|c| c.verify(sig, &payload).is_ok())
                    .map(|ckp| to_verification(sig, cert, ckp))
                    .for_each(|v| verifications.push(v));
            }
        }

        if verifications.is_empty() {
            Err(sop::errors::Error::NoSignature)
        } else {
            Ok(verifications)
        }
    }
}
