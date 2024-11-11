// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{Certs, Keys, RPGSOP};

pub(crate) struct ExtractCert {}

impl ExtractCert {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

impl sop::ops::ExtractCert<'_, RPGSOP, Certs, Keys> for ExtractCert {
    fn keys(self: Box<Self>, keys: &Keys) -> sop::Result<Certs> {
        Ok(Certs {
            certs: keys.keys.iter().map(Into::into).collect(),
            source_name: None,
        })
    }
}
