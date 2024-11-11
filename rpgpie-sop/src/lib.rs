// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod cmd;
mod util;

use std::io;

use pgp::Signature;
use rpgpie::certificate::Certificate;
use rpgpie::tsk::Tsk;
use sop::ops::{CertifyUserID, MergeCerts, UpdateKey, ValidateUserID};

#[derive(Clone, Copy, Default)]
pub struct RPGSOP {}

// SOP singleton
const SOP: RPGSOP = RPGSOP {};

pub struct Certs {
    certs: Vec<Certificate>,
    source_name: Option<String>,
}

pub struct Keys {
    keys: Vec<Tsk>,
    source_name: Option<String>,
}

pub struct Sigs {
    sigs: Vec<Signature>,
    source_name: Option<String>,
}

impl sop::SOP<'_> for RPGSOP {
    type Keys = Keys;
    type Certs = Certs;
    type Sigs = Sigs;

    fn version(&'_ self) -> sop::Result<Box<dyn sop::ops::Version>> {
        Ok(Box::new(cmd::version::Version::new()))
    }

    fn sopv_version(&self) -> sop::Result<&'static str> {
        Ok("1.0")
    }

    fn generate_key(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::GenerateKey<Self, Self::Keys> + '_>> {
        Ok(Box::new(cmd::generate::GenerateKey::new()))
    }

    fn change_key_password(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::ChangeKeyPassword<Self, Self::Keys>>> {
        Ok(Box::new(cmd::password::ChangeKeyPassword::new()))
    }

    fn revoke_key(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::RevokeKey<Self, Self::Certs, Self::Keys>>> {
        Ok(Box::new(cmd::revoke_key::RevokeKey::new()))
    }

    fn extract_cert(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::ExtractCert<Self, Self::Certs, Self::Keys> + '_>> {
        Ok(Box::new(cmd::extract_cert::ExtractCert::new()))
    }

    fn sign(&'_ self) -> sop::Result<Box<dyn sop::ops::Sign<Self, Self::Keys, Self::Sigs> + '_>> {
        Ok(Box::new(cmd::sign::Sign::new()))
    }

    fn verify(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::Verify<Self, Self::Certs, Self::Sigs> + '_>> {
        Ok(Box::new(cmd::verify::Verify::new()))
    }

    fn encrypt(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::Encrypt<Self, Self::Certs, Self::Keys> + '_>> {
        Ok(Box::new(cmd::encrypt::Encrypt::new()))
    }

    fn decrypt(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::Decrypt<Self, Self::Certs, Self::Keys> + '_>> {
        Ok(Box::new(cmd::decrypt::Decrypt::new()))
    }

    fn armor(&'_ self) -> sop::Result<Box<dyn sop::ops::Armor>> {
        Ok(Box::new(cmd::armor::Armor::new()))
    }

    fn dearmor(&'_ self) -> sop::Result<Box<dyn sop::ops::Dearmor>> {
        Ok(Box::new(cmd::dearmor::Dearmor::new()))
    }

    fn inline_detach(&'_ self) -> sop::Result<Box<dyn sop::ops::InlineDetach<Self::Sigs>>> {
        Ok(Box::new(cmd::detach::InlineDetach::new()))
    }

    fn inline_verify(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::InlineVerify<Self, Self::Certs> + '_>> {
        Ok(Box::new(cmd::inline_verify::InlineVerify::new()))
    }

    fn inline_sign(&'_ self) -> sop::Result<Box<dyn sop::ops::InlineSign<Self, Self::Keys> + '_>> {
        Ok(Box::new(cmd::inline_sign::InlineSign::new()))
    }

    fn update_key(&'_ self) -> sop::Result<Box<dyn UpdateKey<Self, Self::Certs, Self::Keys> + '_>> {
        todo!()
    }

    fn merge_certs(&'_ self) -> sop::Result<Box<dyn MergeCerts<Self, Self::Certs> + '_>> {
        todo!()
    }

    fn certify_userid(
        &'_ self,
    ) -> sop::Result<Box<dyn CertifyUserID<Self, Self::Certs, Self::Keys> + '_>> {
        todo!()
    }

    fn validate_userid(&'_ self) -> sop::Result<Box<dyn ValidateUserID<Self, Self::Certs> + '_>> {
        todo!()
    }
}

impl sop::Load<'_, RPGSOP> for Certs {
    fn from_reader(
        _sop: &RPGSOP,
        mut source: &mut (dyn io::Read + Send + Sync),
        source_name: Option<String>,
    ) -> sop::Result<Self> {
        let certs = Certificate::load(&mut source).expect("FIXME");

        Ok(Certs { certs, source_name })
    }

    fn source_name(&self) -> Option<&str> {
        self.source_name.as_deref()
    }
}

impl sop::Save for Certs {
    fn to_writer(
        &self,
        armored: bool,
        sink: &mut (dyn io::Write + Send + Sync),
    ) -> sop::Result<()> {
        Certificate::save_all(&self.certs, armored, sink).expect("FIXME");

        Ok(())
    }
}

impl sop::Load<'_, RPGSOP> for Keys {
    fn from_reader(
        _sop: &'_ RPGSOP,
        mut source: &mut (dyn io::Read + Send + Sync),
        source_name: Option<String>,
    ) -> sop::Result<Self> {
        let keys = Tsk::load(&mut source).expect("FIXME");

        Ok(Keys { keys, source_name })
    }

    fn source_name(&self) -> Option<&str> {
        self.source_name.as_deref()
    }
}

impl sop::Save for Keys {
    fn to_writer(
        &self,
        armored: bool,
        sink: &mut (dyn io::Write + Send + Sync),
    ) -> sop::Result<()> {
        Tsk::save_all(&self.keys, armored, sink).expect("FIXME");

        Ok(())
    }
}

impl sop::Load<'_, RPGSOP> for Sigs {
    fn from_reader(
        _sop: &'_ RPGSOP,
        mut source: &mut (dyn io::Read + Send + Sync),
        source_name: Option<String>,
    ) -> sop::Result<Self> {
        let sigs = rpgpie::signature::load(&mut source).expect("FIXME");

        Ok(Sigs { sigs, source_name })
    }

    fn source_name(&self) -> Option<&str> {
        self.source_name.as_deref()
    }
}

impl sop::Save for Sigs {
    fn to_writer(
        &self,
        armored: bool,
        mut sink: &mut (dyn io::Write + Send + Sync),
    ) -> sop::Result<()> {
        rpgpie::signature::save(&self.sigs, armored, &mut sink).expect("FIXME");

        Ok(())
    }
}

impl<'s> sop::plumbing::SopRef<'s, RPGSOP> for Certs {
    fn sop(&self) -> &'s RPGSOP {
        &SOP
    }
}

impl<'s> sop::plumbing::SopRef<'s, RPGSOP> for Keys {
    fn sop(&self) -> &'s RPGSOP {
        &SOP
    }
}

impl<'s> sop::plumbing::SopRef<'s, RPGSOP> for Sigs {
    fn sop(&self) -> &'s RPGSOP {
        &SOP
    }
}
