// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod cmd;
mod util;

use std::io;

use pgp::Signature;
use rpgpie::key::{Certificate, Tsk};

#[derive(Clone, Copy, Default)]
pub struct RPGSOP {}

// SOP singleton
const SOP: RPGSOP = RPGSOP {};

pub struct Certs {
    certs: Vec<Certificate>,
}

pub struct Keys {
    keys: Vec<Tsk>,
}

pub struct Sigs {
    sigs: Vec<Signature>,
}

impl sop::SOP<'_> for RPGSOP {
    type Keys = Keys;
    type Certs = Certs;
    type Sigs = Sigs;

    fn version(&'_ self) -> sop::Result<Box<dyn sop::ops::Version>> {
        Ok(Box::new(cmd::version::Version::new()))
    }

    fn generate_key(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::GenerateKey<Self, Self::Keys> + '_>> {
        Ok(Box::new(cmd::generate::GenerateKey::new()))
    }

    fn change_key_password(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::ChangeKeyPassword<Self, Self::Keys>>> {
        todo!()
    }

    fn revoke_key(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::RevokeKey<Self, Self::Certs, Self::Keys>>> {
        todo!()
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
        todo!()
    }

    fn dearmor(&'_ self) -> sop::Result<Box<dyn sop::ops::Dearmor>> {
        todo!()
    }

    fn inline_detach(&'_ self) -> sop::Result<Box<dyn sop::ops::InlineDetach<Self::Sigs>>> {
        todo!()
    }

    fn inline_verify(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::InlineVerify<Self, Self::Certs> + '_>> {
        Ok(Box::new(cmd::inline_verify::InlineVerify::new()))
    }

    fn inline_sign(&'_ self) -> sop::Result<Box<dyn sop::ops::InlineSign<Self, Self::Keys> + '_>> {
        Ok(Box::new(cmd::inline_sign::InlineSign::new()))
    }
}

impl sop::Load<'_, RPGSOP> for Certs {
    fn from_reader(
        _sop: &RPGSOP,
        mut source: &mut (dyn io::Read + Send + Sync),
    ) -> sop::Result<Self> {
        let certs = Certificate::load(&mut source).expect("FIXME");

        Ok(Certs { certs })
    }
}

impl sop::Save for Certs {
    fn to_writer(
        &self,
        armored: bool,
        sink: &mut (dyn io::Write + Send + Sync),
    ) -> sop::Result<()> {
        Certificate::save(&self.certs, armored, sink).expect("FIXME");

        Ok(())
    }
}

impl sop::Load<'_, RPGSOP> for Keys {
    fn from_reader(
        _sop: &'_ RPGSOP,
        mut source: &mut (dyn io::Read + Send + Sync),
    ) -> sop::Result<Self> {
        let keys = Tsk::load(&mut source).expect("FIXME");

        Ok(Keys { keys })
    }
}

impl sop::Save for Keys {
    fn to_writer(
        &self,
        armored: bool,
        sink: &mut (dyn io::Write + Send + Sync),
    ) -> sop::Result<()> {
        Tsk::save(&self.keys, armored, sink).expect("FIXME");

        Ok(())
    }
}

impl sop::Load<'_, RPGSOP> for Sigs {
    fn from_reader(
        _sop: &'_ RPGSOP,
        mut source: &mut (dyn io::Read + Send + Sync),
    ) -> sop::Result<Self> {
        let sigs = rpgpie::sig::load(&mut source).expect("FIXME");

        Ok(Sigs { sigs })
    }
}

impl sop::Save for Sigs {
    fn to_writer(
        &self,
        armored: bool,
        mut sink: &mut (dyn io::Write + Send + Sync),
    ) -> sop::Result<()> {
        rpgpie::sig::save(&self.sigs, armored, &mut sink).expect("FIXME");

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
