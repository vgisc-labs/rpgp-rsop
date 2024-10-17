// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod card;
mod cmd;
mod util;

use std::io;

use pgp::Signature;
use rpgpie::certificate::Certificate;

#[derive(Clone, Copy, Default)]
pub struct RPGSOPOCT {}

// SOP singleton
const SOP: RPGSOPOCT = RPGSOPOCT {};

pub struct Certs {
    certs: Vec<Certificate>,
}

pub struct Keys {
    keys: Vec<Certificate>, // certificates that are backed by keys on OpenPGP cards
}

pub struct Sigs {
    sigs: Vec<Signature>,
}

impl sop::SOP<'_> for RPGSOPOCT {
    type Keys = Keys;
    type Certs = Certs;
    type Sigs = Sigs;

    fn version(&'_ self) -> sop::Result<Box<dyn sop::ops::Version>> {
        Ok(Box::new(cmd::version::Version::new()))
    }

    fn generate_key(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::GenerateKey<Self, Self::Keys> + '_>> {
        todo!()
    }

    fn sign(&'_ self) -> sop::Result<Box<dyn sop::ops::Sign<Self, Self::Keys, Self::Sigs> + '_>> {
        Ok(Box::new(cmd::sign::Sign::new()))
    }

    fn inline_sign(&'_ self) -> sop::Result<Box<dyn sop::ops::InlineSign<Self, Self::Keys> + '_>> {
        Ok(Box::new(cmd::inline_sign::InlineSign::new()))
    }

    fn decrypt(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::Decrypt<Self, Self::Certs, Self::Keys> + '_>> {
        Ok(Box::new(cmd::decrypt::Decrypt::new()))
    }

    // Operations that don't involve private key material, based on rpgpie-sop

    fn change_key_password(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::ChangeKeyPassword<Self, Self::Keys>>> {
        unimplemented!()
    }

    fn revoke_key(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::RevokeKey<Self, Self::Certs, Self::Keys>>> {
        unimplemented!()
    }

    fn extract_cert(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::ExtractCert<Self, Self::Certs, Self::Keys> + '_>> {
        unimplemented!()
    }

    fn verify(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::Verify<Self, Self::Certs, Self::Sigs> + '_>> {
        unimplemented!()
    }

    fn encrypt(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::Encrypt<Self, Self::Certs, Self::Keys> + '_>> {
        unimplemented!()
    }

    fn armor(&'_ self) -> sop::Result<Box<dyn sop::ops::Armor>> {
        unimplemented!()
    }

    fn dearmor(&'_ self) -> sop::Result<Box<dyn sop::ops::Dearmor>> {
        unimplemented!()
    }

    fn inline_detach(&'_ self) -> sop::Result<Box<dyn sop::ops::InlineDetach<Self::Sigs>>> {
        unimplemented!()
    }

    fn inline_verify(
        &'_ self,
    ) -> sop::Result<Box<dyn sop::ops::InlineVerify<Self, Self::Certs> + '_>> {
        unimplemented!()
    }
}

impl sop::Load<'_, RPGSOPOCT> for Certs {
    fn from_reader(
        _sop: &RPGSOPOCT,
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
        Certificate::save_all(&self.certs, armored, sink).expect("FIXME");

        Ok(())
    }
}

impl sop::Load<'_, RPGSOPOCT> for Keys {
    fn from_reader(
        _sop: &'_ RPGSOPOCT,
        mut source: &mut (dyn io::Read + Send + Sync),
    ) -> sop::Result<Self> {
        let keys = Certificate::load(&mut source).expect("FIXME");

        Ok(Keys { keys })
    }
}

impl sop::Save for Keys {
    fn to_writer(
        &self,
        _armored: bool,
        _sink: &mut (dyn io::Write + Send + Sync),
    ) -> sop::Result<()> {
        unimplemented!()
    }
}

impl sop::Load<'_, RPGSOPOCT> for Sigs {
    fn from_reader(
        _sop: &'_ RPGSOPOCT,
        mut source: &mut (dyn io::Read + Send + Sync),
    ) -> sop::Result<Self> {
        let sigs = rpgpie::signature::load(&mut source).expect("FIXME");

        Ok(Sigs { sigs })
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

impl<'s> sop::plumbing::SopRef<'s, RPGSOPOCT> for Certs {
    fn sop(&self) -> &'s RPGSOPOCT {
        &SOP
    }
}

impl<'s> sop::plumbing::SopRef<'s, RPGSOPOCT> for Keys {
    fn sop(&self) -> &'s RPGSOPOCT {
        &SOP
    }
}

impl<'s> sop::plumbing::SopRef<'s, RPGSOPOCT> for Sigs {
    fn sop(&self) -> &'s RPGSOPOCT {
        &SOP
    }
}
