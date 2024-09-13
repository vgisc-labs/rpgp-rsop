// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use pgp::armor::BlockType;
use pgp::types::Tag;
use std::io::{BufRead, BufReader, Read, Write};
use std::ops::DerefMut;
use std::sync::Mutex;

#[derive(Default)]
pub(crate) struct Armor {
    label: sop::ops::ArmorLabel,
}

impl Armor {
    pub(crate) fn new() -> Self {
        Default::default()
    }
}

impl<'a> sop::ops::Armor<'a> for Armor {
    fn label(
        mut self: Box<Self>,
        label: sop::ops::ArmorLabel,
    ) -> Box<dyn sop::ops::Armor<'a> + 'a> {
        self.label = label;
        self
    }

    fn data<'d>(
        self: Box<Self>,
        data: &'d mut (dyn Read + Send + Sync),
    ) -> sop::Result<Box<dyn sop::ops::Ready + 'd>>
    where
        'a: 'd,
    {
        Ok(Box::new(ArmorReady { armor: self, data }))
    }
}

struct ArmorReady<'a> {
    armor: Box<Armor>,
    data: &'a mut (dyn Read + Send + Sync),
}

impl<'a> sop::ops::Ready for ArmorReady<'a> {
    fn to_writer(self: Box<Self>, mut sink: &mut (dyn Write + Send + Sync)) -> sop::Result<()> {
        let mut reader = BufReader::new(self.data);

        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(());
        }

        if buf[0] & 0x80 == 0 {
            // the input don't seem to be binary pgp data -> just pass it through
            std::io::copy(&mut reader, &mut sink).expect("FIXME");
        } else {
            let label = if self.armor.label == sop::ops::ArmorLabel::Auto {
                // autodetect type
                encoded_type_id_to_label(buf[0])?
            } else {
                self.armor.label
            };

            let typ = blocktype_try_from(label)?;

            let input = SerializableBinary {
                data: Box::new(Mutex::new(&mut reader)),
            };

            // TODO: don't write out checksum for v6 artifacts?

            pgp::armor::write(&input, typ, &mut sink, None, true).expect("FIXME")
        }

        Ok(())
    }
}

/// Glue between a raw reader and [pgp::armor::write]
struct SerializableBinary<'a> {
    data: Box<Mutex<&'a mut dyn Read>>,
}

impl pgp::ser::Serialize for SerializableBinary<'_> {
    fn to_writer<W: Write>(&self, w: &mut W) -> pgp::errors::Result<()> {
        let mut reader = self.data.lock().unwrap();

        std::io::copy(reader.deref_mut(), w)
            .map_err(|e| pgp::errors::Error::IOError { source: e })?;

        Ok(())
    }
}

// Produce the equivalent pgp::armor::reader::BlockType
//
// NOTE: Panics for sop::ops::ArmorLabel::Auto
fn blocktype_try_from(label: sop::ops::ArmorLabel) -> sop::Result<BlockType> {
    match label {
        sop::ops::ArmorLabel::Auto => unimplemented!("this should never happen"),
        sop::ops::ArmorLabel::Cert => Ok(BlockType::PublicKey),
        sop::ops::ArmorLabel::Key => Ok(BlockType::PrivateKey),
        sop::ops::ArmorLabel::Message => Ok(BlockType::Message),
        sop::ops::ArmorLabel::Sig => Ok(BlockType::Signature),
    }
}

// autodetect ArmorLabel from "Encoded Packet Type ID"
fn encoded_type_id_to_label(byte: u8) -> sop::Result<sop::ops::ArmorLabel> {
    let tag = from_encoded_type_id(byte)?;

    match tag {
        Tag::SecretKey => Ok(sop::ops::ArmorLabel::Key),
        Tag::PublicKey => Ok(sop::ops::ArmorLabel::Cert),
        Tag::PublicKeyEncryptedSessionKey | Tag::SymKeyEncryptedSessionKey => {
            Ok(sop::ops::ArmorLabel::Message)
        }
        Tag::OnePassSignature => Ok(sop::ops::ArmorLabel::Message),

        Tag::Signature => {
            // TODO: distinguish 'just a bunch of signatures' from 'old-style signed message':

            // If the packet stream contains only Signature packets, it should be parsed as a
            // SIGNATURES input (with Armor Header BEGIN PGP SIGNATURE).

            // If it contains any packet other than a Signature packet, it should be parsed as
            // an INLINESIGNED input (with Armor Header BEGIN PGP MESSAGE).

            Ok(sop::ops::ArmorLabel::Sig)
        }

        _ => Err(sop::errors::Error::BadData),
    }
}

fn from_encoded_type_id(byte: u8) -> sop::Result<Tag> {
    if byte & 0x80 == 0 {
        return Err(sop::errors::Error::BadData);
    }

    match byte & 0x40 {
        0 => {
            //   Legacy format:
            //     Bit 7 -- always one
            //     Bit 6 -- always zero
            //     Bits 5 to 2 -- Packet Type ID
            //     Bits 1 to 0 -- length-type

            let tag = byte.checked_shr(2).expect("2 bits") & 0b00001111;

            Ok(tag.into())
        }
        _ => {
            //   OpenPGP format:
            //     Bit 7 -- always one
            //     Bit 6 -- always one
            //     Bits 5 to 0 -- Packet Type ID

            let tag = byte & 0b00111111;

            Ok(tag.into())
        }
    }
}

#[test]
fn test_from_encoded_type_id() {
    // OpenPGP format
    assert_eq!(
        from_encoded_type_id(0b11000001).ok(),
        Some(Tag::PublicKeyEncryptedSessionKey)
    );

    // Legacy format
    assert_eq!(
        from_encoded_type_id(0b10000100).ok(),
        Some(Tag::PublicKeyEncryptedSessionKey)
    );

    // Bit 7 is zero -> bad data
    assert!(matches!(
        from_encoded_type_id(0b00000100),
        Err(sop::errors::Error::BadData)
    ));
}
