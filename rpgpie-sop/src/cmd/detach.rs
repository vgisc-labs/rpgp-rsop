// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{BufRead, Read, Write};

use pgp::{Deserializable, Message, Signature};

use crate::Sigs;

#[derive(Default)]
pub(crate) struct InlineDetach {}

impl InlineDetach {
    pub(crate) fn new() -> Self {
        Default::default()
    }
}

impl<'a> sop::ops::InlineDetach<'a, Sigs> for InlineDetach {
    fn message<'d>(
        self: Box<Self>,
        data: &'d mut (dyn Read + Send + Sync),
    ) -> sop::Result<Box<dyn sop::ops::Ready<Sigs> + 'd>>
    where
        'a: 'd,
    {
        Ok(Box::new(InlineDetachReady { data }))
    }
}

struct InlineDetachReady<'d> {
    data: &'d mut (dyn Read + Send + Sync),
}

impl sop::ops::Ready<Sigs> for InlineDetachReady<'_> {
    fn to_writer(self: Box<Self>, sink: &mut (dyn Write + Send + Sync)) -> sop::Result<Sigs> {
        // Helper: Get the plaintext and list of signatures for a signed message.
        // The message may contain compression layers and multiple signatures.
        //
        // TODO: upstream to rpgpie / DRY with msg.rs
        fn unwrap_signed(msg: Message) -> sop::Result<(Vec<u8>, Vec<Signature>)> {
            unwrap_signed_internal(msg, vec![], 0)
        }

        fn unwrap_signed_internal(
            msg: Message,
            mut sigs: Vec<Signature>,
            depth: usize,
        ) -> sop::Result<(Vec<u8>, Vec<Signature>)> {
            if depth > 10 {
                // FIXME: how to handle excessive message layering?
                return Err(sop::errors::Error::BadData);
            };

            match msg {
                Message::Compressed(cd) => {
                    let payload = cd.decompress().expect("FIXME");
                    let msg = Message::from_bytes(payload).expect("FIXME");

                    unwrap_signed_internal(msg, sigs, depth + 1)
                }
                Message::Signed {
                    message, signature, ..
                } => {
                    sigs.push(signature);
                    unwrap_signed_internal(*message.expect("FIXME"), sigs, depth + 1)
                }
                Message::Literal(lit) => Ok((lit.data().to_vec(), sigs)),
                Message::Encrypted { .. } => Err(sop::errors::Error::BadData),
            }
        }

        // FIXME: DRY message loading against inline_verify!
        let mut reader = std::io::BufReader::new(self.data);

        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            panic!("empty input");
        }

        let (payload, sigs) = if buf[0] & 0x80 != 0 {
            // the input seems to be binary data - presumably an unarmored signed message
            let msg = Message::from_bytes(reader).expect("FIXME");

            unwrap_signed(msg)?
        } else {
            let (pgp, _) = pgp::Any::from_armor(reader).expect("FIXME");

            match pgp {
                pgp::Any::Message(msg) => unwrap_signed(msg)?,
                pgp::Any::Cleartext(csf) => {
                    let payload = csf.signed_text().as_bytes().to_vec();
                    let sigs = csf
                        .signatures()
                        .iter()
                        .map(|s| s.signature.clone())
                        .collect();

                    (payload, sigs)
                }

                _ => panic!("unexpected data type"),
            }
        };

        sink.write_all(&payload).expect("FIXME");

        Ok(Sigs {
            sigs,
            source_name: None,
        })
    }
}
