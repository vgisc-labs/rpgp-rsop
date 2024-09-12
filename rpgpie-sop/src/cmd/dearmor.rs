// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io;

#[derive(Default)]
pub(crate) struct Dearmor {}

impl Dearmor {
    pub(crate) fn new() -> Self {
        Default::default()
    }
}

impl<'a> sop::ops::Dearmor<'a> for Dearmor {
    fn data<'d>(
        self: Box<Self>,
        data: &'d mut (dyn io::Read + Send + Sync),
    ) -> sop::Result<Box<dyn sop::ops::Ready + 'd>>
    where
        'a: 'd,
    {
        Ok(Box::new(DearmorReady { data }))
    }
}

struct DearmorReady<'a> {
    data: &'a mut (dyn io::Read + Send + Sync),
}

impl<'a> sop::ops::Ready for DearmorReady<'a> {
    fn to_writer(self: Box<Self>, mut sink: &mut (dyn io::Write + Send + Sync)) -> sop::Result<()> {
        let mut buf = io::BufReader::new(self.data);

        if is_binary(&mut buf)? {
            // the input is binary data -> just pass it through
            std::io::copy(&mut buf, &mut sink).expect("FIXME");
        } else {
            let mut dearmor = pgp::armor::Dearmor::new(buf);
            std::io::copy(&mut dearmor, &mut sink).expect("FIXME");
        }

        Ok(())
    }
}

/// Check if the OpenPGP data in `input` seems to be ASCII-armored or binary (by looking at the
/// highest bit of the first byte)
///
/// We consider an empty stream to be "binary", here.
fn is_binary<R: std::io::BufRead>(input: &mut R) -> sop::Result<bool> {
    // Peek at the first byte in the reader
    let buf = input.fill_buf()?;
    if buf.is_empty() {
        return Ok(true);
    }

    // If the first bit of the first byte is set, we assume this is binary OpenPGP data, otherwise
    // we assume it is ASCII-armored.
    let binary = buf[0] & 0x80 != 0;

    Ok(binary)
}
