// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{BufRead, BufReader, Read, Write};

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
        data: &'d mut (dyn Read + Send + Sync),
    ) -> sop::Result<Box<dyn sop::ops::Ready + 'd>>
    where
        'a: 'd,
    {
        Ok(Box::new(DearmorReady { data }))
    }
}

struct DearmorReady<'a> {
    data: &'a mut (dyn Read + Send + Sync),
}

impl<'a> sop::ops::Ready for DearmorReady<'a> {
    fn to_writer(self: Box<Self>, mut sink: &mut (dyn Write + Send + Sync)) -> sop::Result<()> {
        let mut reader = BufReader::new(self.data);

        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(());
        }

        if buf[0] & 0x80 != 0 {
            // the input seems to be binary data -> just pass it through
            std::io::copy(&mut reader, &mut sink).expect("FIXME");
        } else {
            let mut dearmor = pgp::armor::Dearmor::new(reader);
            std::io::copy(&mut dearmor, &mut sink).expect("FIXME");
        }

        Ok(())
    }
}
