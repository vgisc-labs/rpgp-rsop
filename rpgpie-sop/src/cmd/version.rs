// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub struct Version {}

impl Version {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

impl sop::ops::Version<'_> for Version {
    fn frontend(&self) -> sop::Result<sop::ops::VersionInfo> {
        Ok(sop::ops::VersionInfo {
            name: env!("CARGO_PKG_NAME").into(),
            version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    fn backend(&self) -> sop::Result<sop::ops::VersionInfo> {
        Ok(sop::ops::VersionInfo {
            name: "rpgpie".into(),
            version: rpgpie::VERSION.into(),
        })
    }

    // FIXME: Is there a way to get the actual rpgp version reported, here?
    fn extended(&self) -> sop::Result<String> {
        Ok([""].join("\n"))
    }
}
