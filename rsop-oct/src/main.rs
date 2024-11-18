// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: CC0-1.0

fn main() {
    #[cfg(feature = "cliv")]
    let variant = sop::cli::Variant::Verification;

    #[cfg(feature = "cli")]
    let variant = sop::cli::Variant::Full;

    env_logger::init();
    sop::cli::main(&mut rpgpie_sop_oct::RPGSOPOCT::default(), variant);
}
