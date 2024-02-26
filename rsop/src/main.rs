// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: CC0-1.0

fn main() {
    env_logger::init();
    sop::cli::main(&rpgpie_sop::RPGSOP::default());
}
