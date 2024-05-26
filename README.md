<!--
SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: CC0-1.0
-->

# rsop and rpgpie-sop

- [rsop](rsop/) is a "Stateless OpenPGP" (SOP) CLI tool.
- [rpgpie-sop](rpgpie-sop/) is the basis of rsop; a SOP library wrapper for [rpgpie 🦀️🔐🥧](https://codeberg.org/heiko/rpgpie).

```mermaid
flowchart TD
    RSOP["rsop <br/> (SOP CLI tool)"] --> RPIESOP
    RPIESOP["rpgpie-sop <br/> (SOP interface wrapper for rpgpie)"] --> RPIE
    RPIE["rpgpie <br/> (Experimental high level OpenPGP API)"] --> RPGP
    RPGP["rPGP <br/> (OpenPGP implementation)"]
    RPIE  --> OCR["openpgp-card-rpgp"] --> RPGP
    OCR --> OC["openpgp-card"]
    RPIE --> OCS["openpgp-card-state <br/> (User PIN management)"]
```

rsop and rpgpie-sop are based on:

- [rPGP](https://github.com/rpgp/rpgp/), a production-grade implementation of low-level OpenPGP functionality.
- [rpgpie 🦀️🔐🥧](https://codeberg.org/heiko/rpgpie), an experimental higher level OpenPGP API based on rpgp.
