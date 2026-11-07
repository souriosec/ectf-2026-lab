# Analysis context
2026 eCTF reference firmware on MSPM0L2228 (Cortex-M0+, Thumb v6-M), 32-bit bare metal with 32 KiB SRAM.
Treat host and peer UART input as untrusted. Trace packet framing through handlers, authorization, filesystem metadata, and flash writes.
Review lengths, capacities, names, slots, parser errors, timeouts, integrity and confidentiality.
CRYPTO_EXAMPLE=0 excludes simple_crypto.c. Precompiled SDK libraries have no source-analysis coverage.
Only synthetic build inputs are used. Report candidate defects and uncertainty; no firmware execution or board access is part of this workflow.
