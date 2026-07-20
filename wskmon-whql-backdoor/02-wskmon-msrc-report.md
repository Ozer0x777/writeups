# Signalement MSRC : Driver kernel signé WHQL abusé comme backdoor réseau

**Destinataire :** Microsoft Security Response Center (MSRC)
**Plateforme :** https://msrc.microsoft.com/report (ou secure@microsoft.com)
**Objet :** Malicious WHQL-signed kernel driver actively abusing attestation signing, certificate still valid, SHA-256 included
**Date :** 2026-07-18
**Analyste :** Gordon PEIRS

---

To the Microsoft Security Response Center,

I am an independent malware analyst reporting a Windows kernel-mode driver that carries a currently valid WHQL (Windows Hardware Compatibility Publisher) signature while functioning as a network-resident backdoor. A public technical writeup already exists ([Nextron Systems, 26 June 2026](https://www.nextron-systems.com/2026/06/26/anatomy-of-a-whql-signed-windows-filtering-platform-wfp-kernel-resident-network-backdoor)); this report adds independent verification and several technical details not previously documented, and, most importantly, the certificate has not yet been revoked as of this writing.

## Summary

| Field | Value |
|---|---|
| File name | `wskmon.sys` |
| SHA-256 | `495c7e5513fa7766c236e76d8520139139fc4ad7203ddcb2ccdae17bdb691979` |
| Imphash | `5c6478fa51bfe6402aa0892dc333f989` |
| Compile timestamp | 2026-04-04 13:05:19 UTC |
| First public sighting | 2026-06-15 (per ReversingLabs), MalwareBazaar 2026-06-27 |
| Function | Kernel-mode network backdoor: remote code execution, arbitrary file write, shellcode injection into `svchost.exe`, triggered by a magic-byte sequence hidden in raw TCP or HTTP POST traffic |
| Current detection | Effectively undetected, treated as legitimate by most AV engines at time of analysis, precisely because of the valid signature |

## Certificate details : the actionable issue

The Authenticode signature (extracted directly from the file's Security directory, independently parsed with both OpenSSL and Python's `cryptography` library) contains two X.509 certificates, both issued by Microsoft:

| Field | Value |
|---|---|
| Signing certificate subject | Microsoft Windows Hardware Compatibility Publisher |
| Issuer | Microsoft Windows Third Party Component CA 2012 |
| Valid from | 2025-11-13 |
| **Valid to** | **2026-11-10, confirmed still valid: checked live against your own CRL (`Microsoft Windows Third Party Component CA 2012.crl`, last updated 2026-05-07), this serial number does not appear in the revoked list.** |
| Serial number | `330000013c4a61fb3578d2b6dd00000000013c` |
| Thumbprint (SHA256) | `2e8072ded075c6b6c0df8c364e9d12319577114991f2455ebc4b364b367f7dba` |

**Submitter identity note:** the name 深圳市奥联信息安全技术有限公司 (Shenzhen Aolian Information Security Technology Co., Ltd), which appears in third-party writeups as the certificate "subject," is not present as an X.509 Subject field in either embedded certificate, I want to be precise about this since it affects how your team should interpret it. The string is present in the file (UTF-16BE, offset 0x6543 in the Security directory), consistent with the Authenticode **SpcSpOpusInfo** signed attribute (the submitter-supplied "program name" field, the one surfaced in the Windows "Digital Signature Details" dialog), not the certificate itself. This still ties the submission to that name, but the distinction matters for your investigation: the entity that supplied this program name at submission time may or may not be the same entity whose Dev Center account credentials were actually used.

**This certificate should be revoked.** It is actively signing a functioning kernel backdoor, and remains valid for nearly four more months as of this writing.

## This is not an isolated incident : the same certificate has signed at least two other files

Searching MalwareBazaar by certificate serial number (rather than file hash or imphash) surfaces two additional files carrying the identical signature, neither mentioned in the public Nextron writeup:

| File | SHA-256 | Imphash | First seen | Reporter |
|---|---|---|---|---|
| `devhost.sys` | `ee8844ffd3879190fb389b0f613cb2dcdcd83375cf0a6994170a648c5ca8c479` | `fb7c5ff17455f725aa59f998a0f324ca` | 2026-04-22 | smica83 |
| `844ljfpvz.sys` | `1d9224a72e64bb2aad289edc81ea0720c764511c3e2b5beb5d0d5ce82a719abd` | `7282cc9e51cb73de8f89c7740b0e69fb` | 2026-06-19 | smica83 |
| `wskmon.sys` (this report) | `495c7e5513fa7766c236e76d8520139139fc4ad7203ddcb2ccdae17bdb691979` | `5c6478fa51bfe6402aa0892dc333f989` | 2026-06-27 | GDHJDSYDH1 |

Three distinct imphashes indicate three separate builds, not the same payload recompiled. This certificate has been used to sign malicious/suspicious drivers across a span of **over two months of public sightings** (2026-04-22 through 2026-06-27) and **nearly three months of compile timestamps** (2026-01-17 through 2026-04-15), surfaced independently by two different researchers.

**I have now reverse-engineered `devhost.sys` as well, and the finding materially changes the scope of this report.** It is not another network backdoor, it is a generic physical-memory read/write primitive:

- At the end of `DriverEntry`, it directly reads the `CR3` and `CR4` control registers and stores them in a context structure returned to the caller.
- Unlike `wskmon.sys`, it creates both an NT device object (`\Device\devhost`) *and* a DOS symbolic link (`\??\devhost`), making it directly accessible from user mode via `\\.\devhost` with a real IOCTL handler (`wskmon.sys`'s device object, by contrast, accepts no real I/O, every request is stubbed to succeed without processing).
- Its core routine walks a caller-supplied buffer in 4KB chunks, using `IoAllocateMdl` → `MmProbeAndLockPages` → system-space mapping → copy → `MmUnlockPages` → `IoFreeMdl` for each page, the standard MDL technique for temporarily mapping arbitrary physical memory into kernel address space to read or write it.

Exposed CR3 plus an arbitrary physical memory read/write primitive, reachable from user mode, is sufficient to manually map and execute a second driver in kernel memory without going through Windows' normal, signature-checked driver loader, a well-known technique (similar in spirit to public "manual mapping" tools such as kdmapper) for bypassing Driver Signature Enforcement. I cannot prove a direct loading relationship between `devhost.sys` and `wskmon.sys` beyond the shared certificate, but the capability is exactly what such a loader would need, and the compile date (January 2026) precedes `wskmon.sys` (April 2026) by nearly three months, consistent with tooling built first and reused later.

The third file, `844ljfpvz.sys`, is minimal (four functions) and makes a single call to the undocumented `ZwSetSystemInformation` with information class `75` and a hardcoded 24-byte structure tagged with the magic value `"BSBS"`. I have not been able to determine this class's function from reliable public documentation and am not speculating on it here.

**Taken together, this certificate has signed what looks like a small toolkit**, a memory read/write primitive, a network backdoor, and a third undetermined component, developed and reused over at least several months, not a single opportunistic abuse. Full technical detail on `devhost.sys` and `844ljfpvz.sys` is in the attached writeup (`writeup.md`, sections 12-14).

**One more finding relevant to your investigation of the submitting account: this is likely not a single actor.** Comparing MSVC Rich header compiler/linker fingerprints across the three files, `wskmon.sys` and `devhost.sys` share the same primary compiler build (33145), with only the linker sub-build differing (35725 vs 35214), consistent with the same developer/machine across the roughly 2.5 months separating their compile dates. `844ljfpvz.sys` uses an entirely different, unrelated toolchain fingerprint (27412/30159), and, unlike the other two, leaks a full PDB path: `F:\0316 桌面\QDDDD\驱动最新加绘制-改PTE方案\x64\Release\NewDriverMMM.pdb`. The vocabulary (`绘制` = on-screen rendering, `改PTE方案` = "modified PTE scheme") is characteristic of the Chinese game-cheat-development community, not espionage or financially-motivated crime tooling. This suggests the compromised signing access may have been shared or resold to more than one unrelated developer, similar to the 2022 POORTRY/STONESTOP pattern where a single signing pipeline served multiple paying customers. Your investigation of the Dev Center account may want to look for evidence of a broker/reseller relationship rather than assuming a single operator.

## Why I believe this is a compromised/abused account, not a complicit vendor

Shenzhen Aolian Information Security is an established, internationally recognized cryptography company (founded 2009, a designated commercial cryptography unit under China's State Cryptography Administration, with SM9 algorithm contributions adopted by ISO/IEEE/3GPP/IETF). This does not fit the profile of a shell entity created solely to obtain a fraudulent signing certificate.

The pattern here closely matches the December 2022 POORTRY/STONESTOP incident (UNC3944), where Mandiant and SentinelOne found that Microsoft Partner Center accounts, some legitimate and compromised, some knowingly complicit, operating through a "driver-signing-as-a-service" broker other threat actors paid to access, were used to obtain attestation signatures for malicious kernel drivers. I would ask that your investigation determine whether Aolian's Hardware Dev Center account was compromised, and notify them directly if so, rather than treating them as the responsible party without further evidence.

Notably, this driver was compiled in **April 2026**, after Microsoft's own announcement of stricter WHCP requirements and the removal of trust for legacy cross-signed drivers, meaning this specific abuse occurred against the hardened process, not the deprecated one.

## Technical summary (full detail in attached writeup)

- **Delivery mechanism:** registers a WFP (Windows Filtering Platform) callout at the `FWPM_LAYER_STREAM_V4` layer, inspecting reassembled TCP streams for a magic byte sequence (`7F 4E 54 46`), either at the start of a raw stream or within the first 1024 bytes of an HTTP POST body.
- **Authentication:** HMAC-SHA256 via CNG, verified before any command is processed.
- **Payload:** XOR-encrypted with a 32-byte hardcoded key.
- **Capabilities:** (1) remote code execution via `WinExec` resolved from a target process's PEB, (2) arbitrary file write with `OBJ_KERNEL_HANDLE` (invisible to user-mode handle enumeration), (3) raw shellcode injection, both (1) and (3) targeting an `svchost.exe` instance specifically verified to run under the SYSTEM account (SID S-1-5-18, confirmed via `SeQueryInformationToken(TokenUser)`).
- **Notable engineering detail:** when the documented `MmGetSystemRoutineAddress` API resolution path fails, the driver falls back to manually rebuilding the System Service Descriptor Table by reading the `IA32_LSTAR` MSR and pattern-matching the kernel's syscall dispatcher, a technique requiring genuine low-level Windows internals expertise, not commodity malware tooling.
- **No outbound C2, no persistence mechanism, no local IOCTL interface** are present in this file, it is a payload component, dropped and loaded by an external, currently unidentified component.

## Request

1. **Revoke certificate** thumbprint `2e8072ded075c6b6c0df8c364e9d12319577114991f2455ebc4b364b367f7dba` (serial `330000013c4a61fb3578d2b6dd00000000013c`).
2. **Investigate the submitting Hardware Dev Center account**, submission history, other drivers signed through the same account, and whether access was obtained fraudulently or through compromise.
3. **Notify Shenzhen Aolian Information Security Technology Co., Ltd** if their account or certificate access was compromised, independent of any action taken against the certificate itself.
4. Consider whether this warrants addition to the Microsoft vulnerable/malicious driver blocklist (the mechanism referenced in your April 2026 driver policy announcement), for all three known hashes (`wskmon.sys`, `devhost.sys`, `844ljfpvz.sys`), not just the one analyzed in depth here.

**Proof of concept:** I have reconstructed the full trigger protocol (magic bytes, HMAC-SHA256 authentication with the extracted secret key, XOR-encrypted payload) into a standalone Python packet builder, available on request. It only constructs and displays packets by default, it does not target or send anything without an explicit, manually confirmed destination. I have not run it against any live system; it is offered as evidence that the protocol I've described is complete and internally consistent, not as a claim of having exploited any machine.

I am available to provide the full technical writeup, IOCs, or any additional detail your team needs.

Respectfully submitted,
Gordon PEIRS
Independent Malware Analyst
