# FBI IC3 Report : Efimer Campaign

**To:** FBI Internet Crime Complaint Center  
**Platform:** https://www.ic3.gov (online complaint form)  
**Or direct:** cywatch@ic3.gov  
**Subject:** Active Cryptoclipping Campaign + WordPress Botnet, Likely US-Based Actor (Efimer/ClickFix)  
**Date:** 2026-07-17  
**Analyst:** Gordon PEIRS

---

To the Internet Crime Complaint Center (IC3),

I am an independent malware analyst reporting an active criminal campaign targeting cryptocurrency users through "ClickFix" social engineering. The technical indicators suggest a US-based threat actor.

## Why This May Concern Your Jurisdiction

Timezone analysis of build artifacts points to UTC-5 or UTC-6 (US Eastern/Central time):

- **psutil library** (compiled by the attacker from source): PE timestamp `2026-01-22 02:52 UTC` → 21:52 EST or 20:52 CST, consistent with an evening development session
- **Two BTC deposit sources** are large-volume exchanges operating in regulated jurisdictions, likely including the United States

## Summary

| Field | Value |
|-------|-------|
| Malware family | Efimer (dropper + clipboard hijacker + WordPress botnet) |
| Delivery method | ClickFix social engineering (malicious web page) |
| Active since | 2026-07-12 (100+ samples, 1 build/hour cadence) |
| SHA-256 | `a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4` |
| C2 infrastructure | Full Tor v3 (3 independent hidden services) |
| Victims targeted | Any Windows user copying a cryptocurrency address |

## KYC-Actionable Financial Leads

**Attacker's primary BTC wallet:**
`bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0`
(active since March 2025, ≥14 months of confirmed criminal activity)

**Source 1, 2025-03-26:**
- Address: `bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h`
- Total received: 59,571,438 BTC / 2,274,664 TX (cumulative lifetime inflow, not a balance, see note*)
- Classification: Top-tier exchange (Binance/Coinbase volume range)
- Amount sent to attacker: 0.00096260 BTC

**Source 2, 2026-05-30 (same day as malware build):**
- Address: `bc1qx9n80t5q7tfmutzaj0ramzzzsvtveara68zntc`
- Total received: 628,396 BTC / 18,675 TX / 1,448-address cluster (cumulative lifetime inflow*)
- Classification: Major regulated exchange with mandatory KYC
- Amount sent to attacker: 0.00444391 BTC (via relay `bc1qgrnp6...`)

*Note: these totals are the `funded_txo_sum` field from public block explorers, the sum of everything an address has ever received over its lifetime, not a current balance. On a high-turnover exchange hub address (millions of transactions), the same BTC cycles through the same address thousands of times over years, so the cumulative figure legitimately exceeds the 21M BTC supply cap without any calculation error. Cross-checked live against mempool.space.

**Actionable:** The attacker has verified accounts at both exchanges. A subpoena or MLAT request to the exchange operators would yield:
- KYC identity documents
- IP addresses used for login
- Bank account or fiat withdrawal destination

**BTC withdrawal chain documented:**
```
Attacker (bc1qz33n9...) → bc1q5acrlm0j5ljh2t4fpmxasaeaqkc5j32z5h634y (cleared in 90 min)
                        → bc1qns9f7yfx3ry9lj6yz7c9er0vwa0ye2eklpzqfw
                          (15,228,010 BTC cumulative received, likely Binance hot wallet pool)
```

## Attacker Addresses (all hardcoded in binary)

| Format | Address |
|--------|---------|
| BTC P2PKH | `12FfZsjyDri1ir3EUU85pRE5quUEPY5Qf4` |
| BTC P2SH | `32ozR62LxL6ynHYBHZhCz5faRjhYrmNheW` |
| BTC Bech32 | `bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0` |
| TRX | `TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82` |
| XMR | `87Y35DbRFf2G2PyghoVAox4tsxfxqwjZh3AMaxrkjasBNW4rmQWs9hfanP5haACxfnXrKPZoesSP18XciY8xVaoY5MLitaW` |

## Build Machine Artifacts (OPSEC Leak)

The malware inadvertently contains the attacker's full build environment embedded in an internal Python module (`campus.py`):

| Field | Value |
|-------|-------|
| Hostname | `DESKTOP-UOB4Aig` |
| Hardware | Intel Arrow Lake (Core Ultra 200, released Oct 2024), 8 physical cores, personal workstation, not a cloud VM |
| OS | Windows 10/11 |
| Username | `User` (generic, likely pseudonym) |
| Build date | 2026-05-30 04:49:41 UTC |
| Build path | `C:\Users\User\Desktop\pyinstaller-6.20.0\` |
| Tools | Python 3.13, VS Code, Node.js, Go, LLVM/Clang, WireGuard VPN |

## USDT Laundering Chain

```
Attacker wallet: TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82
  ← 11.54 USDT  2026-01-21  (from exchange)
  ← 24.09 USDT  2026-02-05  (from exchange)
  ← 10.01 USDT  2026-03-30  (relay wallet)
  ← 330.00 USDT 2026-05-04  (from TTgSknazmXS4..., likely MaaS customer)
  → 375.64 USDT 2026-05-13  → TY9wnbgAynRM... (single-use relay)
                              → TDoXUNZ6PajKuiUkcYg3EDSV9bnqGqsbcf
                                (FixedFloat Exchange hot wallet, no-KYC)
```

## C2 Infrastructure

| Role | Tor v3 Address |
|------|---------------|
| Clipper (exfil) | `hek5ensy7wqqls2cafflihs7sdqr4dwxux47vp3k7pgffeasxsfeeyid.onion/route.php` |
| Clipper (updates) | `swjxev2rvxfivi2wvkxre5vaxkjeepxzxva4u4ydm2qbkbakh6wnyead.onion/core/repla.php` |
| WordPress botnet | `gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad.onion/route.php` |

**ed25519 server keys (cryptographic C2 identities):**

| Server | Public Key |
|--------|-----------|
| Clipper exfil | `3915d23658fda105cb42014ab41e5f90e11e0ed7a5f9fabf6afbcc529012bc8a` |
| Clipper update | `9593725751adca8aa356aaaf1276a0ba92423ef9bd41ca730366a015040a3fac` |
| WordPress botnet | `315d0912cf977f7162ee20d64d187ddbbc9693d8eb61d21f5d6515285b349e61` |

## Full Technical Report Available

A complete 18-section technical writeup is available including:
- Full deobfuscated C2 communication logic
- YARA rule (matches 100+ samples, file `efimer_dropper.yar`)
- Daily persistence IoC table (2026-07-12 through 2026-07-31)
- Blockchain flow graph with all transaction hashes
- Complete build environment documentation

Sample is publicly available on MalwareBazaar (tag: `efimer`).

I am available to provide any additional technical documentation required for an investigation.

Respectfully submitted,  
Gordon PEIRS  
Independent Malware Analyst
