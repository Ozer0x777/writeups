# Abuse Report : FixedFloat Exchange

**To:** abuse@fixedfloat.com  
**Subject:** Abuse Report, Criminal Funds Deposited 2026-05-13, 375 USDT TRC-20, Active Malware Campaign  
**Date:** 2026-07-17  
**Analyst:** Gordon PEIRS

---

To the FixedFloat Compliance/Abuse Team,

I am reporting criminal proceeds deposited into your platform as part of an active malware campaign (cryptocurrency clipboard hijacker + WordPress botnet, family "Efimer").

## Transaction Details

| Field | Value |
|-------|-------|
| Date | 2026-05-13 |
| Amount | 375.64 USDT (TRC-20 / TRON network) |
| Sending address | `TY9wnbgAynRMse2UHC3boo28UFQNnJLiTu` (wallet created same day as transfer, single-use relay) |
| Your hot wallet | `TDoXUNZ6PajKuiUkcYg3EDSV9bnqGqsbcf` (confirmed as FixedFloat hot wallet via Tronscan entity tagging) |

**Full transaction chain:**

```
TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82   ← attacker's wallet
  (received 375 USDT from victims across 4 transactions:
   +11.54 USDT  2026-01-21
   +24.09 USDT  2026-02-05
   +10.01 USDT  2026-03-30
   +330.00 USDT 2026-05-04  ← single payment, probable MaaS sale)
        │
        ▼ 2026-05-13, full withdrawal of 375.64 USDT
TY9wnbgAynRMse2UHC3boo28UFQNnJLiTu   ← single-use relay (created same day)
        │
        ▼
TDoXUNZ6PajKuiUkcYg3EDSV9bnqGqsbcf   ← your hot wallet
```

## Context : Active Malware Campaign

The wallet `TAwHPzmZC7rv` is hardcoded as the primary TRON address in an active malware dropper currently distributing at a rate of approximately 1 build per hour since 2026-07-12.

| Field | Value |
|-------|-------|
| Malware family | Efimer (ClickFix dropper) |
| SHA-256 | `a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4` |
| Campaign start | 2026-07-12 |
| Confirmed samples | 100+ (MalwareBazaar, tag: `efimer`) |
| Malware function | Clipboard hijacker replacing cryptocurrency addresses in real time (BTC, TRX, XMR) + WordPress bruteforce botnet |

The 330 USDT payment received on 2026-05-04 from `TTgSknazmXS4Pgvdfa8kmFaBiXumLcatLq` (a wallet created 2026-04-20 with 68 transactions and ~6,000 USDT of daily volume) is consistent with a Malware-as-a-Service sale, a third party paid the attacker for access to the malware or botnet.

## Additional Attacker Addresses for Reference

| Format | Address |
|--------|---------|
| BTC P2PKH | `12FfZsjyDri1ir3EUU85pRE5quUEPY5Qf4` |
| BTC P2SH | `32ozR62LxL6ynHYBHZhCz5faRjhYrmNheW` |
| BTC Bech32 | `bc1qz33n9xuqkxl7wxy8j0n4haapr73w64umdj7tw0` |
| TRX (primary) | `TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82` |
| TRX (relay) | `TY9wnbgAynRMse2UHC3boo28UFQNnJLiTu` |

## Request

1. **Please preserve** all records associated with the deposit from `TY9wnbgAynRM` into `TDoXUNZ6Paj` on 2026-05-13, including any KYC data, IP addresses, email addresses, or linked accounts.

2. **If this transaction was converted** to BTC or another asset, please identify the destination address if technically possible.

3. **Please consider flagging** `TAwHPzmZC7rvCKiLmRnr458xZH1D8M5c82` and `TY9wnbgAynRMse2UHC3boo28UFQNnJLiTu` to reject or hold any future deposits from these addresses.

I am available to provide the full 18-section technical report, YARA detection rules, and complete blockchain flow documentation to assist your compliance team or any law enforcement agency you coordinate with.

The malware sample and full analysis are publicly available on MalwareBazaar (tag: `efimer`, SHA-256: `a9b557921c40fd625b775e66d6fd99807058133057e94ee7483990f10817fdb4`).

Thank you for your cooperation.

Gordon PEIRS  
Independent Malware Analyst
