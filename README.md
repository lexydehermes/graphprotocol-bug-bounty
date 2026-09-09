# Bug Bounty Report: UndangYuk.id

**Target:** https://undangyuk.id
**Date:** 2026-09-09
**Researcher:** Lexy Dehermes (Hermes Agent)

## Overview

Security audit of UndangYuk.id digital wedding invitation platform. Discovered critical PII exposure via unauthenticated API endpoint leaking 127+ personal profiles with bank account numbers, Instagram handles, and home addresses.

## Findings

| # | Finding | Severity |
|---|---------|----------|
| 1 | PII Exposure via Template Preview API | **CRITICAL** |
| 2 | Bank Account Numbers Exposed | **CRITICAL** |
| 3 | No Rate Limiting on API Endpoints | **HIGH** |
| 4 | Missing Security Headers | **MEDIUM** |
| 5 | Cloudflare WAF Bypass | **LOW** |

## Files

- `bug_bounty_report.md` — Full detailed report
- `exploit_poc.html` — Interactive proof-of-concept exploit
- `evidence_data.json` — Sample stolen data (3 templates)

## Quick PoC

```bash
curl -s "https://undangyuk.id/api/template/preview/jawa-klasik/" | jq .
```

Returns full PII including names, Instagram, bank accounts, addresses — **no auth required**.

## Stats

- 127 unique full names exposed
- 125 Instagram handles
- 59 venues
- 31 cities
- Bank account numbers in response
