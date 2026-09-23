# Blind SQLi Boolean-Oracle Extraction (Contacts-Provider class)

> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `contacts_provider_blind_sqli_oracle` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-CODE-4 |
| MASWE | MASWE-0032 |
| CWE | CWE-89, CWE-862 |
| Suggested tools |  |

## Description

A provider accepts a crafted WHERE/selection clause on a legacy code path with no strict-SQL hardening, so a permission-less caller uses a balanced subquery as a boolean oracle and dumps a protected column one character at a time (Android 17 Contacts Provider CVE-2026-28576 class; reproduced app-layer offline).

## Exploit steps

1. Open the module and press **Run blind extraction**. On a device the oracle drives DVMA's real exported provider (`content://com.dvma.provider.vuln/users`) over its seeded SQLite `secret` column; the panel reports the recovered value, the request count, and confirms it came from the real provider.
2. Reproduce it directly with adb, each request leaks a single bit (row / no row), so a balanced sub-query in the selection is a boolean oracle:

   ```
   # true -> returns the admin row; false -> no rows
   adb shell content query --uri content://com.dvma.provider.vuln/users \
     --where "name='admin' AND substr(secret,1,1)='D'"
   ```
3. Iterate the index (`substr(secret,i,1)`) and guessed character to walk the whole column, with no direct read of `secret` and no `READ_CONTACTS`-style grant.
4. Compare with the hardened path (parameterized selection + strict SQL): the smuggled sub-query is treated as a literal, so the oracle always returns false.

This reproduces the Android 17 Contacts-Provider blind SQLi (CVE-2026-28576) at the app layer against a real provider: the OS bug lived in a platform provider, but the weakness class, concatenating a caller selection into SQL on an unhardened path, is exactly what runs here.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-CODE-4
- OWASP MASWE: MASWE-0032
- CWE: CWE-89, CWE-862
