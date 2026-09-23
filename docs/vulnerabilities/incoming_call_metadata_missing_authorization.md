# Incoming-Call Metadata Read (Missing Authorization class)

> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `incoming_call_metadata_missing_authorization` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-PRIVACY-1 |
| MASWE | MASWE-0032 |
| CWE | CWE-862, CWE-200 |
| Suggested tools |  |

## Description

A provider path returns an incoming call's phone number and associated metadata with no permission check, so a local app reads it with zero grants and no user interaction (Android 17 Contacts Provider CVE-2026-0057 class; reproduced app-layer).

## Exploit steps

1. Open the module and press **Read as unprivileged app**. On a device it reads DVMA's real exported provider path `content://com.dvma.provider.vuln/calls`, which returns the seeded call-log row (number + metadata) with no permission check.
2. Reproduce it directly with adb, no `READ_CALL_LOG`/`READ_PHONE_STATE` grant and no user interaction are required:

   ```
   adb shell content query --uri content://com.dvma.provider.vuln/calls
   ```
3. Observe the returned number and associated fields, private data a correctly-gated provider would only release to a permitted caller.

This reproduces the Android 17 Contacts-Provider missing-authorization read (CVE-2026-0057) at the app layer against a real provider: the weakness is the absent permission check on a metadata-returning path.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-PRIVACY-1
- OWASP MASWE: MASWE-0032
- CWE: CWE-862, CWE-200
