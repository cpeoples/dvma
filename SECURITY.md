# Security Policy

## This project is intentionally vulnerable

DVMA (Damn Vulnerable Mobile App) is a deliberately insecure application built
for mobile security training and pentest practice. It ships hundreds of
intentional vulnerabilities across its modules, mapped to the OWASP Mobile Top
10, MASVS/MASTG, CWE, and the OWASP Top 10 for LLM/GenAI and Agentic
applications.

**Do not report the built-in, intentional vulnerabilities.** They are the
product. Examples include hardcoded secrets in demo fixtures, SQL injection in
the sample content provider, weak or missing cryptography, exported components,
path traversal, insecure WebView configuration, and the LLM/agentic demos. These
are documented behavior, guarded by regression tests so they cannot be
accidentally "fixed."

Only build and run DVMA in an environment you are authorized to use. Do not
deploy it to production infrastructure, publish it to app stores, or run it on
devices holding real data.

## What to report

Please report only issues that are **not** part of the intentional training
surface, such as:

- A vulnerability in the build tooling, CI/CD pipelines, or release signing that
  could compromise a contributor's machine or the published artifacts.
- A supply-chain risk in a dependency that is not itself the subject of a
  training module.
- A flaw in the documentation site generator or automation scripts that could be
  abused against someone running them.
- Accidental exposure of a real secret or credential in the repository or its
  history.

If you are unsure whether something is intentional, check the module's entry in
the registry and its docs page first; the intentional vulnerabilities are always
labeled and standards-mapped.

## How to report

Use GitHub's private vulnerability reporting for this repository
("Security" tab, then "Report a vulnerability"). Please include:

- A clear description of the issue and why it is outside the intended training
  surface.
- Steps to reproduce.
- The affected file(s), commit, or workflow.

Do not open a public issue for a genuine (non-training) security problem until it
has been triaged.
