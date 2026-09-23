Contributions that add real, well-mapped vulnerability modules — or improve the
tooling, docs, and platform parity around them — are welcome. This page covers
the standards mapping and validation gates every contribution must pass. The
full workflow (branching, PR expectations, component glossary, troubleshooting)
lives in [`CONTRIBUTING.md`](https://github.com/cpeoples/dvma/blob/main/CONTRIBUTING.md)
at the repo root.

> **Scope reminder.** Every module must be a *training artifact*: a
> self-contained demonstration inside DVMA. Do not contribute exploits,
> payloads, or tooling aimed at third-party apps, services, or infrastructure
> you are not authorized to test.

## The registry is the single source of truth

Vulnerability metadata is authored in **one** place — the YAML registry under
`config/registry/categories/` — and everything else (the app catalog, the
router, the automation manifest, and every page on this site) is generated from
it. You never hand-edit generated files: edit the YAML, run the generator, and
commit its output.

```sh
dart run tool/generate.dart
```

## Required, enforced standards tags

Every module **must** carry a genuine mapping for all four of:

| Field | Example | Notes |
| --- | --- | --- |
| `masvs` | `MASVS-CRYPTO-1` | at least one MASVS control |
| `cwe` | `CWE-327` | at least one CWE |
| `maswe` | `MASWE-0007` | at least one MASWE weakness id |
| `owasp_mobile` | `M10` | OWASP Mobile Top 10 (2024) category |

`owasp_llm` / `owasp_agentic` and `mastg_v2` / `mastg_demo` are optional and
added only when a real mapping exists. Map honestly — never invent an id to
satisfy a gate. MASVS names *controls*, not vulnerabilities, so a module keeps
its own descriptive `title`/`id` and *maps* to the relevant control(s) plus a
MASWE weakness and (where one exists) a MASTG test.

## Difficulty and severity

The registry has a `difficulty` field (`easy` | `medium` | `hard`), which sorts
a module within its category. There is no *required* `severity` field: DVMA maps
each module to CWE/MASWE/OWASP, which already carry the industry severity
framing. An **optional** `severity` (`low` | `medium` | `high` | `critical`) may
be added when a module has a defensible rating — it is enum-validated but never
fabricated to fill a column.

## What gets validated

Two layers enforce the contract; both run in [`make check`](https://github.com/cpeoples/dvma/blob/main/Makefile)
and CI:

| Check | What it enforces | Run it |
| --- | --- | --- |
| **Generator** (`tool/generate.dart`) | Required tags present; id shapes (`CWE-<n>`, `MASWE-<n>`, `MASVS-<AREA>-<n>`, `M<n>`); unique ids; known fields only; `platforms` enum; reference URLs are `text\|https://url` | `make generate` |
| **Registry schema** (`module.schema.json`) | The same contract expressed declaratively as JSON Schema, plus editor hints | `make schema` |
| **Standards links** (`standards_mapping_audit.py --check`) | Every MASVS/CWE/MASWE/MASTG id is well-formed **and resolves to a real `mas.owasp.org` page** — no invented or dangling standard ids | `make standards` |

Install the commit-time gate once so these run automatically on every commit:

```sh
pip install pre-commit && pre-commit install
```

The standards checks depend on Python's `pyyaml` (and `jsonschema` for the
schema check); pre-commit installs those into an isolated environment for you.
If you run the scripts directly instead, install them first:

```sh
pip install pyyaml jsonschema
```
