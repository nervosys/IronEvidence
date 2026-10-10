# IronEvidence

Compliance evidence for the IronSecurity stack: each project's control mappings
written as [OSCAL](https://pages.nist.gov/OSCAL/), so an assessor's tooling can
read them.

**Status: scaffold.** IronEvidence models a component's control statements and
writes them as an OSCAL component definition. Its example output validates
against NIST's OSCAL 1.1.2 component-definition JSON schema. It does not yet
read any project's mappings. The crate is not published.

## What is here

| Item | Purpose |
| --- | --- |
| `ComponentDefinition`, `Component` | A document and the software components it describes |
| `ControlImplementation` | A component's statements against one catalog or profile |
| `Requirement` | One statement: a control, a status, a description and where the evidence is |
| `Status` | OSCAL's vocabulary (implemented, partial, planned, alternative, not-applicable) plus `Unmet`, written as `not-implemented` |
| `to_oscal_json` | Deterministic OSCAL 1.1.2 component-definition JSON |

The crate forbids unsafe code and has no dependencies. UUIDs and the
last-modified time are supplied by the caller, so output is reproducible.

## What evidence is not

A statement is a claim by a project about itself, with the status the project
gives it. It is not an assessment. IronEvidence never upgrades a status: a
control that needs a FIPS 140-3 validated module stays unmet until a
certificate exists. IronCrypto is not CMVP validated; a validation is planned,
with no date.

## Plan

See [docs/DESIGN.md](docs/DESIGN.md) for the sources to read and the open
questions.

## Checks

```text
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
python scripts/check-first-party-only.py --all-features
```

To check output against NIST's schema (needs Python's `jsonschema`; the schema
is downloaded, not bundled):

```text
curl -sfLO https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/oscal_component_schema.json
cargo run --locked --example component > component.json
python scripts/check-oscal-schema.py oscal_component_schema.json component.json
```

## Licence

AGPL-3.0-or-later; see [LICENSE](LICENSE). Whether a commercial licence is
also offered is the maintainer's decision and is not stated here.
