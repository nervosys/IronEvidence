# IronEvidence

Compliance evidence for the IronSecurity stack: each project's control mappings
written as [OSCAL](https://pages.nist.gov/OSCAL/), so an assessor's tooling can
read them.

**Status: early.** IronEvidence models a component's control statements,
writes them as an OSCAL component definition, and reads IronCrypto's control
mappings. Its output validates against NIST's OSCAL 1.1.2 component-definition
JSON schema. It does not yet read IronPrivacyGuard's, IronSocketLayer's or
IronKeys' mappings. The crate is not published.

## What is here

| Item | Purpose |
| --- | --- |
| `ComponentDefinition`, `Component` | A document and the software components it describes |
| `ControlImplementation` | A component's statements against one catalog or profile |
| `Requirement` | One statement: a control, a status, a description and where the evidence is |
| `Status` | OSCAL's vocabulary (implemented, partial, planned, alternative, not-applicable) plus `Unmet`, written as `not-implemented` |
| `to_oscal_json` | Deterministic OSCAL 1.1.2 component-definition JSON |
| `ironcrypto::Controls` | Reads `ic ontology controls --json` (schema `ironcrypto-controls/1`) and turns it into a component |
| `uuid5` | Name-based identifiers, so a statement keeps its UUID across runs |

The crate forbids unsafe code and depends only on IronCrypto's `ic-json`. The
last-modified time is supplied by the caller and identifiers are derived from
names, so output is reproducible. `uuid5` contains a SHA-1, as RFC 4122
version 5 requires; it derives identifiers from public names and is not a
security function.

## IronCrypto's mappings

```text
ic ontology controls --json > controls.json
ironevidence component --ironcrypto controls.json --last-modified 2026-10-10T00:00:00Z --output ironcrypto.json
ironevidence summary --ironcrypto controls.json
```

`component` writes the OSCAL component definition; `--framework sp800-53` or
`--framework cmmc` limits it to one catalog. `summary` prints how many
statements carry each status, per catalog, as JSON. The tool fetches nothing
and does not read the clock: the timestamp is an argument, so the same input
gives the same bytes. It exits with status 2 for wrong arguments and 1 for
input it cannot read or refuses. From a checkout, run it as
`cargo run --locked -- component ...`.

## Other projects' mappings

Every other project states its mappings in one JSON file of schema
`ironsecurity-controls/1`, described in [docs/FORMAT.md](docs/FORMAT.md), and
`--source <file>` reads it. Sources can be combined, giving one document with
a component for each:

```text
ironevidence component --ironcrypto controls.json --source ipg-controls.json     --last-modified 2026-10-10T00:00:00Z --output stack.json
```

No project ships such a file yet: IronPrivacyGuard's mappings are still prose
in its security audit, and IronSocketLayer and IronKeys have none. The reader
is tested against a fictional example. Writing each file is that project's
maintainers' work, because every entry is a claim the project makes about
itself.

From IronCrypto 0.2.23 this gives 12 NIST SP 800-53 statements (8 partial, 2
not-implemented, 2 not-applicable) and 7 CMMC 2.0 statements (5 partial, 1
not-implemented, 1 not-applicable). None is `implemented`. Each statement
opens with how the control bears on a library, keeps IronCrypto's gap or
reason, and names the IronCrypto version it was read from. An export that
claims FIPS validation, or is of another schema, is refused. IronCrypto's CWE
and ATT&CK mappings are not controls and are left out.

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
cargo run --locked -- component --ironcrypto tests/data/ironcrypto-controls-0.2.23.json --last-modified 2026-10-10T00:00:00Z --output ironcrypto.json
python scripts/check-oscal-schema.py oscal_component_schema.json ironcrypto.json
```

## Licence

AGPL-3.0-or-later; see [LICENSE](LICENSE). A commercial licence is available
from NERVOSYS: see [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md).
Contributions require agreement to the [CLA](CLA.md); see
[CONTRIBUTING.md](CONTRIBUTING.md).
