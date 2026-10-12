# Changelog

## Unreleased

- Added the shared mappings format `ironsecurity-controls/1`
  (`docs/FORMAT.md`) and its reader, `controls::Mappings`. A partial control
  must name its gap, a met or partial control its evidence, and a file that
  claims FIPS validation or uses an identifier OSCAL cannot carry is refused.
  IronPrivacyGuard ships one; its file at 0.2.0 is a test fixture.
- `ironevidence` takes `--source <file>` for such files, repeatable and
  combinable with `--ironcrypto`, and writes one document with a component for
  each. `summary` now prints a `components` list.
- Added the `ironevidence` command: `component` writes IronCrypto's control
  mappings as an OSCAL component definition and `summary` counts statements
  by status. The timestamp is an argument and nothing is fetched.
- IronEvidence is dual-licensed: AGPL-3.0-or-later, with a commercial licence
  available from NERVOSYS. Added `LICENSE-COMMERCIAL.md`, `CLA.md` and
  `CONTRIBUTING.md`.
- Reads IronCrypto's control mappings (`ic ontology controls --json`, schema
  `ironcrypto-controls/1`) into an OSCAL component, keeping each control's
  bearing, gap or reason and the IronCrypto version. Refuses other schemas
  and any export that claims FIPS validation.
- Added `uuid5`: name-based identifiers that are stable across runs.
- Output now validates against NIST's OSCAL 1.1.2 component-definition JSON
  schema; `scripts/check-oscal-schema.py` and CI check it. UUIDs must be
  version 4 or 5, as OSCAL requires.
- Added `Status::Unmet`, written as `not-implemented`, so an unmet control is
  never rendered as planned.
- Scaffolded IronEvidence: workspace, licence, CI, dependency policy, the initial
  types and the design notes in `docs/`. Not published.
