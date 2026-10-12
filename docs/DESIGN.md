# IronEvidence design notes

IronEvidence emits OSCAL from every IronSecurity project's control mappings,
so one command produces the evidence an assessor's tooling reads.

## Sources to read

| Project | Where its mappings are today | Form |
| --- | --- | --- |
| IronCrypto | `ic_ontology::frameworks`, or `ic ontology controls --framework sp800-53 --json` (12 SP 800-53 controls: 2 unmet, 8 partial, 2 not applicable). Neither is a promised interface before 1.0. | Rust data or JSON |
| IronPrivacyGuard | `docs/SECURITY_AUDIT.md`: the CMMC 2.0 (NIST SP 800-171 r2) table, the FIPS algorithm table and the MITRE ATT&CK table | Prose and Markdown tables |
| IronSocketLayer | Its ontology (`isl-ontology`) and requirement identifiers (`REQ-*`) | Rust data |
| IronKeys | `Provider` and `Validation`: custody class, exportability and declared module validation | Rust data |

IPG's mappings are prose. Before IronEvidence can read them they need a
machine-readable form in IPG, with the audit document generated from it or
checked against it.

## Rules

1. **A statement is a project's own claim.** IronEvidence records the status
   the project gives; it never infers or raises one.
2. **Unmet stays unmet.** A control that needs a validated module (NIST
   SP 800-53 SC-13, SP 800-171 3.13.11) is not `implemented` on the strength
   of approved algorithms or a planned validation. A source's `Unmet` is
   written as `not-implemented`, never as `planned`: IronCrypto's own table
   records SC-13 and SC-12(2) as unmet.
3. **Reproducible output.** The same input gives the same bytes: the caller
   supplies UUIDs and timestamps, and members are written in a fixed order.
4. **Evidence is referenced, not copied.** A statement links to the test,
   document or commit that supports it.

## Reading IronCrypto's mappings

Facts from the IronCrypto session (IronCrypto 0.2.20), to follow when the
reader is written:

- **Shape.** `ic ontology controls --json` gives, per control: `id`,
  `framework`, `frameworkName`, `title`, `description`, `bearing`,
  `compliance`, `algorithms` and `standards`. `compliance.state` is `met`,
  `partial`, `unmet` or `not-applicable`; met and partial carry `file` and
  `evidence` (a symbol). The name of the gap or reason field is to be checked
  against real output.
- **Mapping.** met to `implemented`, partial to `partial` with the gap,
  unmet to `not-implemented` with the reason, not-applicable to
  `not-applicable` with the reason.
- **"Met" is about a library.** It means IronCrypto's part of a control has
  evidence in its code, never that a system satisfies the control. A statement
  must carry the control's `bearing` text, which says how the control bears on
  a library at all.
- **A partial keeps its gap.** Dropping the gap would turn partial into
  something stronger.
- **Evidence is true for one version.** `file` and `evidence` are checked by
  IronCrypto's tests at the commit they ship in, so record the IronCrypto
  version or commit each mapping was read from.
- **Counts today.** SP 800-53: 8 partial, 2 unmet, 2 not applicable; no
  control is met. CMMC: 5 partial, 1 unmet, 1 not applicable. CWE (9 met, 2
  partial) and ATT&CK (6 met, 1 partial) are weakness and technique mappings,
  not controls, and may not belong in a component definition.
- **Never state or imply** that IronCrypto is FIPS 140 or CMVP validated.

## Next steps

1. Done: the JSON validates against NIST's OSCAL 1.1.2 component-definition
   schema, and CI runs that check. The schema's Unicode patterns are narrowed
   to ASCII there, which is stricter. The `not-implemented` status value is a
   property value the schema does not constrain; an assessor's tooling may
   still expect one of OSCAL's five suggested states.
2. Done for IronCrypto: `ironcrypto::Controls` reads its versioned export
   and the result validates against the schema. The other projects publish
   a data file per repository, schema `ironsecurity-controls/1`
   ([FORMAT.md](FORMAT.md)), read by `controls::Mappings`. A file was chosen
   over a crate because it needs no build, can be reviewed as text, and is
   what IronCrypto's export already is. No project has written one yet.
3. Give IPG's CMMC and FIPS tables a machine-readable source.
4. Done: the `ironevidence` command reads IronCrypto's export and any
   number of `ironsecurity-controls/1` files, and writes one component
   definition with a component for each, or a count of statuses.
5. Done: `uuid5` derives stable version 5 UUIDs from project, catalog and
   control names.

## Open questions

- Which OSCAL models are needed beyond component definitions: a system
  security plan and a plan of action and milestones belong to the deploying
  organization, not to these libraries.
- Which catalogs: NIST SP 800-53 r5, SP 800-171 r2 (CMMC 2.0 Level 2), and
  whether CNSA 2.0 and FIPS 140-3 requirements are expressed as controls.
- Where `implementation-status` belongs. Component definitions carry it here
  as a property; system security plans have a dedicated field.
