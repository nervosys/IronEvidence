//! Compliance evidence for the IronSecurity stack.
//!
//! Each IronSecurity project states which security controls it helps meet:
//! IronCrypto in `ic_ontology::frameworks`, IronPrivacyGuard in its security
//! audit, IronSocketLayer in its ontology. IronEvidence turns those statements
//! into [OSCAL](https://pages.nist.gov/OSCAL/) so an assessor's tooling can
//! read them.
//!
//! # Status
//!
//! It models a component's control statements, writes them as an OSCAL
//! component definition that validates against NIST's OSCAL 1.1.2
//! component-definition JSON schema (`scripts/check-oscal-schema.py`), and
//! reads IronCrypto's control mappings ([`ironcrypto`]). The other projects'
//! mappings are not read yet.
//!
//! # What evidence is not
//!
//! A statement here is a claim by a project about itself, with the status the
//! project gives it. It is not an assessment, and it never upgrades a status:
//! a control that needs a FIPS 140-3 validated module stays unmet until a
//! certificate exists.

use std::fmt::Write as _;

pub mod ironcrypto;
pub mod uuid5;

/// The OSCAL version the output is structured for.
pub const OSCAL_VERSION: &str = "1.1.2";

/// What can be wrong with evidence before it is written.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An identifier is not a lowercase RFC 4122 UUID of version 4 or 5.
    InvalidUuid(String),
    /// A required text field is empty.
    Empty(&'static str),
    /// Two entries share an identifier that must be unique.
    Duplicate(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUuid(value) => {
                write!(f, "not a lowercase version 4 or 5 UUID: {value}")
            }
            Self::Empty(field) => write!(f, "{field} must not be empty"),
            Self::Duplicate(value) => write!(f, "duplicate identifier: {value}"),
        }
    }
}

impl std::error::Error for Error {}

/// How far a component goes toward a control: OSCAL's vocabulary, plus
/// [`Status::Unmet`] for a control the component does not meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The component meets its part of the control.
    Implemented,
    /// The component meets some of its part.
    Partial,
    /// The component does not meet it yet; work is scheduled.
    Planned,
    /// The component does not meet it. Written as `not-implemented`, which
    /// is outside OSCAL's suggested values, because `planned` would say more
    /// than is true when no work is scheduled.
    Unmet,
    /// The control is met another way.
    Alternative,
    /// The control does not apply to the component.
    NotApplicable,
}

impl Status {
    /// The OSCAL `implementation-status` value.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::Partial => "partial",
            Self::Planned => "planned",
            Self::Unmet => "not-implemented",
            Self::Alternative => "alternative",
            Self::NotApplicable => "not-applicable",
        }
    }
}

/// One statement: how a component relates to one control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// A UUID for this statement, stable across runs.
    pub uuid: String,
    /// The control's identifier in its catalog, such as `sc-13`.
    pub control_id: String,
    /// The status the project gives itself.
    pub status: Status,
    /// What the component does, and what it does not.
    pub description: String,
    /// Where the supporting evidence is: URLs or repository paths.
    pub evidence: Vec<String>,
}

/// A component's statements against one catalog or profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlImplementation {
    /// A UUID for this set, stable across runs.
    pub uuid: String,
    /// The catalog or profile the control identifiers come from, as a URL.
    pub source: String,
    /// What this set covers.
    pub description: String,
    /// The statements.
    pub requirements: Vec<Requirement>,
}

/// A software component and what it claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// A UUID for the component, stable across runs.
    pub uuid: String,
    /// The component's name, such as `IronPrivacyGuard`.
    pub title: String,
    /// What the component is.
    pub description: String,
    /// The component's version.
    pub version: String,
    /// Its statements, per catalog.
    pub implementations: Vec<ControlImplementation>,
}

/// A document: components and when they were described.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentDefinition {
    /// A UUID for this document.
    pub uuid: String,
    /// The document's title.
    pub title: String,
    /// The document's own version.
    pub version: String,
    /// When it was last changed, as an RFC 3339 timestamp. The caller
    /// supplies it so that output is reproducible.
    pub last_modified: String,
    /// The components.
    pub components: Vec<Component>,
}

fn check_uuid(value: &str, seen: &mut Vec<String>) -> Result<(), Error> {
    let bytes = value.as_bytes();
    let shaped = bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            // OSCAL accepts only version 4 or 5 UUIDs of the RFC 4122 variant.
            14 => matches!(b, b'4' | b'5'),
            19 => matches!(b, b'8' | b'9' | b'a' | b'b'),
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        });
    if !shaped {
        return Err(Error::InvalidUuid(value.to_owned()));
    }
    if seen.iter().any(|s| s == value) {
        return Err(Error::Duplicate(value.to_owned()));
    }
    seen.push(value.to_owned());
    Ok(())
}

fn required(value: &str, field: &'static str) -> Result<(), Error> {
    if value.trim().is_empty() {
        Err(Error::Empty(field))
    } else {
        Ok(())
    }
}

/// A JSON string literal.
fn string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn member(out: &mut String, name: &str, value: &str) {
    string(out, name);
    out.push(':');
    string(out, value);
}

impl ComponentDefinition {
    /// Check that every identifier is a unique UUID and no required text is
    /// empty.
    pub fn validate(&self) -> Result<(), Error> {
        let mut seen = Vec::new();
        check_uuid(&self.uuid, &mut seen)?;
        required(&self.title, "title")?;
        required(&self.version, "version")?;
        required(&self.last_modified, "last_modified")?;
        for component in &self.components {
            check_uuid(&component.uuid, &mut seen)?;
            required(&component.title, "component title")?;
            required(&component.description, "component description")?;
            for implementation in &component.implementations {
                check_uuid(&implementation.uuid, &mut seen)?;
                required(&implementation.source, "control source")?;
                required(
                    &implementation.description,
                    "control implementation description",
                )?;
                let mut controls: Vec<&str> = Vec::new();
                for requirement in &implementation.requirements {
                    check_uuid(&requirement.uuid, &mut seen)?;
                    required(&requirement.control_id, "control_id")?;
                    required(&requirement.description, "requirement description")?;
                    if controls.contains(&requirement.control_id.as_str()) {
                        return Err(Error::Duplicate(requirement.control_id.clone()));
                    }
                    controls.push(&requirement.control_id);
                }
            }
        }
        Ok(())
    }

    /// The document as OSCAL component-definition JSON.
    ///
    /// Output is deterministic: members and entries appear in the order
    /// given, with no whitespace. Each statement's status is carried as an
    /// `implementation-status` property and its evidence as `reference`
    /// links.
    pub fn to_oscal_json(&self) -> Result<String, Error> {
        self.validate()?;
        let mut out = String::from("{\"component-definition\":{");
        member(&mut out, "uuid", &self.uuid);
        out.push_str(",\"metadata\":{");
        member(&mut out, "title", &self.title);
        out.push(',');
        member(&mut out, "last-modified", &self.last_modified);
        out.push(',');
        member(&mut out, "version", &self.version);
        out.push(',');
        member(&mut out, "oscal-version", OSCAL_VERSION);
        out.push_str("},\"components\":[");
        for (i, component) in self.components.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            member(&mut out, "uuid", &component.uuid);
            out.push(',');
            member(&mut out, "type", "software");
            out.push(',');
            member(&mut out, "title", &component.title);
            out.push(',');
            member(&mut out, "description", &component.description);
            out.push_str(",\"props\":[{");
            member(&mut out, "name", "version");
            out.push(',');
            member(&mut out, "value", &component.version);
            out.push_str("}],\"control-implementations\":[");
            for (j, implementation) in component.implementations.iter().enumerate() {
                if j > 0 {
                    out.push(',');
                }
                out.push('{');
                member(&mut out, "uuid", &implementation.uuid);
                out.push(',');
                member(&mut out, "source", &implementation.source);
                out.push(',');
                member(&mut out, "description", &implementation.description);
                out.push_str(",\"implemented-requirements\":[");
                for (k, requirement) in implementation.requirements.iter().enumerate() {
                    if k > 0 {
                        out.push(',');
                    }
                    out.push('{');
                    member(&mut out, "uuid", &requirement.uuid);
                    out.push(',');
                    member(&mut out, "control-id", &requirement.control_id);
                    out.push(',');
                    member(&mut out, "description", &requirement.description);
                    out.push_str(",\"props\":[{");
                    member(&mut out, "name", "implementation-status");
                    out.push(',');
                    member(&mut out, "value", requirement.status.id());
                    out.push_str("}]");
                    if !requirement.evidence.is_empty() {
                        out.push_str(",\"links\":[");
                        for (l, href) in requirement.evidence.iter().enumerate() {
                            if l > 0 {
                                out.push(',');
                            }
                            out.push('{');
                            member(&mut out, "href", href);
                            out.push(',');
                            member(&mut out, "rel", "reference");
                            out.push('}');
                        }
                        out.push(']');
                    }
                    out.push('}');
                }
                out.push_str("]}");
            }
            out.push_str("]}");
        }
        out.push_str("]}}");
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(n: u8) -> String {
        format!("00000000-0000-4000-8000-0000000000{n:02x}")
    }

    fn sample() -> ComponentDefinition {
        ComponentDefinition {
            uuid: uuid(1),
            title: "IronSecurity component definitions".into(),
            version: "0.0.0".into(),
            last_modified: "2026-10-09T00:00:00Z".into(),
            components: vec![Component {
                uuid: uuid(2),
                title: "IronPrivacyGuard".into(),
                description: "Agent-first privacy CLI".into(),
                version: "0.2.0".into(),
                implementations: vec![ControlImplementation {
                    uuid: uuid(3),
                    source: "https://doi.org/10.6028/NIST.SP.800-171r2".into(),
                    description: "NIST SP 800-171 r2 practices".into(),
                    requirements: vec![
                        Requirement {
                            uuid: uuid(4),
                            control_id: "3.13.11".into(),
                            status: Status::Unmet,
                            description:
                                "Approved algorithms on P-384 paths; no \"validated\" module."
                                    .into(),
                            evidence: vec!["docs/SECURITY_AUDIT.md".into()],
                        },
                        Requirement {
                            uuid: uuid(5),
                            control_id: "3.3.8".into(),
                            status: Status::Partial,
                            description: "Hash-chained audit log\nwith signed checkpoints.".into(),
                            evidence: Vec::new(),
                        },
                    ],
                }],
            }],
        }
    }

    #[test]
    fn writes_a_deterministic_component_definition() {
        let json = sample().to_oscal_json().unwrap();
        assert_eq!(json, sample().to_oscal_json().unwrap());
        assert!(json.starts_with("{\"component-definition\":{\"uuid\":\""));
        assert!(json.contains("\"oscal-version\":\"1.1.2\""));
        assert!(json.contains("\"control-id\":\"3.13.11\""));
        assert!(
            json.contains("{\"name\":\"implementation-status\",\"value\":\"not-implemented\"}")
        );
        assert!(json.contains("{\"href\":\"docs/SECURITY_AUDIT.md\",\"rel\":\"reference\"}"));
        // Text is escaped, never interpolated raw.
        assert!(json.contains("no \\\"validated\\\" module."));
        assert!(json.contains("audit log\\nwith signed"));
        assert!(!json.contains('\n'));
        // Braces and brackets balance outside strings.
        let (mut depth, mut in_string, mut escaped) = (0i32, false, false);
        for c in json.chars() {
            match (in_string, escaped, c) {
                (true, true, _) => escaped = false,
                (true, false, '\\') => escaped = true,
                (true, false, '"') => in_string = false,
                (false, _, '"') => in_string = true,
                (false, _, '{' | '[') => depth += 1,
                (false, _, '}' | ']') => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0);
        }
        assert_eq!(depth, 0);
        assert!(!in_string);
    }

    #[test]
    fn refuses_bad_identifiers_and_empty_statements() {
        let mut bad = sample();
        bad.uuid = "NOT-A-UUID".into();
        assert!(matches!(bad.to_oscal_json(), Err(Error::InvalidUuid(_))));

        let mut upper = sample();
        upper.uuid = upper.uuid.to_uppercase().replace('0', "A");
        assert!(matches!(upper.validate(), Err(Error::InvalidUuid(_))));

        // OSCAL's schema refuses other UUID versions and variants.
        for wrong in [
            "00000000-0000-1000-8000-000000000001",
            "00000000-0000-4000-c000-000000000001",
        ] {
            let mut versioned = sample();
            versioned.uuid = wrong.into();
            assert!(matches!(versioned.validate(), Err(Error::InvalidUuid(_))));
        }

        let mut reused = sample();
        reused.components[0].uuid = reused.uuid.clone();
        assert!(matches!(reused.validate(), Err(Error::Duplicate(_))));

        let mut repeated = sample();
        repeated.components[0].implementations[0].requirements[1].control_id = "3.13.11".into();
        assert!(matches!(repeated.validate(), Err(Error::Duplicate(_))));

        let mut silent = sample();
        silent.components[0].implementations[0].requirements[0].description = "  ".into();
        assert_eq!(
            silent.validate(),
            Err(Error::Empty("requirement description"))
        );
    }

    #[test]
    fn statuses_use_the_oscal_vocabulary() {
        let ids: Vec<&str> = [
            Status::Implemented,
            Status::Partial,
            Status::Planned,
            Status::Unmet,
            Status::Alternative,
            Status::NotApplicable,
        ]
        .iter()
        .map(|s| s.id())
        .collect();
        assert_eq!(
            ids,
            [
                "implemented",
                "partial",
                "planned",
                "not-implemented",
                "alternative",
                "not-applicable"
            ]
        );
    }
}
