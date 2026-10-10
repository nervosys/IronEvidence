//! Read IronCrypto's control mappings.
//!
//! The source is `ic ontology controls --json`, schema `ironcrypto-controls/1`
//! (IronCrypto 0.2.23 and later). Within one schema number IronCrypto only
//! adds fields, so unknown fields are ignored here and a different schema
//! number is refused.
//!
//! Three rules from IronCrypto are kept when a mapping becomes a statement:
//!
//! - "met" means IronCrypto's part of a control has evidence in its code,
//!   never that a system satisfies the control. Every statement therefore
//!   opens with the control's `bearing`: how it bears on a library at all.
//! - A partial mapping keeps its gap, and an unmet or not-applicable one its
//!   reason. Dropping either would say more than IronCrypto does.
//! - Evidence is a file and symbol checked at one version, so each statement
//!   names the IronCrypto version it was read from.

use crate::{Component, ControlImplementation, Requirement, Status, uuid5};
use ic_json::Json;

/// The export schema this module reads.
pub const SCHEMA: &str = "ironcrypto-controls/1";

/// Why an export could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadError {
    /// The text is not JSON.
    Json(String),
    /// The export is of another schema.
    Schema(String),
    /// A field this module needs is missing or of the wrong type.
    Field(String),
    /// The export claims a validation IronCrypto does not have.
    ClaimsValidation,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "not JSON: {e}"),
            Self::Schema(s) => write!(f, "unsupported controls schema: {s}"),
            Self::Field(name) => write!(f, "missing or malformed field: {name}"),
            Self::ClaimsValidation => {
                write!(
                    f,
                    "the export claims FIPS validation; refusing to render it"
                )
            }
        }
    }
}

impl std::error::Error for ReadError {}

/// How IronCrypto stands against one control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compliance {
    /// IronCrypto's part is met, with a test-checked file and symbol.
    Met {
        /// The source file.
        file: String,
        /// The symbol in it.
        evidence: String,
    },
    /// Part is met; `gap` says what is not.
    Partial {
        /// The source file.
        file: String,
        /// The symbol in it.
        evidence: String,
        /// What remains unmet.
        gap: String,
    },
    /// Not met.
    Unmet {
        /// Why.
        reason: String,
    },
    /// The control does not apply to a library.
    NotApplicable {
        /// Why.
        reason: String,
    },
}

/// One control as IronCrypto maps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    /// The control's identifier as IronCrypto writes it, such as `SC-13`.
    pub id: String,
    /// The framework's identifier, such as `sp800-53` or `cmmc`.
    pub framework: String,
    /// The control's title.
    pub title: String,
    /// How the control bears on a cryptographic library.
    pub bearing: String,
    /// Where IronCrypto stands.
    pub compliance: Compliance,
}

/// A controls export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Controls {
    /// The IronCrypto version the mappings were read from.
    pub version: String,
    /// Every control in the export, in its order.
    pub controls: Vec<Control>,
}

fn text(node: &Json, name: &str) -> Result<String, ReadError> {
    node.get(name)
        .and_then(Json::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ReadError::Field(name.to_owned()))
}

impl Controls {
    /// Read the JSON `ic ontology controls --json` prints.
    pub fn from_json(input: &str) -> Result<Self, ReadError> {
        let root = ic_json::parse(input).map_err(ReadError::Json)?;
        let schema = text(&root, "schema")?;
        if schema != SCHEMA {
            return Err(ReadError::Schema(schema));
        }
        // IronCrypto is not validated. An export that says otherwise is
        // wrong or forged, and nothing may be rendered from it.
        if root.get("fipsValidated").and_then(Json::as_bool) != Some(false) {
            return Err(ReadError::ClaimsValidation);
        }
        let version = text(&root, "version")?;
        let controls = root
            .get("controls")
            .and_then(Json::as_array)
            .ok_or_else(|| ReadError::Field("controls".into()))?
            .iter()
            .map(|control| {
                let compliance = control
                    .get("compliance")
                    .ok_or_else(|| ReadError::Field("compliance".into()))?;
                let compliance = match text(compliance, "state")?.as_str() {
                    "met" => Compliance::Met {
                        file: text(compliance, "file")?,
                        evidence: text(compliance, "evidence")?,
                    },
                    "partial" => Compliance::Partial {
                        file: text(compliance, "file")?,
                        evidence: text(compliance, "evidence")?,
                        gap: text(compliance, "gap")?,
                    },
                    "unmet" => Compliance::Unmet {
                        reason: text(compliance, "reason")?,
                    },
                    "not-applicable" => Compliance::NotApplicable {
                        reason: text(compliance, "reason")?,
                    },
                    other => return Err(ReadError::Field(format!("compliance.state {other}"))),
                };
                Ok(Control {
                    id: text(control, "id")?,
                    framework: text(control, "framework")?,
                    title: text(control, "title")?,
                    bearing: text(control, "bearing")?,
                    compliance,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { version, controls })
    }

    /// IronCrypto as an OSCAL component, with one control implementation for
    /// each of `frameworks` that has controls in the export.
    ///
    /// Only control frameworks are offered: `sp800-53` and `cmmc`. IronCrypto
    /// also maps CWE weaknesses and ATT&CK techniques, which are not controls
    /// and do not belong in a component definition; asking for one is `None`.
    /// Identifiers are derived from names, so they are stable across runs.
    pub fn component(&self, frameworks: &[&str]) -> Option<Component> {
        let mut implementations = Vec::new();
        for framework in frameworks {
            let (source, description) = catalog(framework)?;
            let requirements: Vec<Requirement> = self
                .controls
                .iter()
                .filter(|c| c.framework == *framework)
                .map(|c| self.requirement(c))
                .collect();
            if requirements.is_empty() {
                continue;
            }
            implementations.push(ControlImplementation {
                uuid: uuid5::id(&format!("ironcrypto/{framework}")),
                source: source.into(),
                description: description.into(),
                requirements,
            });
        }
        Some(Component {
            uuid: uuid5::id("ironcrypto"),
            title: "IronCrypto".into(),
            description: "Cryptographic primitives for the IronSecurity stack. A library \
                          component: its statements say what the library contributes to a \
                          control, never that a system satisfies it. IronCrypto is not FIPS \
                          140 validated."
                .into(),
            version: self.version.clone(),
            implementations,
        })
    }

    fn requirement(&self, control: &Control) -> Requirement {
        let version = &self.version;
        let (status, detail, evidence) = match &control.compliance {
            Compliance::Met { file, evidence } => (
                Status::Implemented,
                format!(
                    "IronCrypto's part is met. Evidence: {evidence} in {file}, as of \
                     IronCrypto {version}."
                ),
                vec![file.clone()],
            ),
            Compliance::Partial {
                file,
                evidence,
                gap,
            } => (
                Status::Partial,
                format!(
                    "Partly met. Gap: {gap} Evidence for the part that is met: {evidence} in \
                     {file}, as of IronCrypto {version}."
                ),
                vec![file.clone()],
            ),
            Compliance::Unmet { reason } => (
                Status::Unmet,
                format!("Not met as of IronCrypto {version}. {reason}"),
                Vec::new(),
            ),
            Compliance::NotApplicable { reason } => (
                Status::NotApplicable,
                format!("Not applicable to this library as of IronCrypto {version}. {reason}"),
                Vec::new(),
            ),
        };
        Requirement {
            uuid: uuid5::id(&format!("ironcrypto/{}/{}", control.framework, control.id)),
            control_id: control_id(&control.framework, &control.id),
            status,
            description: format!("{} {}", control.bearing, detail),
            evidence,
        }
    }
}

/// The catalog a framework's identifiers come from, and what a set covers.
fn catalog(framework: &str) -> Option<(&'static str, &'static str)> {
    match framework {
        "sp800-53" => Some((
            "https://doi.org/10.6028/NIST.SP.800-53r5",
            "NIST SP 800-53 Rev. 5 controls, as IronCrypto maps them to itself",
        )),
        "cmmc" => Some((
            "https://doi.org/10.6028/NIST.SP.800-171r2",
            "CMMC 2.0 practices (NIST SP 800-171 Rev. 2), as IronCrypto maps them to itself",
        )),
        _ => None,
    }
}

/// A control identifier as an OSCAL token. SP 800-53 identifiers take the
/// catalog's form (`SC-12(2)` is `sc-12.2`); others are kept as written.
fn control_id(framework: &str, id: &str) -> String {
    if framework != "sp800-53" {
        return id.to_owned();
    }
    id.to_ascii_lowercase().replace('(', ".").replace(')', "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ComponentDefinition;

    const EXPORT: &str = include_str!("../tests/data/ironcrypto-controls-0.2.23.json");

    #[test]
    fn reads_the_released_export() {
        let controls = Controls::from_json(EXPORT).unwrap();
        assert_eq!(controls.version, "0.2.23");
        assert_eq!(controls.controls.len(), 37);
        let count = |framework: &str, state: fn(&Compliance) -> bool| {
            controls
                .controls
                .iter()
                .filter(|c| c.framework == framework && state(&c.compliance))
                .count()
        };
        // IronCrypto's own counts: no SP 800-53 control is met.
        assert_eq!(
            count("sp800-53", |c| matches!(c, Compliance::Met { .. })),
            0
        );
        assert_eq!(
            count("sp800-53", |c| matches!(c, Compliance::Partial { .. })),
            8
        );
        assert_eq!(
            count("sp800-53", |c| matches!(c, Compliance::Unmet { .. })),
            2
        );
        assert_eq!(
            count("sp800-53", |c| matches!(
                c,
                Compliance::NotApplicable { .. }
            )),
            2
        );
        assert_eq!(count("cmmc", |c| matches!(c, Compliance::Unmet { .. })), 1);
    }

    #[test]
    fn statements_never_say_more_than_ironcrypto_does() {
        let controls = Controls::from_json(EXPORT).unwrap();
        let component = controls.component(&["sp800-53", "cmmc"]).unwrap();
        assert_eq!(component.implementations.len(), 2);
        let sp = &component.implementations[0];
        assert_eq!(sp.requirements.len(), 12);
        // Nothing in SP 800-53 is rendered as implemented.
        assert!(
            sp.requirements
                .iter()
                .all(|r| r.status != Status::Implemented)
        );
        let sc13 = sp
            .requirements
            .iter()
            .find(|r| r.control_id == "sc-13")
            .unwrap();
        assert_eq!(sc13.status, Status::Unmet);
        assert!(sc13.description.contains("Not met as of IronCrypto 0.2.23"));
        // Every source control keeps its bearing, and its gap or reason.
        for (control, requirement) in controls
            .controls
            .iter()
            .filter(|c| c.framework == "sp800-53")
            .zip(&sp.requirements)
        {
            assert!(requirement.description.starts_with(&control.bearing));
            assert!(requirement.description.contains("0.2.23"));
            match &control.compliance {
                Compliance::Partial { gap, .. } => {
                    assert_eq!(requirement.status, Status::Partial);
                    assert!(requirement.description.contains(gap.as_str()));
                }
                Compliance::Unmet { reason } | Compliance::NotApplicable { reason } => {
                    assert!(requirement.description.contains(reason.as_str()));
                    assert!(requirement.evidence.is_empty());
                }
                Compliance::Met { .. } => unreachable!("no SP 800-53 control is met"),
            }
        }
        // Enhancements take the catalog's form.
        assert!(sp.requirements.iter().any(|r| r.control_id == "sc-12.2"));
        // Weakness and technique mappings are not controls.
        assert!(controls.component(&["cwe"]).is_none());
        assert!(controls.component(&["attack"]).is_none());

        let definition = ComponentDefinition {
            uuid: uuid5::id("ironsecurity/component-definition"),
            title: "IronSecurity component definitions".into(),
            version: controls.version.clone(),
            last_modified: "2026-10-10T00:00:00Z".into(),
            components: vec![component],
        };
        let json = definition.to_oscal_json().unwrap();
        assert_eq!(json, definition.to_oscal_json().unwrap());
        assert!(!json.to_lowercase().contains("fips-validated\":true"));
    }

    #[test]
    fn refuses_other_schemas_and_validation_claims() {
        let other = EXPORT.replacen("ironcrypto-controls/1", "ironcrypto-controls/2", 1);
        assert!(matches!(
            Controls::from_json(&other),
            Err(ReadError::Schema(_))
        ));
        let claimed = EXPORT.replacen("\"fipsValidated\":false", "\"fipsValidated\":true", 1);
        assert_ne!(claimed, EXPORT, "the fixture states fipsValidated");
        assert_eq!(
            Controls::from_json(&claimed),
            Err(ReadError::ClaimsValidation)
        );
        assert!(matches!(
            Controls::from_json("not json"),
            Err(ReadError::Json(_))
        ));
        assert!(matches!(
            Controls::from_json("{\"schema\":\"ironcrypto-controls/1\",\"fipsValidated\":false}"),
            Err(ReadError::Field(_))
        ));
    }
}
