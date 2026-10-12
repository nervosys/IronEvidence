//! A project's control mappings in the stack's shared form.
//!
//! A project states how it stands against controls in one JSON file, schema
//! [`SCHEMA`], kept in its own repository and reviewed like its code.
//! [`Mappings::from_json`] reads the file and [`Mappings::component`] turns
//! it into an OSCAL component. `docs/FORMAT.md` describes the file.
//!
//! IronCrypto publishes its mappings in its own form, read by
//! [`crate::ironcrypto`]; every other project uses this one.
//!
//! The reader holds a file to the rules a statement must follow: a partial
//! control names its gap, a met or partial control names its evidence, and a
//! file that claims FIPS validation is refused.

use crate::{Component, ControlImplementation, Requirement, Status, uuid5};
use ic_json::Json;

/// The schema this module reads.
pub const SCHEMA: &str = "ironsecurity-controls/1";

/// A file that cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// Not JSON.
    Json(String),
    /// Another schema, or none.
    Schema(String),
    /// A member is missing, empty or of the wrong type.
    Field(String),
    /// The file does not say `"fipsValidated": false`. No project in the
    /// stack is validated, so anything else is wrong.
    ClaimsValidation,
    /// A framework that is not a control framework this crate writes.
    Framework(String),
    /// The same control appears twice in one framework.
    Duplicate(String),
    /// A control identifier OSCAL cannot carry: it must start with a letter
    /// and hold only letters, digits, `.`, `-` and `_`. A CMMC practice is
    /// written `SC.L2-3.13.11`, not `3.13.11`.
    Identifier(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "not JSON: {e}"),
            Self::Schema(s) => write!(f, "schema is {s:?}, expected {SCHEMA:?}"),
            Self::Field(name) => write!(f, "missing or invalid member {name}"),
            Self::ClaimsValidation => {
                f.write_str("the file does not state \"fipsValidated\": false")
            }
            Self::Framework(name) => write!(
                f,
                "{name:?} is not a control framework; use sp800-53 or cmmc"
            ),
            Self::Duplicate(id) => write!(f, "control {id} appears twice"),
            Self::Identifier(id) => write!(
                f,
                "control identifier {id:?} must start with a letter and hold only letters,                  digits, '.', '-' and '_' (a CMMC practice is written SC.L2-3.13.11)"
            ),
        }
    }
}

impl std::error::Error for ReadError {}

/// How a project stands against one control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compliance {
    /// The project's part is met; `evidence` says where that is shown.
    Met {
        /// Repository paths or URLs.
        evidence: Vec<String>,
    },
    /// Part is met; `gap` says what is not.
    Partial {
        /// Repository paths or URLs, for the part that is met.
        evidence: Vec<String>,
        /// What remains unmet.
        gap: String,
    },
    /// Not met.
    Unmet {
        /// Why.
        reason: String,
    },
    /// The control does not apply to the project.
    NotApplicable {
        /// Why.
        reason: String,
    },
}

/// One control as a project maps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    /// The framework: `sp800-53` or `cmmc`.
    pub framework: String,
    /// The control's identifier as the framework writes it, such as `SC-13`
    /// or `3.13.11`.
    pub id: String,
    /// The control's title.
    pub title: String,
    /// How the control bears on this project at all.
    pub bearing: String,
    /// Where the project stands.
    pub compliance: Compliance,
}

/// A project's mappings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mappings {
    /// The project's name, such as `IronPrivacyGuard`.
    pub project: String,
    /// What the project is, in a sentence or two.
    pub description: String,
    /// The project version the mappings describe.
    pub version: String,
    /// The controls, in the file's order.
    pub controls: Vec<Control>,
}

fn text(node: &Json, name: &str) -> Result<String, ReadError> {
    node.get(name)
        .and_then(Json::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ReadError::Field(name.to_owned()))
}

/// A non-empty list of non-empty strings.
fn references(node: &Json) -> Result<Vec<String>, ReadError> {
    let invalid = || ReadError::Field("compliance.evidence".into());
    let list = node
        .get("evidence")
        .and_then(Json::as_array)
        .filter(|list| !list.is_empty())
        .ok_or_else(invalid)?;
    list.iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(invalid)
        })
        .collect()
}

/// The catalog a framework's identifiers come from.
fn catalog(framework: &str) -> Option<(&'static str, &'static str)> {
    match framework {
        "sp800-53" => Some((
            "https://doi.org/10.6028/NIST.SP.800-53r5",
            "NIST SP 800-53 Rev. 5 controls",
        )),
        "cmmc" => Some((
            "https://doi.org/10.6028/NIST.SP.800-171r2",
            "CMMC 2.0 practices (NIST SP 800-171 Rev. 2)",
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

impl Mappings {
    /// Read a `ironsecurity-controls/1` file.
    pub fn from_json(input: &str) -> Result<Self, ReadError> {
        let root = ic_json::parse(input).map_err(ReadError::Json)?;
        let schema = root
            .get("schema")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_owned();
        if schema != SCHEMA {
            return Err(ReadError::Schema(schema));
        }
        // No project in the stack is validated. A file that says otherwise,
        // or does not say, is wrong, and nothing may be rendered from it.
        if root.get("fipsValidated").and_then(Json::as_bool) != Some(false) {
            return Err(ReadError::ClaimsValidation);
        }
        let mut seen: Vec<(String, String)> = Vec::new();
        let controls = root
            .get("controls")
            .and_then(Json::as_array)
            .ok_or_else(|| ReadError::Field("controls".into()))?
            .iter()
            .map(|control| {
                let framework = text(control, "framework")?;
                if catalog(&framework).is_none() {
                    return Err(ReadError::Framework(framework));
                }
                let id = text(control, "id")?;
                // Compared as OSCAL will write them, so `SC-13` and `sc-13`
                // are one control.
                let key = (framework.clone(), control_id(&framework, &id));
                let token = key.1.as_bytes();
                if !token
                    .first()
                    .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
                    || !token
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(b))
                {
                    return Err(ReadError::Identifier(id));
                }
                if seen.contains(&key) {
                    return Err(ReadError::Duplicate(id));
                }
                seen.push(key);
                let compliance = control
                    .get("compliance")
                    .ok_or_else(|| ReadError::Field("compliance".into()))?;
                let reason = |name: &str| {
                    text(compliance, name)
                        .map_err(|_| ReadError::Field(format!("compliance.{name}")))
                };
                let compliance = match text(compliance, "state")?.as_str() {
                    "met" => Compliance::Met {
                        evidence: references(compliance)?,
                    },
                    "partial" => Compliance::Partial {
                        evidence: references(compliance)?,
                        gap: reason("gap")?,
                    },
                    "unmet" => Compliance::Unmet {
                        reason: reason("reason")?,
                    },
                    "not-applicable" => Compliance::NotApplicable {
                        reason: reason("reason")?,
                    },
                    other => return Err(ReadError::Field(format!("compliance.state {other}"))),
                };
                Ok(Control {
                    framework,
                    id,
                    title: text(control, "title")?,
                    bearing: text(control, "bearing")?,
                    compliance,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            project: text(&root, "project")?,
            description: text(&root, "description")?,
            version: text(&root, "version")?,
            controls,
        })
    }

    /// The name used in identifiers: the project's name in lower case, with
    /// anything but letters and digits as `-`.
    pub fn slug(&self) -> String {
        self.project
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect()
    }

    /// The project as an OSCAL component, with one control implementation
    /// for each of `frameworks` the file has controls in. `None` when a
    /// framework is not a control framework.
    ///
    /// Identifiers are derived from names, so they are stable across runs.
    pub fn component(&self, frameworks: &[&str]) -> Option<Component> {
        let slug = self.slug();
        let mut implementations = Vec::new();
        for framework in frameworks {
            let (source, covers) = catalog(framework)?;
            let requirements: Vec<Requirement> = self
                .controls
                .iter()
                .filter(|c| c.framework == *framework)
                .map(|c| self.requirement(&slug, c))
                .collect();
            if requirements.is_empty() {
                continue;
            }
            implementations.push(ControlImplementation {
                uuid: uuid5::id(&format!("{slug}/{framework}")),
                source: source.into(),
                description: format!("{covers}, as {} maps them to itself", self.project),
                requirements,
            });
        }
        Some(Component {
            uuid: uuid5::id(&slug),
            title: self.project.clone(),
            description: format!(
                "{} Its statements say what it contributes to a control, never that a \
                 system satisfies it. {} is not FIPS 140 validated.",
                self.description, self.project
            ),
            version: self.version.clone(),
            implementations,
        })
    }

    fn requirement(&self, slug: &str, control: &Control) -> Requirement {
        let (project, version) = (&self.project, &self.version);
        let (status, detail, evidence) = match &control.compliance {
            Compliance::Met { evidence } => (
                Status::Implemented,
                format!("{project}'s part is met, as of {project} {version}."),
                evidence.clone(),
            ),
            Compliance::Partial { evidence, gap } => (
                Status::Partial,
                format!("Partly met as of {project} {version}. Gap: {gap}"),
                evidence.clone(),
            ),
            Compliance::Unmet { reason } => (
                Status::Unmet,
                format!("Not met as of {project} {version}. {reason}"),
                Vec::new(),
            ),
            Compliance::NotApplicable { reason } => (
                Status::NotApplicable,
                format!("Not applicable to {project} {version}. {reason}"),
                Vec::new(),
            ),
        };
        Requirement {
            uuid: uuid5::id(&format!("{slug}/{}/{}", control.framework, control.id)),
            control_id: control_id(&control.framework, &control.id),
            status,
            description: format!("{} {}", control.bearing, detail),
            evidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ComponentDefinition;

    const EXAMPLE: &str = include_str!("../tests/data/example-controls.json");

    #[test]
    fn reads_a_file_and_keeps_what_it_states() {
        let mappings = Mappings::from_json(EXAMPLE).unwrap();
        assert_eq!(mappings.project, "Example Project");
        assert_eq!(mappings.slug(), "example-project");
        assert_eq!(mappings.controls.len(), 5);
        let component = mappings.component(&["sp800-53", "cmmc"]).unwrap();
        assert_eq!(component.implementations.len(), 2);
        let statements = &component.implementations[0].requirements;
        let statuses: Vec<Status> = statements.iter().map(|r| r.status).collect();
        assert_eq!(
            statuses,
            [
                Status::Implemented,
                Status::Partial,
                Status::Unmet,
                Status::NotApplicable
            ]
        );
        // SP 800-53 identifiers take the catalog's form.
        assert_eq!(statements[1].control_id, "sc-12.2");
        // A partial keeps its gap, and each statement opens with the bearing.
        assert!(statements[1].description.contains("Gap: "));
        assert!(statements[1].description.starts_with("Keys are"));
        // Unmet is never softened, and carries no evidence.
        assert!(statements[2].description.contains("Not met as of"));
        assert!(statements[2].evidence.is_empty());
        assert_eq!(statements[0].evidence, ["tests/audit.rs", "docs/AUDIT.md"]);
        assert!(
            component
                .description
                .ends_with("is not FIPS 140 validated.")
        );
        // One framework, and a framework with no controls.
        assert_eq!(
            mappings.component(&["cmmc"]).unwrap().implementations.len(),
            1
        );
        assert!(mappings.component(&["cwe"]).is_none());
        // Identifiers are stable and the document is valid.
        assert_eq!(
            component,
            mappings.component(&["sp800-53", "cmmc"]).unwrap()
        );
        let definition = ComponentDefinition {
            uuid: uuid5::id("example"),
            title: "Example".into(),
            version: "1".into(),
            last_modified: "2026-10-10T00:00:00Z".into(),
            components: vec![component],
        };
        definition.to_oscal_json().unwrap();
    }

    #[test]
    fn reads_ironprivacyguards_released_file() {
        let mappings =
            Mappings::from_json(include_str!("../tests/data/ipg-controls-0.2.0.json")).unwrap();
        assert_eq!(mappings.project, "IronPrivacyGuard");
        let component = mappings.component(&["sp800-53", "cmmc"]).unwrap();
        // CMMC only, and IPG's own counts.
        assert_eq!(component.implementations.len(), 1);
        let statements = &component.implementations[0].requirements;
        let count = |status| statements.iter().filter(|r| r.status == status).count();
        assert_eq!(
            [
                statements.len(),
                count(Status::Implemented),
                count(Status::Partial),
                count(Status::Unmet)
            ],
            [17, 7, 9, 1]
        );
        // The practice that needs a validated module is not met.
        let fips = statements
            .iter()
            .find(|r| r.control_id == "SC.L2-3.13.11")
            .unwrap();
        assert_eq!(fips.status, Status::Unmet);
    }

    #[test]
    fn a_file_that_breaks_a_rule_is_refused() {
        let with = |from: &str, to: &str| {
            assert!(EXAMPLE.contains(from), "{from}");
            Mappings::from_json(&EXAMPLE.replacen(from, to, 1))
        };
        assert!(matches!(
            with("ironsecurity-controls/1", "ironcrypto-controls/1"),
            Err(ReadError::Schema(_))
        ));
        // Claiming validation, or leaving the question open.
        assert_eq!(
            with("\"fipsValidated\": false", "\"fipsValidated\": true"),
            Err(ReadError::ClaimsValidation)
        );
        assert_eq!(
            with("\"fipsValidated\": false", "\"fipsvalidated\": false"),
            Err(ReadError::ClaimsValidation)
        );
        // A partial without its gap would read as something stronger.
        assert_eq!(
            with("\"gap\": ", "\"note\": "),
            Err(ReadError::Field("compliance.gap".into()))
        );
        // Met without evidence, or with an empty reference.
        assert_eq!(
            with("[\"tests/audit.rs\", \"docs/AUDIT.md\"]", "[]"),
            Err(ReadError::Field("compliance.evidence".into()))
        );
        assert_eq!(
            with("\"docs/AUDIT.md\"", "\" \""),
            Err(ReadError::Field("compliance.evidence".into()))
        );
        assert!(matches!(
            with("\"state\": \"unmet\"", "\"state\": \"planned\""),
            Err(ReadError::Field(_))
        ));
        // Weaknesses and techniques are not controls.
        assert_eq!(
            with("\"framework\": \"cmmc\"", "\"framework\": \"cwe\""),
            Err(ReadError::Framework("cwe".into()))
        );
        // The same control twice, however it is written.
        assert_eq!(
            with("\"id\": \"SC-12(2)\"", "\"id\": \"au-9\""),
            Err(ReadError::Duplicate("au-9".into()))
        );
        // An identifier OSCAL's schema would reject.
        for id in ["3.13.11", "SC 13", ""] {
            assert!(
                matches!(
                    with("\"id\": \"SC.L2-3.13.11\"", &format!("\"id\": \"{id}\"")),
                    Err(ReadError::Identifier(_) | ReadError::Field(_))
                ),
                "{id}"
            );
        }
        assert_eq!(
            with("\"id\": \"SC.L2-3.13.11\"", "\"id\": \"3.13.11\""),
            Err(ReadError::Identifier("3.13.11".into()))
        );
        assert!(matches!(
            with("\"project\": \"Example Project\"", "\"project\": \"\""),
            Err(ReadError::Field(_))
        ));
        assert!(matches!(
            Mappings::from_json("not json"),
            Err(ReadError::Json(_))
        ));
    }
}
