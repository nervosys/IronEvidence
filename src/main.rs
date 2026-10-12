//! `ironevidence`: write OSCAL from a project's control mappings.
//!
//! ```text
//! ironevidence component [--ironcrypto <controls.json>] [--source <file>]...
//!                        --last-modified <RFC 3339>
//!                        [--framework sp800-53|cmmc]... [--output <file>]
//! ironevidence summary   [--ironcrypto <controls.json>] [--source <file>]...
//!                        [--framework ...]...
//! ```
//!
//! `--ironcrypto` takes the output of `ic ontology controls --json`, and
//! `--source` a project's `ironsecurity-controls/1` file. Nothing is
//! fetched and the clock is not read: the caller supplies the timestamp, so
//! the same input gives the same bytes.
#![forbid(unsafe_code)]

use ic_json::Json;
use ironevidence::{
    Component, ComponentDefinition, Status, controls::Mappings, ironcrypto::Controls, uuid5,
};

const USAGE: &str = "usage:
  ironevidence component [--ironcrypto <controls.json>] [--source <file>]...
                         --last-modified <RFC 3339>
                         [--framework sp800-53|cmmc]... [--output <file>]
  ironevidence summary   [--ironcrypto <controls.json>] [--source <file>]...
                         [--framework sp800-53|cmmc]...

--ironcrypto takes the output of `ic ontology controls --json`; --source takes
a project's ironsecurity-controls/1 file and may be repeated. At least one is
required, and each becomes one component. Without --framework, both control
frameworks are written. A statement is the project's own claim, with the
status the project gives it; it is not an assessment.";

/// The control frameworks a component definition can carry.
const FRAMEWORKS: [&str; 2] = ["sp800-53", "cmmc"];

/// Why a run stopped, and the exit status that says so.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    /// The arguments were wrong: exit status 2.
    Usage(String),
    /// The input could not be read or was refused: exit status 1.
    Input(String),
}

/// What the arguments ask for.
#[derive(Debug, Default, PartialEq, Eq)]
struct Request {
    command: String,
    ironcrypto: Option<String>,
    sources: Vec<String>,
    last_modified: Option<String>,
    frameworks: Vec<String>,
    output: Option<String>,
}

fn parse(args: &[String]) -> Result<Request, Failure> {
    let usage = |text: String| Failure::Usage(text);
    let mut request = Request::default();
    let mut args = args.iter();
    request.command = match args.next().map(String::as_str) {
        Some(command @ ("component" | "summary")) => command.into(),
        Some(other) => return Err(usage(format!("unknown command {other:?}"))),
        None => return Err(usage("a command is required".into())),
    };
    while let Some(flag) = args.next() {
        let mut value = || {
            args.next()
                .cloned()
                .ok_or_else(|| Failure::Usage(format!("{flag} needs a value")))
        };
        // A repeated flag is a mistake, not an override.
        let once = |slot: &mut Option<String>, value: String| {
            if slot.replace(value).is_some() {
                return Err(Failure::Usage(format!("{flag} was given twice")));
            }
            Ok(())
        };
        match flag.as_str() {
            "--ironcrypto" => once(&mut request.ironcrypto, value()?)?,
            "--last-modified" => once(&mut request.last_modified, value()?)?,
            "--output" => once(&mut request.output, value()?)?,
            "--source" => {
                let source = value()?;
                if request.sources.contains(&source) {
                    return Err(usage(format!("--source {source} was given twice")));
                }
                request.sources.push(source);
            }
            "--framework" => {
                let framework = value()?;
                if !FRAMEWORKS.contains(&framework.as_str()) {
                    return Err(usage(format!(
                        "{framework:?} is not a control framework; use sp800-53 or cmmc"
                    )));
                }
                if request.frameworks.contains(&framework) {
                    return Err(usage(format!("--framework {framework} was given twice")));
                }
                request.frameworks.push(framework);
            }
            other => return Err(usage(format!("unknown argument {other:?}"))),
        }
    }
    if request.ironcrypto.is_none() && request.sources.is_empty() {
        return Err(usage(
            "--ironcrypto <controls.json> or --source <file> is required".into(),
        ));
    }
    match (request.command.as_str(), &request.last_modified) {
        ("component", None) => {
            return Err(usage("component needs --last-modified".into()));
        }
        ("component", Some(time)) if !is_rfc3339(time) => {
            return Err(usage(format!(
                "--last-modified {time:?} is not an RFC 3339 timestamp such as 2026-10-10T00:00:00Z"
            )));
        }
        ("summary", Some(_)) => {
            return Err(usage("summary takes no --last-modified".into()));
        }
        _ => {}
    }
    if request.command == "summary" && request.output.is_some() {
        return Err(usage("summary takes no --output".into()));
    }
    Ok(request)
}

/// Whether `text` is an RFC 3339 date-time with a time zone, as OSCAL
/// requires: `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)`.
fn is_rfc3339(text: &str) -> bool {
    let bytes = text.as_bytes();
    let shape = |part: &[u8], pattern: &str| {
        part.len() == pattern.len()
            && part.iter().zip(pattern.bytes()).all(|(b, p)| match p {
                b'd' => b.is_ascii_digit(),
                p => *b == p,
            })
    };
    let number = |range: std::ops::Range<usize>| -> u32 {
        text.get(range).and_then(|s| s.parse().ok()).unwrap_or(99)
    };
    if bytes.len() < 20 || !shape(&bytes[..19], "dddd-dd-ddTdd:dd:dd") {
        return false;
    }
    let (month, day, hour, minute, second) = (
        number(5..7),
        number(8..10),
        number(11..13),
        number(14..16),
        number(17..19),
    );
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return false;
    }
    let mut rest = &bytes[19..];
    if let [b'.', fraction @ ..] = rest {
        let digits = fraction.iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 {
            return false;
        }
        rest = &fraction[digits..];
    }
    match rest {
        b"Z" => true,
        [b'+' | b'-', offset @ ..] => {
            shape(offset, "dd:dd")
                && (offset[0] - b'0') * 10 + (offset[1] - b'0') <= 23
                && (offset[3] - b'0') * 10 + (offset[4] - b'0') <= 59
        }
        _ => false,
    }
}

/// One source as read: the name used in identifiers, the project version
/// and the component.
struct Source {
    slug: String,
    version: String,
    component: Component,
}

/// Every source's component, IronCrypto's first, for the frameworks asked
/// for.
fn sources(
    request: &Request,
    read: &dyn Fn(&str) -> std::io::Result<String>,
) -> Result<Vec<Source>, Failure> {
    let frameworks: Vec<&str> = if request.frameworks.is_empty() {
        FRAMEWORKS.to_vec()
    } else {
        request.frameworks.iter().map(String::as_str).collect()
    };
    let text = |path: &str| read(path).map_err(|e| Failure::Input(format!("{path}: {e}")));
    let none =
        |path: &str| Failure::Input(format!("{path}: no controls of the requested frameworks"));
    let mut found: Vec<Source> = Vec::new();
    if let Some(path) = request.ironcrypto.as_deref() {
        let controls = Controls::from_json(&text(path)?)
            .map_err(|e| Failure::Input(format!("{path}: {e}")))?;
        let component = controls
            .component(&frameworks)
            .filter(|component| !component.implementations.is_empty())
            .ok_or_else(|| none(path))?;
        found.push(Source {
            slug: "ironcrypto".into(),
            version: controls.version,
            component,
        });
    }
    for path in &request.sources {
        let mappings = Mappings::from_json(&text(path)?)
            .map_err(|e| Failure::Input(format!("{path}: {e}")))?;
        let slug = mappings.slug();
        // Two files for one project would be two components with one
        // identifier.
        if found.iter().any(|source| source.slug == slug) {
            return Err(Failure::Input(format!(
                "{path}: {} is described by more than one source",
                mappings.project
            )));
        }
        let component = mappings
            .component(&frameworks)
            .filter(|component| !component.implementations.is_empty())
            .ok_or_else(|| none(path))?;
        found.push(Source {
            slug,
            version: mappings.version,
            component,
        });
    }
    Ok(found)
}

/// Counts of each status per catalog, for one component.
fn summary(component: &Component) -> Json {
    const STATUSES: [Status; 6] = [
        Status::Implemented,
        Status::Partial,
        Status::Planned,
        Status::Unmet,
        Status::Alternative,
        Status::NotApplicable,
    ];
    let catalogs = component
        .implementations
        .iter()
        .map(|implementation| {
            let count = |status: Status| {
                implementation
                    .requirements
                    .iter()
                    .filter(|r| r.status == status)
                    .count() as u32
            };
            Json::object([
                ("source", Json::str(implementation.source.as_str())),
                (
                    "statements",
                    Json::num(implementation.requirements.len() as u32),
                ),
                (
                    "statuses",
                    Json::Object(
                        STATUSES
                            .iter()
                            .map(|s| (s.id().to_string(), Json::num(count(*s))))
                            .collect(),
                    ),
                ),
            ])
        })
        .collect();
    Json::object([
        ("component", Json::str(component.title.as_str())),
        ("version", Json::str(component.version.as_str())),
        ("catalogs", Json::Array(catalogs)),
    ])
}

/// Run one command and return what it prints.
fn run(args: &[String], read: &dyn Fn(&str) -> std::io::Result<String>) -> Result<String, Failure> {
    let request = parse(args)?;
    let sources = sources(&request, read)?;
    if request.command == "summary" {
        let components = sources.iter().map(|s| summary(&s.component)).collect();
        return Ok(Json::object([("components", Json::Array(components))]).to_string());
    }
    // IronCrypto alone keeps the document it has always had; several
    // sources make one document named for all of them.
    let (uuid, title, version) = match &sources[..] {
        [only] if only.slug == "ironcrypto" => (
            uuid5::id("ironsecurity/component-definition/ironcrypto"),
            "IronCrypto component definition".to_string(),
            only.version.clone(),
        ),
        many => {
            let slugs: Vec<&str> = many.iter().map(|s| s.slug.as_str()).collect();
            let versions: Vec<String> = many
                .iter()
                .map(|s| format!("{}-{}", s.slug, s.version))
                .collect();
            (
                uuid5::id(&format!(
                    "ironsecurity/component-definition/{}",
                    slugs.join("+")
                )),
                "IronSecurity component definition".to_string(),
                versions.join("+"),
            )
        }
    };
    let definition = ComponentDefinition {
        uuid,
        title,
        version,
        last_modified: request.last_modified.clone().unwrap_or_default(),
        components: sources.into_iter().map(|s| s.component).collect(),
    };
    definition
        .to_oscal_json()
        .map_err(|e| Failure::Input(e.to_string()))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return;
    }
    let output = args
        .windows(2)
        .find(|pair| pair[0] == "--output")
        .map(|pair| pair[1].clone());
    let written =
        run(&args, &|path| std::fs::read_to_string(path)).and_then(|text| match &output {
            Some(path) => std::fs::write(path, format!("{text}\n"))
                .map_err(|e| Failure::Input(format!("{path}: {e}"))),
            None => {
                println!("{text}");
                Ok(())
            }
        });
    match written {
        Ok(()) => {}
        Err(Failure::Usage(message)) => {
            eprintln!("ironevidence: {message}\n\n{USAGE}");
            std::process::exit(2);
        }
        Err(Failure::Input(message)) => {
            eprintln!("ironevidence: {message}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPORT: &str = include_str!("../tests/data/ironcrypto-controls-0.2.23.json");
    const EXAMPLE: &str = include_str!("../tests/data/example-controls.json");

    fn call(args: &[&str]) -> Result<String, Failure> {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        run(&args, &|path| match path {
            "controls.json" => Ok(EXPORT.to_string()),
            "example.json" | "again.json" => Ok(EXAMPLE.to_string()),
            "validated.json" => {
                Ok(EXPORT.replacen("\"fipsValidated\":false", "\"fipsValidated\":true", 1))
            }
            _ => Err(std::io::ErrorKind::NotFound.into()),
        })
    }

    fn usage(args: &[&str]) -> bool {
        matches!(call(args), Err(Failure::Usage(_)))
    }

    #[test]
    fn a_component_definition_is_written_and_is_reproducible() {
        let args = [
            "component",
            "--ironcrypto",
            "controls.json",
            "--last-modified",
            "2026-10-10T00:00:00Z",
        ];
        let first = call(&args).unwrap();
        assert_eq!(first, call(&args).unwrap());
        let json = ic_json::parse(&first).unwrap();
        let definition = json.get("component-definition").unwrap();
        assert_eq!(
            definition
                .get("metadata")
                .and_then(|m| m.get("last-modified"))
                .and_then(Json::as_str),
            Some("2026-10-10T00:00:00Z")
        );
        // Both control frameworks by default, one when one is named.
        let catalogs = |text: &str| {
            ic_json::parse(text)
                .unwrap()
                .get("component-definition")
                .and_then(|d| d.get("components"))
                .and_then(Json::as_array)
                .unwrap()[0]
                .get("control-implementations")
                .and_then(Json::as_array)
                .unwrap()
                .len()
        };
        assert_eq!(catalogs(&first), 2);
        let one = call(&[&args[..], &["--framework", "cmmc"]].concat()).unwrap();
        assert_eq!(catalogs(&one), 1);
        // Nothing in the output claims the control that needs a validated
        // module is met.
        assert!(first.contains("not-implemented"));
        assert!(!first.contains("\"value\":\"implemented\""));
    }

    #[test]
    fn the_summary_counts_what_the_project_states() {
        let text = call(&["summary", "--ironcrypto", "controls.json"]).unwrap();
        let all = ic_json::parse(&text).unwrap();
        let json = &all.get("components").and_then(Json::as_array).unwrap()[0];
        assert_eq!(
            json.get("component").and_then(Json::as_str),
            Some("IronCrypto")
        );
        assert_eq!(json.get("version").and_then(Json::as_str), Some("0.2.23"));
        let catalogs = json.get("catalogs").and_then(Json::as_array).unwrap();
        let counts: Vec<[i64; 5]> = catalogs
            .iter()
            .map(|c| {
                let status = |name: &str| {
                    c.get("statuses")
                        .and_then(|s| s.get(name))
                        .and_then(Json::as_i64)
                        .unwrap()
                };
                [
                    c.get("statements").and_then(Json::as_i64).unwrap(),
                    status("implemented"),
                    status("partial"),
                    status("not-implemented"),
                    status("not-applicable"),
                ]
            })
            .collect();
        // SP 800-53, then CMMC: none implemented.
        assert_eq!(counts, [[12, 0, 8, 2, 2], [7, 0, 5, 1, 1]]);
    }

    #[test]
    fn several_sources_make_one_document_with_a_component_each() {
        let time = ["--last-modified", "2026-10-10T00:00:00Z"];
        let both = [
            "component",
            "--ironcrypto",
            "controls.json",
            "--source",
            "example.json",
        ];
        let text = call(&[&both[..], &time].concat()).unwrap();
        let json = ic_json::parse(&text).unwrap();
        let definition = json.get("component-definition").unwrap();
        let metadata = definition.get("metadata").unwrap();
        assert_eq!(
            metadata.get("title").and_then(Json::as_str),
            Some("IronSecurity component definition")
        );
        assert_eq!(
            metadata.get("version").and_then(Json::as_str),
            Some("ironcrypto-0.2.23+example-project-1.2.3")
        );
        let titles: Vec<&str> = definition
            .get("components")
            .and_then(Json::as_array)
            .unwrap()
            .iter()
            .map(|c| c.get("title").and_then(Json::as_str).unwrap())
            .collect();
        assert_eq!(titles, ["IronCrypto", "Example Project"]);
        // A project's file alone, and its summary.
        let alone = ["--source", "example.json"];
        call(&[&["component"][..], &alone, &time].concat()).unwrap();
        let summary = call(&[&["summary"][..], &alone].concat()).unwrap();
        assert!(summary.contains("\"component\":\"Example Project\""));
        assert!(summary.contains("\"not-implemented\":1"));
        // One project described twice is refused; so is the same file twice.
        assert!(matches!(
            call(&[&both[..], &["--source", "again.json"], &time].concat()),
            Err(Failure::Input(_))
        ));
        assert!(usage(
            &[&both[..], &["--source", "example.json"], &time].concat()
        ));
        // IronCrypto's own form is not the shared form, and the reverse.
        assert!(matches!(
            call(&[&["component", "--source", "controls.json"][..], &time].concat()),
            Err(Failure::Input(_))
        ));
        assert!(matches!(
            call(&[&["component", "--ironcrypto", "example.json"][..], &time].concat()),
            Err(Failure::Input(_))
        ));
    }

    #[test]
    fn wrong_arguments_are_refused_before_anything_is_read() {
        let base = ["component", "--ironcrypto", "missing.json"];
        // Usage errors come first: the missing file is never opened.
        assert!(usage(&base));
        for extra in [
            &["--last-modified", "yesterday"][..],
            &["--last-modified", "2026-10-10"],
            &["--last-modified", "2026-13-10T00:00:00Z"],
            &["--last-modified", "2026-10-10T00:00:00"],
            &[
                "--last-modified",
                "2026-10-10T00:00:00Z",
                "--framework",
                "cwe",
            ],
            &[
                "--last-modified",
                "2026-10-10T00:00:00Z",
                "--last-modified",
                "2026-10-11T00:00:00Z",
            ],
            &[
                "--last-modified",
                "2026-10-10T00:00:00Z",
                "--framework",
                "cmmc",
                "--framework",
                "cmmc",
            ],
            &["--last-modified"],
            &["--verbose"],
        ] {
            assert!(usage(&[&base[..], extra].concat()), "{extra:?}");
        }
        assert!(usage(&[]));
        assert!(usage(&["publish"]));
        assert!(usage(&[
            "component",
            "--last-modified",
            "2026-10-10T00:00:00Z"
        ]));
        assert!(usage(&[
            "summary",
            "--ironcrypto",
            "controls.json",
            "--output",
            "x"
        ]));
        assert!(usage(&[
            "summary",
            "--ironcrypto",
            "controls.json",
            "--last-modified",
            "2026-10-10T00:00:00Z"
        ]));
        for time in [
            "2026-10-10T00:00:00Z",
            "2026-10-10T23:59:60Z",
            "2026-10-10T00:00:00.125Z",
            "2026-10-10T00:00:00+05:30",
            "2026-10-10T00:00:00.5-08:00",
        ] {
            assert!(is_rfc3339(time), "{time}");
        }
        for time in [
            "2026-10-10T00:00:00.Z",
            "2026-10-10T24:00:00Z",
            "2026-10-10T00:00:00+24:00",
            "2026-10-10t00:00:00Z",
            "2026-10-10T00:00:00Zjunk",
            "２０２６-10-10T00:00:00Z",
        ] {
            assert!(!is_rfc3339(time), "{time}");
        }
    }

    #[test]
    fn unreadable_or_refused_input_is_an_input_failure() {
        let with = |path: &str| {
            call(&[
                "component",
                "--ironcrypto",
                path,
                "--last-modified",
                "2026-10-10T00:00:00Z",
            ])
        };
        assert!(matches!(with("missing.json"), Err(Failure::Input(_))));
        // An export that claims FIPS validation is refused, not passed on.
        assert!(matches!(with("validated.json"), Err(Failure::Input(_))));
        assert!(with("controls.json").is_ok());
    }
}
