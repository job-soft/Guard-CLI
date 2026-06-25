use clap::{Parser, Subcommand};
use colored::Colorize;
use soroban_guard_analyzer::scan_directory;
use soroban_guard_checks::{Finding, Severity};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "soroban-guard")]
#[command(
    about = "Soroban Guard Core — static analyzer for Soroban smart contracts",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory tree for vulnerability patterns
    Scan {
        /// Path to the contract crate or folder containing Rust sources
        path: PathBuf,
        /// Print findings as JSON (`{ "findings": [...] }`)
        #[arg(long)]
        json: bool,
        /// Suppress all output when there are zero High findings
        #[arg(long)]
        quiet: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { path, json, quiet } => match scan_directory(&path) {
            Ok(findings) => {
                let any_high = findings
                    .iter()
                    .any(|f| matches!(f.severity, Severity::High));

                if json {
                    if !quiet || any_high {
                        if let Err(e) = print_json(&findings) {
                            eprintln!("{} {}", "error:".red().bold(), e);
                            std::process::exit(2);
                        }
                    }
                } else {
                    if !quiet || any_high {
                        print_pretty(&findings, path.display().to_string());
                    }
                }

                if any_high {
                    std::process::exit(1);
                }
            }
            Err(e) => {
                if json {
                    let envelope = serde_json::json!({ "error": e.to_string() });
                    println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
                } else {
                    eprintln!("{} {}", "error:".red().bold(), e);
                }
                std::process::exit(2);
            }
        },
    }
}

fn print_json(findings: &[Finding]) -> Result<(), serde_json::Error> {
    #[derive(serde::Serialize)]
    struct Out<'a> {
        findings: &'a [Finding],
    }
    let json = serde_json::to_string_pretty(&Out { findings })?;
    println!("{json}");
    Ok(())
}

fn print_pretty(findings: &[Finding], root_label: String) {
    println!();
    println!(
        "{} {}",
        "Soroban Guard Core".cyan().bold(),
        format!("(scan: {})", root_label).dimmed()
    );
    println!();

    if findings.is_empty() {
        println!("  {}", "No issues found.".green());
        println!();
        return;
    }

    println!(
        "  {} finding(s):\n",
        findings.len().to_string().yellow().bold()
    );

    for (i, f) in findings.iter().enumerate() {
        let sev = match f.severity {
            Severity::High => "HIGH".red().bold(),
            Severity::Medium => "MEDIUM".magenta().bold(),  // #46 bold magenta
            Severity::Low => "LOW".white(),
        };
        println!(
            "  {}  {}  {}  {}",
            format!("[{}]", i + 1).dimmed(),
            sev,
            format!("{}:{}", f.file_path, f.line).bright_white(),
            f.check_name.cyan()
        );
        println!("         {} `{}`", "function:".dimmed(), f.function_name);
        println!("         {}", f.description);
        println!();
    }

    // #47 summary line
    let high = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();
    let medium = findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count();
    let low = findings.iter().filter(|f| matches!(f.severity, Severity::Low)).count();
    println!(
        "  {} {}, {} {}, {} {}",
        high.to_string().red().bold(),
        "High".red().bold(),
        medium.to_string().magenta().bold(),
        "Medium".magenta().bold(),
        low.to_string().white(),
        "Low".white(),
    );
    println!();
}
