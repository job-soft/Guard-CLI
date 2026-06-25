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
        /// Glob pattern to skip (relative to `path`); repeatable, e.g. `--exclude 'vendor/**'`
        #[arg(long = "exclude", value_name = "GLOB")]
        exclude: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { path, json, exclude } => match scan_directory(&path, &exclude) {
            Ok(findings) => {
                if json {
                    if let Err(e) = print_json(&findings) {
                        eprintln!("{} {}", "error:".red().bold(), e);
                        std::process::exit(2);
                    }
                } else {
                    print_pretty(&findings, path.display().to_string());
                }
                let any_high = findings
                    .iter()
                    .any(|f| matches!(f.severity, Severity::High));
                if any_high {
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("{} {}", "error:".red().bold(), e);
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
            Severity::Medium => "MEDIUM".yellow().bold(),
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
}
