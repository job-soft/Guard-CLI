//! Vulnerability detectors for Soroban smart contracts.

pub mod admin;
pub mod auth;
pub mod division;
pub mod hardcoded_address;
pub mod overflow;
pub mod panics;
pub mod reentrancy;
pub mod std_imports;
pub mod storage;
pub mod ttl;
pub mod zero_address;
mod util;

pub use admin::UnprotectedAdminCheck;
pub use auth::MissingRequireAuthCheck;
pub use division::IntegerDivisionTruncationCheck;
pub use hardcoded_address::HardcodedAddressCheck;
pub use overflow::UncheckedArithmeticCheck;
pub use panics::PanicInContractCheck;
pub use reentrancy::ReentrancyRiskCheck;
pub use std_imports::ForbiddenStdImportsCheck;
pub use storage::UnsafeStoragePatternsCheck;
pub use ttl::MissingTtlExtensionCheck;
pub use zero_address::MissingZeroAddressCheck;

use serde::Serialize;
use syn::File;

/// Severity of a finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
}

/// One issue reported by a check.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Finding {
    pub check_name: String,
    pub severity: Severity,
    pub file_path: String,
    pub line: usize,
    pub function_name: String,
    pub description: String,
    /// Link to the check's documentation section (exposed in `--json` output for dashboard integrations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_url: Option<String>,
}

/// A static analyzer check implemented against a parsed `syn::File`.
pub trait Check {
    fn name(&self) -> &str;
    fn run(&self, file: &File, source: &str) -> Vec<Finding>;
}

/// All checks executed by the analyzer (extend here as you add detectors).
///
/// Checks are **stateless and isolated**: implementations must not use shared mutable
/// static state or assume a particular invocation order. The analyzer runs each check
/// against the same parsed `syn::File` independently and concatenates `Finding`s.
pub fn default_checks() -> Vec<Box<dyn Check + Send + Sync>> {
    vec![
        Box::new(MissingRequireAuthCheck),
        Box::new(UncheckedArithmeticCheck),
        Box::new(UnprotectedAdminCheck),
        Box::new(UnsafeStoragePatternsCheck),
        Box::new(MissingTtlExtensionCheck),
        Box::new(ForbiddenStdImportsCheck),
        Box::new(HardcodedAddressCheck),
        Box::new(ReentrancyRiskCheck),
        Box::new(IntegerDivisionTruncationCheck),
        Box::new(PanicInContractCheck),
        Box::new(MissingZeroAddressCheck),
    ]
}
