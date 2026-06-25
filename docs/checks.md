# Checks reference

This document describes what each Soroban Guard Core check looks for and why it matters.

---

## `missing-require-auth` (High)

**Status:** Phase 1

**What it detects**

In an `impl` block marked with `#[contractimpl]` or `#[soroban_sdk::contractimpl]`, any function whose body:

1. Performs a storage mutation through `env.storage()` (heuristic: method calls `set`, `remove`, `extend_ttl`, `bump`, or `append` on a receiver chain that includes `.storage()`), and  
2. Never calls `env.require_auth()` (parameter name **`env`**: `env.require_auth()`).

**Why it matters**

Contract state updates should be gated. This rule only recognizes `env.require_auth()`, not `user.require_auth()` or `env.require_auth_for_args()`.

**Limitations**

- Only the `Env` binding named `env` counts.
- Static analysis cannot see auth hidden in helpers.

**Fixture:** `test-contracts/vulnerable/`, `test-contracts/safe/`

---

## `unchecked-arithmetic` (Medium)

**Status:** Phase 2

**What it detects**

Inside `#[contractimpl]` methods:

- Binary `+`, `-`, `*` where **both** sides are not integer/string literals (so `1 + 2` is ignored, `a + b` is flagged).
- Compound `+=`, `-=`, `*=` (syn 2 represents these as `ExprBinary` with `AddAssign` / `SubAssign` / `MulAssign`).

**Why it matters**

Wrapping arithmetic on `i128` / `u128` amounts can silently overflow. Prefer `checked_*` or `saturating_*` for token math.

**Limitations**

- May flag harmless loop indices; review context.
- Does not analyze types; it is syntactic.

**Fixture:** `test-contracts/arithmetic-vulnerable/`, `test-contracts/arithmetic-safe/`

---

## `unprotected-admin` (High)

**Status:** Phase 2

**What it detects**

Public (`pub fn`) methods in `#[contractimpl]` whose name **exactly matches** a built-in list of sensitive entrypoints (e.g. `set_owner`, `pause`, `migrate`, `upgrade`, … — see `SENSITIVE_NAMES` in `crates/checks/src/admin.rs`), and whose body contains **no** call to `require_auth` or `require_auth_for_args` on any receiver.

**Why it matters**

Names like `set_owner` strongly suggest privilege; without any auth call the scanner treats the entrypoint as world-callable.

**Limitations**

- Name allowlist only; extend the list as your org sees fit.
- Any `require_auth` / `require_auth_for_args` anywhere in the body clears the finding (no dataflow).

**Fixture:** `test-contracts/admin-vulnerable/`, `test-contracts/admin-safe/`

---

## `unsafe-storage-patterns` (Medium)

**Status:** Phase 2

**What it detects**

1. **Temporary storage writes** — `env.storage().temporary()` in the receiver chain of a storage mutation (`set`, `remove`, `extend_ttl`, `bump`, `append`).
2. **Dynamic `Symbol::new` keys** — `Symbol::new(&env, …)` where the second argument is **not** a string literal (e.g. derived from a parameter). Literal second args like `Symbol::new(&env, "fixed")` are ignored.

**Why it matters**

- Temporary data expires with TTL; it is easy to misuse for long-lived balances or ownership.
- Caller-derived symbol strings are easier to enumerate or collide than fixed `symbol_short!` keys.

**Limitations**

- Does not analyze `symbol_short!(...)` macros beyond normal parsing.
- `Symbol::new` with a `const` or macro-expanded literal may still be flagged if it is not a `syn::Lit::Str`.

**Fixture:** `test-contracts/storage-vulnerable/`, `test-contracts/storage-safe/`

---

## `reentrancy-risk` (High)

**Status:** Phase 3

**What it detects**

Inside `#[contractimpl]` methods, any call to `invoke_contract` or `invoke_contract_check` that occurs **after** a storage write (`set`, `remove`, `extend_ttl`, `bump`, `append`) and **before** a subsequent storage read (which would indicate the developer re-checked state after the call).

**Why it matters**

Soroban's cross-contract call API allows calling untrusted contracts. If state has been mutated before the call, the callee can observe or re-enter the contract in an intermediate state. The checks-effects-interactions pattern (write last, or re-read state) eliminates the risk.

**Limitations**

- Purely sequential within a single method body; does not follow helper calls.
- A storage read anywhere after the write clears the flag regardless of whether it covers the written key.

**Fixture:** `test-contracts/reentrancy-vulnerable/`, `test-contracts/reentrancy-safe/`

---

## `integer-division-truncation` (Medium)

**Status:** Phase 3

**What it detects**

Inside `#[contractimpl]` methods, binary `/` where **at least one operand is not an integer literal**, and `/=` compound assignments. Literal-only expressions such as `6 / 2` are ignored.

**Why it matters**

Integer division silently truncates towards zero. In token arithmetic this can cause value to be drained: `1_000_001 / 2` returns `500_000`, losing one unit. Prefer `checked_div` or explicit rounding logic when the result must be exact.

**Limitations**

- Syntactic only; does not track operand types.
- May flag intentional floor division; treat as a review signal.

**Fixture:** `test-contracts/division-vulnerable/`, `test-contracts/division-safe/`

---

## `panic-in-contract` (Medium)

**Status:** Phase 3

**What it detects**

Inside `#[contractimpl]` methods:

- `.unwrap()` and `.expect(…)` method calls.
- `panic!(…)` and `unreachable!()` macro invocations.

**Why it matters**

`panic!` and its equivalents abort the transaction with an unhelpful, opaque error. Prefer `env.panic_with_error` (typed SDK errors) or returning a `Result` with a descriptive error type so callers receive actionable feedback.

**Limitations**

- Flags all `unwrap` / `expect` calls regardless of whether the `Option` / `Result` can actually be `None` / `Err` at runtime.
- Does not distinguish `unwrap_or`, `unwrap_or_default`, etc. (those are not flagged).

**Fixture:** `test-contracts/panic-vulnerable/`, `test-contracts/panic-safe/`

---

## `missing-zero-address-check` (Medium)

**Status:** Phase 3

**What it detects**

Public `#[contractimpl]` methods whose name matches a set of sensitive admin/ownership entrypoints (e.g. `set_owner`, `set_admin`, `initialize`, `transfer_ownership`, …) that:

1. Accept at least one `Address` parameter, **and**
2. Do not contain any of: `require_auth`, an `assert!` / `require!` macro, or a call whose name contains `zero`, `default`, `check_address`, `assert`, or `validate`.

**Why it matters**

Passing a zero or default `Address` to an admin function can permanently lock the contract if there is no recovery path. A simple non-zero guard at the entry point prevents this.

**Limitations**

- Name-list heuristic; extend `SENSITIVE_NAMES` in `crates/checks/src/zero_address.rs` for custom entrypoint names.
- Any matching call name clears the finding regardless of whether it actually validates the address value.

**Fixture:** `test-contracts/zero-address-vulnerable/`, `test-contracts/zero-address-safe/`
