#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct ReentrancyVulnerable;

#[contractimpl]
impl ReentrancyVulnerable {
    /// Writes to storage and then calls an untrusted contract — should trigger
    /// `reentrancy-risk` (High).
    pub fn transfer(env: Env, to: Address, amount: i128) {
        env.storage().persistent().set(&symbol_short!("bal"), &amount);
        // ❌ cross-contract call after write — callee can re-enter
        env.invoke_contract::<()>(
            &to,
            &symbol_short!("recv"),
            soroban_sdk::vec![&env],
        );
    }
}
