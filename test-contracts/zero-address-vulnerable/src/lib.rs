#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct ZeroAddressVulnerable;

#[contractimpl]
impl ZeroAddressVulnerable {
    /// Accepts Address without checking for zero/default — should trigger
    /// `missing-zero-address-check` (Medium).
    pub fn set_owner(env: Env, new_owner: Address) {
        // ❌ no zero-address check; passing a default address locks the contract
        env.storage()
            .instance()
            .set(&symbol_short!("owner"), &new_owner);
    }
}
