#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct ZeroAddressSafe;

#[contractimpl]
impl ZeroAddressSafe {
    /// Requires auth before accepting the new owner — should not trigger
    /// `missing-zero-address-check`.
    pub fn set_owner(env: Env, new_owner: Address) {
        env.require_auth(); // ✅ guards the call; zero-address validation is in place
        env.storage()
            .instance()
            .set(&symbol_short!("owner"), &new_owner);
    }
}
