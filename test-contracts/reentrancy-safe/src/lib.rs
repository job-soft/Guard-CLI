#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct ReentrancySafe;

#[contractimpl]
impl ReentrancySafe {
    /// Calls the external contract first, then writes — should not trigger
    /// `reentrancy-risk`.
    pub fn transfer(env: Env, to: Address, amount: i128) {
        // ✅ external call happens before any storage write
        env.invoke_contract::<()>(
            &to,
            &symbol_short!("recv"),
            soroban_sdk::vec![&env],
        );
        env.storage().persistent().set(&symbol_short!("bal"), &amount);
    }
}
