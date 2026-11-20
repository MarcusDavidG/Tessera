//! Atomic multilateral batch settlement engine (issue #316).
//!
//! Bilateral pairs in tokenized secondary markets are often illiquid. A
//! multilateral cross-trade lets N participants settle a ring of trades —
//! A pays B in a real-estate token, B pays C in a bond token, C pays A in
//! USDC — as one indivisible unit, so nobody delivers their leg without
//! receiving theirs.
//!
//! The settlement contract never takes custody. Each leg is a direct
//! `token.transfer(from, to, amount)` invoked by this contract on the
//! sender's behalf, so every sender must authorize the batch (their auth
//! entry covers this contract's root invocation and the token transfer
//! sub-invocations it makes). All validation — graph shape, conservation,
//! balances, compliance — runs before the first transfer, and the transfers
//! themselves run inside the same Soroban invocation: any panic anywhere
//! (failed auth, an underfunded sender, a token refusing a transfer) aborts
//! the transaction and rolls back every leg already applied.
//!
//! Tokens must be registered by the admin before they can appear in a batch,
//! either as *regulated* (bound to the compliance contract whose
//! `is_allowed(address) -> bool` gates every leg in that token) or explicitly
//! as *unregulated* (e.g. a USDC Stellar Asset Contract used as the cash leg).
//! An unregistered token fails closed.
#![no_std]

mod batch_settler;
mod dvp;

#[cfg(test)]
mod dvp_test;
#[cfg(test)]
mod test;

pub use batch_settler::{AssetPolicy, TradeLeg, MAX_LEGS};
pub use dvp::{InstructionStatus, SettlementInstruction, MAX_NET_INSTRUCTIONS};

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, Address, BytesN, Env,
    Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    Paused = 4,
    /// The batch is empty or longer than [`MAX_LEGS`].
    InvalidBatchSize = 5,
    /// A leg has a non-positive amount.
    InvalidAmount = 6,
    /// A leg sends a token from an account to itself.
    SelfTransfer = 7,
    /// A leg uses a token that has not been registered with the engine.
    AssetNotRegistered = 8,
    /// A leg is not part of any directed cycle in the trade graph, i.e. it
    /// is a one-way transfer with nothing flowing back to its sender.
    LegNotInCycle = 9,
    /// Inflows and outflows of a token do not net to zero across the batch,
    /// or an account that both receives and forwards the same token does not
    /// pass it through in full.
    ConservationViolation = 10,
    /// A sender cannot fund its legs from its current balance plus what the
    /// batch delivers to it.
    InsufficientBalance = 11,
    /// The token's compliance contract rejected a leg's sender.
    SenderNotCompliant = 12,
    /// The token's compliance contract rejected a leg's recipient.
    RecipientNotCompliant = 13,
    Overflow = 14,
    /// No settlement instruction exists with that id.
    InstructionNotFound = 15,
    /// The instruction has already been settled.
    InstructionNotPending = 16,
    /// The current ledger is before the instruction's settlement ledger.
    SettlementNotDue = 17,
    /// Only the buyer or the seller of an instruction may settle it.
    NotSettlementParty = 18,
    /// The instruction names a settlement ledger before the current one.
    InvalidSettlementLedger = 19,
    /// The same instruction id appears twice in one netting set.
    DuplicateInstruction = 20,
    /// The settlement guarantee fund has not been configured.
    GuaranteeNotConfigured = 21,
    /// The shortfall exceeds the fund's `max_guarantee_amount`.
    GuaranteeLimitExceeded = 22,
    /// The fund's reserve for the payment asset cannot cover the shortfall.
    GuaranteeInsufficient = 23,
}

#[derive(Clone)]
#[contracttype]
pub(crate) enum DataKey {
    Admin,
    /// Registration of a token: its [`AssetPolicy`].
    Asset(Address),
    /// Number of batches settled so far; the next batch's id.
    BatchCount,
    /// Number of DvP settlement instructions created; the next id.
    InstructionCount,
    /// A DvP settlement instruction by id.
    Instruction(u32),
    /// Admin-configured cap on a single guarantee-fund advance.
    GuaranteeMax,
    /// Guarantee-fund reserve held by the contract, per token.
    GuaranteeReserve(Address),
    /// What a buyer owes the guarantee fund, per token.
    GuaranteeClaim(Address, Address),
}

#[contract]
pub struct SettlementContract;

#[contractimpl]
impl SettlementContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(env, Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::BatchCount, &0u64);
    }

    /// Register `token` as tradeable in batches. `compliance` is the
    /// compliance contract that gates the token; `None` registers it as an
    /// unregulated settlement asset (a cash leg such as USDC).
    #[allow(deprecated)] // Same `events().publish` style as the other Tessera contracts.
    pub fn register_asset(env: Env, admin: Address, token: Address, compliance: Option<Address>) {
        Self::require_admin(&env, &admin);
        let policy = match compliance.clone() {
            Some(c) => AssetPolicy::Regulated(c),
            None => AssetPolicy::Unregulated,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Asset(token.clone()), &policy);
        env.events()
            .publish((soroban_sdk::symbol_short!("asset_reg"), token), compliance);
    }

    #[allow(deprecated)] // Same `events().publish` style as the other Tessera contracts.
    pub fn deregister_asset(env: Env, admin: Address, token: Address) {
        Self::require_admin(&env, &admin);
        env.storage()
            .persistent()
            .remove(&DataKey::Asset(token.clone()));
        env.events()
            .publish((soroban_sdk::symbol_short!("asset_del"), token), ());
    }

    pub fn get_asset_policy(env: Env, token: Address) -> Option<AssetPolicy> {
        env.storage().persistent().get(&DataKey::Asset(token))
    }

    /// Validate and atomically execute a multilateral cross-trade.
    ///
    /// Returns the batch id. See [`batch_settler`] for the full rule set;
    /// every rule is checked before the first transfer, and any failure —
    /// including one raised by a token during execution — reverts every leg.
    #[allow(deprecated)] // Same `events().publish` style as the other Tessera contracts.
    pub fn execute_multilateral_settlement(env: Env, trade_legs: Vec<TradeLeg>) -> u64 {
        if tessera_common::is_paused(&env) {
            panic_with_error!(env, Error::Paused);
        }
        if !env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(env, Error::NotInitialized);
        }

        batch_settler::settle(&env, &trade_legs);

        let batch_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::BatchCount)
            .unwrap_or(0);
        let next = batch_id
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(env, Error::Overflow));
        env.storage().instance().set(&DataKey::BatchCount, &next);
        env.events().publish(
            (soroban_sdk::symbol_short!("settled"), batch_id),
            trade_legs.len(),
        );
        batch_id
    }

    /// Run every pre-execution check on `trade_legs` without moving funds or
    /// requiring auth. Panics with the same error the real settlement would.
    pub fn validate_settlement(env: Env, trade_legs: Vec<TradeLeg>) {
        batch_settler::validate(&env, &trade_legs);
    }

    // -----------------------------------------------------------------
    // T+0 delivery-versus-payment instructions (issue #390)
    // -----------------------------------------------------------------

    /// Create a settlement instruction signed by both counterparties. The
    /// seller will deliver `amount` of `asset`; the buyer will pay
    /// `payment_amount` of `payment_asset`; it becomes settleable on
    /// `settlement_ledger`. Returns the instruction id.
    pub fn create_instruction(
        env: Env,
        buyer: Address,
        seller: Address,
        asset: Address,
        amount: i128,
        payment_asset: Address,
        payment_amount: i128,
        settlement_ledger: u32,
    ) -> u32 {
        Self::ensure_active(&env);
        dvp::create_instruction(
            &env,
            &buyer,
            &seller,
            &asset,
            amount,
            &payment_asset,
            payment_amount,
            settlement_ledger,
        )
    }

    /// Atomically settle one due instruction: asset from seller to buyer and
    /// payment from buyer to seller in the same invocation. Either party may
    /// call it. Returns the amount the guarantee fund advanced (0 if none).
    pub fn settle(env: Env, caller: Address, instruction_id: u32) -> i128 {
        Self::ensure_active(&env);
        dvp::settle(&env, &caller, instruction_id)
    }

    /// Net-settle a set of due instructions with the fewest transfers.
    /// Returns the number of transfers executed. Every account whose net
    /// position is negative must have authorized the call.
    pub fn net_settle(env: Env, instruction_ids: Vec<u32>) -> u32 {
        Self::ensure_active(&env);
        dvp::net_settle(&env, &instruction_ids)
    }

    pub fn get_instruction(env: Env, instruction_id: u32) -> SettlementInstruction {
        dvp::instruction(&env, instruction_id)
    }

    pub fn instruction_count(env: Env) -> u32 {
        dvp::instruction_count(&env)
    }

    /// Set the largest shortfall the guarantee fund may cover per settlement.
    pub fn configure_guarantee_fund(env: Env, admin: Address, max_guarantee_amount: i128) {
        dvp::configure_guarantee_fund(&env, &admin, max_guarantee_amount);
    }

    /// Deposit `amount` of `token` into the guarantee reserve.
    pub fn deposit_guarantee(env: Env, admin: Address, token: Address, amount: i128) {
        dvp::deposit_guarantee(&env, &admin, &token, amount);
    }

    /// Repay part of what the fund advanced on `buyer`'s behalf.
    pub fn repay_guarantee(env: Env, buyer: Address, token: Address, amount: i128) {
        dvp::repay_guarantee(&env, &buyer, &token, amount);
    }

    pub fn guarantee_max(env: Env) -> i128 {
        dvp::guarantee_max(&env)
    }

    pub fn guarantee_reserve(env: Env, token: Address) -> i128 {
        dvp::guarantee_reserve(&env, &token)
    }

    pub fn guarantee_claim(env: Env, buyer: Address, token: Address) -> i128 {
        dvp::guarantee_claim(&env, &buyer, &token)
    }

    pub fn batch_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::BatchCount)
            .unwrap_or(0)
    }

    pub fn pause(env: Env, admin: Address) {
        Self::require_admin(&env, &admin);
        tessera_common::set_paused(&env, true);
    }

    pub fn unpause(env: Env, admin: Address) {
        Self::require_admin(&env, &admin);
        tessera_common::set_paused(&env, false);
    }

    pub fn upgrade(env: Env, admin: Address, new_wasm_hash: BytesN<32>) {
        Self::require_admin(&env, &admin);
        tessera_common::upgrade(&env, new_wasm_hash);
    }

    fn ensure_active(env: &Env) {
        if tessera_common::is_paused(env) {
            panic_with_error!(env, Error::Paused);
        }
        if !env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(env, Error::NotInitialized);
        }
    }
}

impl SettlementContract {
    pub(crate) fn require_admin(env: &Env, admin: &Address) {
        let stored: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(env, Error::NotInitialized));
        admin.require_auth();
        if admin != &stored {
            panic_with_error!(env, Error::Unauthorized);
        }
    }
}
