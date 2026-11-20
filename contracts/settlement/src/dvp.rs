//! T+0 delivery-versus-payment (DvP) settlement instructions (issue #390).
//!
//! A bilateral *instruction* records what one party owes another: the seller
//! delivers `amount` of `asset`, the buyer pays `payment_amount` of
//! `payment_asset`, on `settlement_ledger`. Both parties sign the instruction
//! when it is created; from then on either party may call [`settle`] on or
//! after the settlement ledger.
//!
//! Settlement executes two cross-contract token transfers inside one Soroban
//! invocation — the asset leg (seller → buyer) and the payment leg (buyer →
//! seller). Soroban rolls the whole invocation back if any call panics, so a
//! failure in either leg can never leave the other leg applied: delivery and
//! payment are atomic.
//!
//! [`net_settle`] takes a set of due instructions and replaces their gross
//! legs with the minimum number of transfers. Per token it computes every
//! account's net position and matches debtors to creditors greedily; each
//! transfer clears either a debtor or a creditor, so a token with `d` debtors
//! and `c` creditors settles in exactly `d + c - 1` transfers instead of the
//! `2 * instructions` gross legs.
//!
//! The **settlement guarantee fund** covers the payment leg when the buyer is
//! short of cash: up to [`configure_guarantee_fund`]'s `max_guarantee_amount`
//! per instruction, drawn from the reserve the admin deposited with
//! [`deposit_guarantee`]. The fund pays the seller the shortfall and books a
//! claim against the buyer, which the buyer later clears with
//! [`repay_guarantee`].

use soroban_sdk::{
    contracttype, panic_with_error, token, Address, Env, IntoVal, Map, Symbol, Val, Vec,
};

use crate::batch_settler::AssetPolicy;
use crate::{DataKey, Error};

/// Maximum number of instructions one [`net_settle`] call may combine. Bounds
/// every loop below; the resulting transfer list is at most `2 * this` legs.
pub const MAX_NET_INSTRUCTIONS: u32 = 32;

/// Lifecycle of a settlement instruction.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstructionStatus {
    Pending,
    Settled,
}

/// A signed, not-yet-settled delivery-versus-payment instruction.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementInstruction {
    pub buyer: Address,
    pub seller: Address,
    /// Asset delivered by the seller.
    pub asset: Address,
    /// Units of `asset` delivered.
    pub amount: i128,
    /// Asset paid by the buyer.
    pub payment_asset: Address,
    /// Units of `payment_asset` paid.
    pub payment_amount: i128,
    /// Ledger sequence on or after which the instruction may settle.
    pub settlement_ledger: u32,
    pub status: InstructionStatus,
}

/// A partially netted position during [`net_settle`].
#[derive(Clone)]
struct Position {
    account: Address,
    amount: i128,
}

/// A planned transfer: `amount` of `token` from `from` to `to`.
#[derive(Clone)]
struct PlannedTransfer {
    from: Address,
    to: Address,
    token: Address,
    amount: i128,
}

fn load_instruction(env: &Env, id: u32) -> SettlementInstruction {
    env.storage()
        .persistent()
        .get(&DataKey::Instruction(id))
        .unwrap_or_else(|| panic_with_error!(env, Error::InstructionNotFound))
}

fn asset_policy(env: &Env, token: &Address) -> AssetPolicy {
    env.storage()
        .persistent()
        .get(&DataKey::Asset(token.clone()))
        .unwrap_or_else(|| panic_with_error!(env, Error::AssetNotRegistered))
}

/// Fail unless `account` may hold `token` per its registered policy. Answers
/// are not cached: compliance can change between instruction creation and
/// settlement, so both points re-check it.
fn ensure_allowed(env: &Env, token: &Address, account: &Address, is_sender: bool) {
    if let AssetPolicy::Regulated(compliance) = asset_policy(env, token) {
        let args: Vec<Val> = (account.clone(),).into_val(env);
        let allowed: bool =
            env.invoke_contract(&compliance, &Symbol::new(env, "is_allowed"), args);
        if !allowed {
            if is_sender {
                panic_with_error!(env, Error::SenderNotCompliant);
            }
            panic_with_error!(env, Error::RecipientNotCompliant);
        }
    }
}

fn check_instruction_compliance(env: &Env, instruction: &SettlementInstruction) {
    ensure_allowed(env, &instruction.asset, &instruction.seller, true);
    ensure_allowed(env, &instruction.asset, &instruction.buyer, false);
    ensure_allowed(env, &instruction.payment_asset, &instruction.buyer, true);
    ensure_allowed(env, &instruction.payment_asset, &instruction.seller, false);
}

#[allow(deprecated)] // Same `events().publish` style as the other Tessera contracts.
pub(crate) fn create_instruction(
    env: &Env,
    buyer: &Address,
    seller: &Address,
    asset: &Address,
    amount: i128,
    payment_asset: &Address,
    payment_amount: i128,
    settlement_ledger: u32,
) -> u32 {
    if buyer == seller {
        panic_with_error!(env, Error::SelfTransfer);
    }
    if amount <= 0 || payment_amount <= 0 {
        panic_with_error!(env, Error::InvalidAmount);
    }
    if settlement_ledger < env.ledger().sequence() {
        panic_with_error!(env, Error::InvalidSettlementLedger);
    }
    // Fails closed for unregistered tokens and for a party the compliance
    // contract rejects at signing time.
    check_instruction_compliance(
        env,
        &SettlementInstruction {
            buyer: buyer.clone(),
            seller: seller.clone(),
            asset: asset.clone(),
            amount,
            payment_asset: payment_asset.clone(),
            payment_amount,
            settlement_ledger,
            status: InstructionStatus::Pending,
        },
    );

    // Both counterparties sign the instruction itself.
    buyer.require_auth();
    seller.require_auth();

    let id: u32 = env
        .storage()
        .instance()
        .get(&DataKey::InstructionCount)
        .unwrap_or(0);
    let next = id
        .checked_add(1)
        .unwrap_or_else(|| panic_with_error!(env, Error::Overflow));
    env.storage()
        .instance()
        .set(&DataKey::InstructionCount, &next);
    env.storage().persistent().set(
        &DataKey::Instruction(id),
        &SettlementInstruction {
            buyer: buyer.clone(),
            seller: seller.clone(),
            asset: asset.clone(),
            amount,
            payment_asset: payment_asset.clone(),
            payment_amount,
            settlement_ledger,
            status: InstructionStatus::Pending,
        },
    );
    env.events().publish(
        (soroban_sdk::symbol_short!("dvp_new"), id),
        (buyer.clone(), seller.clone(), amount, payment_amount),
    );
    id
}

/// Atomically deliver the asset and pay for it. Returns the amount the
/// guarantee fund had to advance (0 when the buyer funded the payment).
#[allow(deprecated)] // Same `events().publish` style as the other Tessera contracts.
pub(crate) fn settle(env: &Env, caller: &Address, id: u32) -> i128 {
    let instruction = load_instruction(env, id);
    if instruction.status != InstructionStatus::Pending {
        panic_with_error!(env, Error::InstructionNotPending);
    }
    if caller != &instruction.buyer && caller != &instruction.seller {
        panic_with_error!(env, Error::NotSettlementParty);
    }
    caller.require_auth();
    if env.ledger().sequence() < instruction.settlement_ledger {
        panic_with_error!(env, Error::SettlementNotDue);
    }
    check_instruction_compliance(env, &instruction);

    // Leg 1 — delivery. If leg 2 panics, Soroban reverts this transfer too.
    token::TokenClient::new(env, &instruction.asset).transfer(
        &instruction.seller,
        &instruction.buyer,
        &instruction.amount,
    );

    // Leg 2 — payment, with the guarantee fund covering a cash shortfall.
    let due = instruction.payment_amount;
    let buyer_balance =
        token::TokenClient::new(env, &instruction.payment_asset).balance(&instruction.buyer);
    let paid_by_buyer = buyer_balance.min(due);
    let guarantee_used = due - paid_by_buyer;
    if paid_by_buyer > 0 {
        token::TokenClient::new(env, &instruction.payment_asset).transfer(
            &instruction.buyer,
            &instruction.seller,
            &paid_by_buyer,
        );
    }
    if guarantee_used > 0 {
        draw_guarantee(
            env,
            &instruction.buyer,
            &instruction.seller,
            &instruction.payment_asset,
            guarantee_used,
        );
    }

    let mut settled = instruction;
    settled.status = InstructionStatus::Settled;
    env.storage()
        .persistent()
        .set(&DataKey::Instruction(id), &settled);
    env.events().publish(
        (soroban_sdk::symbol_short!("dvp_set"), id),
        (settled.buyer.clone(), settled.seller.clone(), guarantee_used),
    );
    guarantee_used
}

/// Net-settle a set of due instructions with the fewest possible transfers.
/// Returns the number of transfers executed.
#[allow(deprecated)] // Same `events().publish` style as the other Tessera contracts.
pub(crate) fn net_settle(env: &Env, instruction_ids: &Vec<u32>) -> u32 {
    let count = instruction_ids.len();
    if count == 0 || count > MAX_NET_INSTRUCTIONS {
        panic_with_error!(env, Error::InvalidBatchSize);
    }

    let mut seen: Vec<u32> = Vec::new(env);
    let mut instructions: Vec<SettlementInstruction> = Vec::new(env);
    for i in 0..count {
        let id = instruction_ids.get_unchecked(i);
        if seen.contains(&id) {
            panic_with_error!(env, Error::DuplicateInstruction);
        }
        seen.push_back(id);

        let instruction = load_instruction(env, id);
        if instruction.status != InstructionStatus::Pending {
            panic_with_error!(env, Error::InstructionNotPending);
        }
        if env.ledger().sequence() < instruction.settlement_ledger {
            panic_with_error!(env, Error::SettlementNotDue);
        }
        check_instruction_compliance(env, &instruction);
        instructions.push_back(instruction);
    }

    // (token, account) -> net position. Positive means the account receives
    // that token, negative that it pays it.
    let mut nets: Map<(Address, Address), i128> = Map::new(env);
    for instruction in instructions.iter() {
        add_net(
            env,
            &mut nets,
            &instruction.asset,
            &instruction.buyer,
            instruction.amount,
        );
        add_net(
            env,
            &mut nets,
            &instruction.asset,
            &instruction.seller,
            -instruction.amount,
        );
        add_net(
            env,
            &mut nets,
            &instruction.payment_asset,
            &instruction.buyer,
            -instruction.payment_amount,
        );
        add_net(
            env,
            &mut nets,
            &instruction.payment_asset,
            &instruction.seller,
            instruction.payment_amount,
        );
    }

    // Distinct tokens, in a deterministic order (Map iteration is sorted).
    let mut tokens: Vec<Address> = Vec::new(env);
    for ((token, _), net) in nets.iter() {
        if net != 0 && !tokens.contains(&token) {
            tokens.push_back(token);
        }
    }

    // Build the minimal transfer list: per token, match the largest net
    // debtors against the net creditors. Each transfer zeroes at least one
    // side, so `d` debtors and `c` creditors take exactly `d + c - 1` legacy
    // transfers — the minimum for a fully netted set.
    let mut planned: Vec<PlannedTransfer> = Vec::new(env);
    for t in 0..tokens.len() {
        let token = tokens.get_unchecked(t);
        let mut debtors: Vec<Position> = Vec::new(env);
        let mut creditors: Vec<Position> = Vec::new(env);
        for ((net_token, account), net) in nets.iter() {
            if &net_token != &token || net == 0 {
                continue;
            }
            if net < 0 {
                debtors.push_back(Position {
                    account,
                    amount: -net,
                });
            } else {
                creditors.push_back(Position {
                    account,
                    amount: net,
                });
            }
        }

        let mut debtor_ix = 0u32;
        let mut creditor_ix = 0u32;
        while debtor_ix < debtors.len() && creditor_ix < creditors.len() {
            let mut debtor = debtors.get_unchecked(debtor_ix);
            let mut creditor = creditors.get_unchecked(creditor_ix);
            let amount = debtor.amount.min(creditor.amount);
            debtor.amount -= amount;
            creditor.amount -= amount;
            let debtor_done = debtor.amount == 0;
            let creditor_done = creditor.amount == 0;
            planned.push_back(PlannedTransfer {
                from: debtor.account.clone(),
                to: creditor.account.clone(),
                token: token.clone(),
                amount,
            });
            debtors.set(debtor_ix, debtor);
            creditors.set(creditor_ix, creditor);
            if debtor_done {
                debtor_ix += 1;
            }
            if creditor_done {
                creditor_ix += 1;
            }
        }
        if debtor_ix < debtors.len() || creditor_ix < creditors.len() {
            // Net positions of a token must sum to zero; anything else means
            // an accounting bug, so fail closed rather than half-settle.
            panic_with_error!(env, Error::ConservationViolation);
        }
    }

    // Every account that pays must authorize, before the first transfer.
    let mut payers: Vec<Address> = Vec::new(env);
    for transfer in planned.iter() {
        if !payers.contains(&transfer.from) {
            transfer.from.require_auth();
            payers.push_back(transfer.from.clone());
        }
    }

    for transfer in planned.iter() {
        token::TokenClient::new(env, &transfer.token).transfer(
            &transfer.from,
            &transfer.to,
            &transfer.amount,
        );
    }

    for id in instruction_ids.iter() {
        let mut instruction = load_instruction(env, id);
        instruction.status = InstructionStatus::Settled;
        env.storage()
            .persistent()
            .set(&DataKey::Instruction(id), &instruction);
    }
    let executed = planned.len();
    env.events()
        .publish((soroban_sdk::symbol_short!("dvp_net"), executed), executed);
    executed
}

fn add_net(
    env: &Env,
    nets: &mut Map<(Address, Address), i128>,
    token: &Address,
    account: &Address,
    delta: i128,
) {
    let key = (token.clone(), account.clone());
    let current = nets.get(key.clone()).unwrap_or(0);
    let next = current
        .checked_add(delta)
        .unwrap_or_else(|| panic_with_error!(env, Error::Overflow));
    nets.set(key, next);
}

#[allow(deprecated)] // Same `events().publish` style as the other Tessera contracts.
pub(crate) fn configure_guarantee_fund(env: &Env, admin: &Address, max_guarantee_amount: i128) {
    crate::SettlementContract::require_admin(env, admin);
    if max_guarantee_amount < 0 {
        panic_with_error!(env, Error::InvalidAmount);
    }
    env.storage()
        .instance()
        .set(&DataKey::GuaranteeMax, &max_guarantee_amount);
    env.events()
        .publish((soroban_sdk::symbol_short!("gr_max"),), max_guarantee_amount);
}

#[allow(deprecated)] // Same `events().publish` style as the other Tessera contracts.
pub(crate) fn deposit_guarantee(env: &Env, admin: &Address, token: &Address, amount: i128) {
    crate::SettlementContract::require_admin(env, admin);
    if amount <= 0 {
        panic_with_error!(env, Error::InvalidAmount);
    }
    asset_policy(env, token);

    token::TokenClient::new(env, token).transfer(
        admin,
        &env.current_contract_address(),
        &amount,
    );
    let reserve = reserve_of(env, token);
    env.storage().persistent().set(
        &DataKey::GuaranteeReserve(token.clone()),
        &(reserve + amount),
    );
    env.events()
        .publish((soroban_sdk::symbol_short!("gr_dep"), token.clone()), amount);
}

/// Repay (part of) what the fund advanced for `buyer`, releasing the claim.
#[allow(deprecated)] // Same `events().publish` style as the other Tessera contracts.
pub(crate) fn repay_guarantee(env: &Env, buyer: &Address, token: &Address, amount: i128) {
    if amount <= 0 {
        panic_with_error!(env, Error::InvalidAmount);
    }
    let claim: i128 = env
        .storage()
        .persistent()
        .get(&DataKey::GuaranteeClaim(buyer.clone(), token.clone()))
        .unwrap_or(0);
    if amount > claim {
        panic_with_error!(env, Error::InvalidAmount);
    }
    buyer.require_auth();

    token::TokenClient::new(env, token).transfer(buyer, &env.current_contract_address(), &amount);
    env.storage().persistent().set(
        &DataKey::GuaranteeClaim(buyer.clone(), token.clone()),
        &(claim - amount),
    );
    let reserve = reserve_of(env, token);
    env.storage().persistent().set(
        &DataKey::GuaranteeReserve(token.clone()),
        &(reserve + amount),
    );
    env.events()
        .publish((soroban_sdk::symbol_short!("gr_rep"), buyer.clone()), amount);
}

fn reserve_of(env: &Env, token: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::GuaranteeReserve(token.clone()))
        .unwrap_or(0)
}

/// Pay `shortfall` of `token` from the guarantee reserve to `recipient` and
/// book it as a claim against `buyer`. Panics (reverting the settlement) when
/// the fund cannot cover the gap.
fn draw_guarantee(
    env: &Env,
    buyer: &Address,
    recipient: &Address,
    token: &Address,
    shortfall: i128,
) {
    let max: i128 = env
        .storage()
        .instance()
        .get(&DataKey::GuaranteeMax)
        .unwrap_or(0);
    if max <= 0 {
        panic_with_error!(env, Error::GuaranteeNotConfigured);
    }
    if shortfall > max {
        panic_with_error!(env, Error::GuaranteeLimitExceeded);
    }
    let reserve = reserve_of(env, token);
    if reserve < shortfall {
        panic_with_error!(env, Error::GuaranteeInsufficient);
    }

    env.storage().persistent().set(
        &DataKey::GuaranteeReserve(token.clone()),
        &(reserve - shortfall),
    );
    let claim: i128 = env
        .storage()
        .persistent()
        .get(&DataKey::GuaranteeClaim(buyer.clone(), token.clone()))
        .unwrap_or(0);
    env.storage().persistent().set(
        &DataKey::GuaranteeClaim(buyer.clone(), token.clone()),
        &(claim + shortfall),
    );

    token::TokenClient::new(env, token).transfer(
        &env.current_contract_address(),
        recipient,
        &shortfall,
    );
}

pub(crate) fn guarantee_max(env: &Env) -> i128 {
    env.storage()
        .instance()
        .get(&DataKey::GuaranteeMax)
        .unwrap_or(0)
}

pub(crate) fn guarantee_reserve(env: &Env, token: &Address) -> i128 {
    reserve_of(env, token)
}

pub(crate) fn guarantee_claim(env: &Env, buyer: &Address, token: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::GuaranteeClaim(buyer.clone(), token.clone()))
        .unwrap_or(0)
}

pub(crate) fn instruction(env: &Env, id: u32) -> SettlementInstruction {
    load_instruction(env, id)
}

pub(crate) fn instruction_count(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::InstructionCount)
        .unwrap_or(0)
}
