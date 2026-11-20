extern crate std;

use soroban_sdk::{
    testutils::Address as _, token::StellarAssetClient, vec, Address, Env, String,
};
use tessera_asset_token::{AssetTokenContract, AssetTokenContractClient};
use tessera_compliance::{ComplianceContract, ComplianceContractClient};

use crate::{
    Error, InstructionStatus, SettlementContract, SettlementContractClient, SettlementInstruction,
};

struct Market<'a> {
    env: Env,
    admin: Address,
    engine: SettlementContractClient<'a>,
    compliance: ComplianceContractClient<'a>,
    real_estate: Address,
    usdc: Address,
    a: Address,
    b: Address,
    c: Address,
}

fn asset_token(env: &Env, admin: &Address, compliance: &Address, symbol: &str) -> Address {
    let id = env.register(AssetTokenContract, ());
    AssetTokenContractClient::new(env, &id).initialize(
        admin,
        &String::from_str(env, symbol),
        &String::from_str(env, symbol),
        &String::from_str(env, "rwa"),
        &1_000_000,
        &7,
        compliance,
        &String::from_str(env, "test asset"),
        &1_000_000,
    );
    id
}

fn setup<'a>() -> Market<'a> {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    let c = Address::generate(&env);

    let compliance_id = env.register(ComplianceContract, ());
    let compliance = ComplianceContractClient::new(&env, &compliance_id);
    compliance.initialize(&admin);
    let us = String::from_str(&env, "US");
    for who in [&admin, &a, &b, &c] {
        compliance.add_to_allowlist(&admin, who, &us, &0);
    }

    let real_estate = asset_token(&env, &admin, &compliance_id, "RE");
    let usdc = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();

    let engine_id = env.register(SettlementContract, ());
    let engine = SettlementContractClient::new(&env, &engine_id);
    engine.initialize(&admin);
    engine.register_asset(&admin, &real_estate, &Some(compliance_id.clone()));
    engine.register_asset(&admin, &usdc, &None);

    Market {
        env,
        admin,
        engine,
        compliance,
        real_estate,
        usdc,
        a,
        b,
        c,
    }
}

fn ce(e: Error) -> soroban_sdk::Error {
    soroban_sdk::Error::from_contract_error(e as u32)
}

fn fund_usdc(m: &Market, who: &Address, amount: i128) {
    StellarAssetClient::new(&m.env, &m.usdc).mint(who, &amount);
}

fn fund_re(m: &Market, who: &Address, amount: i128) {
    soroban_sdk::token::TokenClient::new(&m.env, &m.real_estate).transfer(&m.admin, who, &amount);
}

fn usdc(m: &Market, who: &Address) -> i128 {
    soroban_sdk::token::TokenClient::new(&m.env, &m.usdc).balance(who)
}

fn re(m: &Market, who: &Address) -> i128 {
    soroban_sdk::token::TokenClient::new(&m.env, &m.real_estate).balance(who)
}

#[test]
fn settle_delivers_asset_and_payment_atomically() {
    let m = setup();
    fund_re(&m, &m.a, 100);
    fund_usdc(&m, &m.b, 1_000);

    let id = m.engine.create_instruction(
        &m.b, // buyer
        &m.a, // seller
        &m.real_estate,
        &40,
        &m.usdc,
        &400,
        &0, // settle immediately
    );
    assert_eq!(m.engine.instruction_count(), 1);

    let guarantee = m.engine.settle(&m.a, &id);
    assert_eq!(guarantee, 0);
    assert_eq!(re(&m, &m.b), 40);
    assert_eq!(re(&m, &m.a), 60);
    assert_eq!(usdc(&m, &m.a), 400);
    assert_eq!(usdc(&m, &m.b), 600);

    let stored: SettlementInstruction = m.engine.get_instruction(&id);
    assert_eq!(stored.status, InstructionStatus::Settled);
}

#[test]
fn settle_before_the_settlement_ledger_is_rejected() {
    let m = setup();
    fund_re(&m, &m.a, 10);
    fund_usdc(&m, &m.b, 100);
    let id = m
        .engine
        .create_instruction(&m.b, &m.a, &m.real_estate, &10, &m.usdc, &100, &50);

    assert_eq!(
        m.engine.try_settle(&m.b, &id),
        Err(Ok(ce(Error::SettlementNotDue)))
    );
    assert_eq!(re(&m, &m.a), 10);
}

#[test]
fn only_a_counterparty_may_settle() {
    let m = setup();
    fund_re(&m, &m.a, 10);
    fund_usdc(&m, &m.b, 100);
    let id = m
        .engine
        .create_instruction(&m.b, &m.a, &m.real_estate, &10, &m.usdc, &100, &0);

    let outsider = Address::generate(&m.env);
    assert_eq!(
        m.engine.try_settle(&outsider, &id),
        Err(Ok(ce(Error::NotSettlementParty)))
    );
}

#[test]
fn unpaid_buyer_reverts_the_delivery_too() {
    let m = setup();
    fund_re(&m, &m.a, 10); // seller funded, buyer has no USDC and no guarantee fund
    let id = m
        .engine
        .create_instruction(&m.b, &m.a, &m.real_estate, &10, &m.usdc, &100, &0);

    assert!(m.engine.try_settle(&m.b, &id).is_err());
    // Both legs rolled back: the seller still holds the asset.
    assert_eq!(re(&m, &m.a), 10);
    assert_eq!(re(&m, &m.b), 0);
    assert_eq!(
        m.engine.get_instruction(&id).status,
        InstructionStatus::Pending
    );
}

#[test]
fn guarantee_fund_covers_a_payment_shortfall() {
    let m = setup();
    fund_re(&m, &m.a, 10);
    fund_usdc(&m, &m.b, 40); // buyer can only fund 40 of the 100 due

    m.engine.configure_guarantee_fund(&m.admin, &500);
    fund_usdc(&m, &m.admin, 500);
    m.engine.deposit_guarantee(&m.admin, &m.usdc, &500);
    assert_eq!(m.engine.guarantee_reserve(&m.usdc), 500);

    let id = m
        .engine
        .create_instruction(&m.b, &m.a, &m.real_estate, &10, &m.usdc, &100, &0);
    let drawn = m.engine.settle(&m.b, &id);

    assert_eq!(drawn, 60);
    assert_eq!(usdc(&m, &m.a), 100); // seller paid in full
    assert_eq!(m.engine.guarantee_reserve(&m.usdc), 440);
    assert_eq!(m.engine.guarantee_claim(&m.b, &m.usdc), 60);
    assert_eq!(re(&m, &m.b), 10);
}

#[test]
fn guarantee_fund_refuses_shortfalls_over_the_cap() {
    let m = setup();
    fund_re(&m, &m.a, 10);

    m.engine.configure_guarantee_fund(&m.admin, &50);
    fund_usdc(&m, &m.admin, 500);
    m.engine.deposit_guarantee(&m.admin, &m.usdc, &500);

    let id = m
        .engine
        .create_instruction(&m.b, &m.a, &m.real_estate, &10, &m.usdc, &100, &0);
    assert_eq!(
        m.engine.try_settle(&m.b, &id),
        Err(Ok(ce(Error::GuaranteeLimitExceeded)))
    );
    assert_eq!(re(&m, &m.a), 10);
    assert_eq!(m.engine.guarantee_reserve(&m.usdc), 500);
}

#[test]
fn net_settle_ten_instructions_with_cross_netting() {
    let m = setup();
    // Only net amounts move: B needs 70 RE, A 400 USDC and C 300 USDC.
    fund_re(&m, &m.b, 70);
    fund_usdc(&m, &m.a, 400);
    fund_usdc(&m, &m.c, 300);

    // (buyer, seller, asset amount, usdc amount)
    let legs: [(Address, Address, i128, i128); 10] = [
        (m.a.clone(), m.b.clone(), 100, 1000),
        (m.b.clone(), m.a.clone(), 40, 400),
        (m.c.clone(), m.b.clone(), 50, 500),
        (m.a.clone(), m.c.clone(), 10, 100),
        (m.b.clone(), m.c.clone(), 20, 200),
        (m.c.clone(), m.a.clone(), 30, 300),
        (m.a.clone(), m.c.clone(), 15, 150),
        (m.b.clone(), m.a.clone(), 25, 250),
        (m.c.clone(), m.b.clone(), 5, 50),
        (m.a.clone(), m.c.clone(), 10, 100),
    ];
    let mut ids = soroban_sdk::Vec::new(&m.env);
    for (buyer, seller, asset_amount, payment_amount) in legs.iter() {
        ids.push_back(m.engine.create_instruction(
            buyer,
            seller,
            &m.real_estate,
            asset_amount,
            &m.usdc,
            payment_amount,
            &0,
        ));
    }

    // Gross settlement would need 20 transfers. Net positions:
    //   RE:   A +40, B -70, C +30  -> 1 debtor, 2 creditors -> 2 transfers
    //   USDC: A -400, B +700, C -300 -> 2 debtors, 1 creditor -> 2 transfers
    let executed = m.engine.net_settle(&ids);
    assert_eq!(executed, 4);

    assert_eq!(re(&m, &m.a), 40);
    assert_eq!(re(&m, &m.b), 0);
    assert_eq!(re(&m, &m.c), 30);
    assert_eq!(usdc(&m, &m.a), 0);
    assert_eq!(usdc(&m, &m.b), 700);
    assert_eq!(usdc(&m, &m.c), 0);

    for id in ids.iter() {
        assert_eq!(
            m.engine.get_instruction(&id).status,
            InstructionStatus::Settled
        );
    }
}

#[test]
fn net_settle_rejects_duplicate_instruction_ids() {
    let m = setup();
    fund_re(&m, &m.a, 10);
    fund_usdc(&m, &m.b, 100);
    let id = m
        .engine
        .create_instruction(&m.b, &m.a, &m.real_estate, &10, &m.usdc, &100, &0);

    let ids = vec![&m.env, id, id];
    assert_eq!(
        m.engine.try_net_settle(&ids),
        Err(Ok(ce(Error::DuplicateInstruction)))
    );
}

#[test]
fn net_settle_rejects_an_instruction_that_is_not_due() {
    let m = setup();
    fund_re(&m, &m.a, 10);
    fund_usdc(&m, &m.b, 100);
    let id = m
        .engine
        .create_instruction(&m.b, &m.a, &m.real_estate, &10, &m.usdc, &100, &9_999);

    let ids = vec![&m.env, id];
    assert_eq!(
        m.engine.try_net_settle(&ids),
        Err(Ok(ce(Error::SettlementNotDue)))
    );
}

#[test]
fn create_instruction_requires_both_signatures() {
    let m = setup();
    let id = m
        .engine
        .create_instruction(&m.b, &m.a, &m.real_estate, &10, &m.usdc, &100, &0);
    let auths = m.env.auths();
    assert!(auths.iter().any(|(who, _)| who == &m.b));
    assert!(auths.iter().any(|(who, _)| who == &m.a));
    assert_eq!(id, 0);
}

#[test]
fn non_compliant_buyer_is_rejected() {
    let m = setup();
    fund_re(&m, &m.a, 10);
    fund_usdc(&m, &m.b, 100);
    let id = m
        .engine
        .create_instruction(&m.b, &m.a, &m.real_estate, &10, &m.usdc, &100, &0);

    // Compliance changed after signing: settlement re-checks it.
    m.compliance.suspend(&m.admin, &m.b);
    assert_eq!(
        m.engine.try_settle(&m.a, &id),
        Err(Ok(ce(Error::RecipientNotCompliant)))
    );
    assert_eq!(re(&m, &m.a), 10);
}
