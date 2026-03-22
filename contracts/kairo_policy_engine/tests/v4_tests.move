#[test_only]
#[allow(duplicate_alias, unused_use)]
module kairo_policy_engine::v4_tests;

use sui::test_scenario::{Self as ts, Scenario};
use sui::clock::{Self, Clock};
use sui::object;

use kairo_policy_engine::policy_registry::{
    Self as registry,
    PolicyRegistry,
    PolicyBinding,
    PolicyV4,
    PolicyReceiptV4,
    create_generic_rule,
};

use kairo_policy_engine::policy_governance::{
    Self as gov,
    PolicyGovernanceV2,
    GovernanceAdminCapV2,
    PolicyChangeProposalV2,
    RecoveryConfig,
    RecoveryAdminCap,
    RecoveryProposal,
    RecoveryReceiptV1,
};

use kairo_policy_engine::dwallet_policy_vault::{
    Self as vault,
    PolicyVault,
    VaultAdminCap,
};

const ADMIN: address = @0xAD;
const APPROVER1: address = @0xA1;
const APPROVER2: address = @0xA2;
const APPROVER3: address = @0xA3;
const GUARDIAN1: address = @0xD1;
const GUARDIAN2: address = @0xD2;
const GUARDIAN3: address = @0xD3;

fun setup_registry(scenario: &mut Scenario, clock: &Clock): object::ID {
    ts::next_tx(scenario, ADMIN);
    registry::create_and_share_policy_registry(ts::ctx(scenario))
}

fun register_v4_policy_version(
    scenario: &mut Scenario,
    clock: &Clock,
): object::ID {
    ts::next_tx(scenario, ADMIN);
    let rules = vector[
        create_generic_rule(1, 0, x"000000000000000000000000000000000000000000000000000000003B9ACA00"),
    ];
    let _policy_id = registry::create_and_share_policy_v4(
        b"test-v4-policy",
        b"1.0.0",
        0,
        vector[],
        vector[],
        vector[],
        vector[],
        rules,
        ts::ctx(scenario),
    );

    ts::next_tx(scenario, ADMIN);
    let mut reg = ts::take_shared<PolicyRegistry>(scenario);
    let policy = ts::take_shared<PolicyV4>(scenario);
    let version_id = registry::register_policy_version_from_policy_v4(
        &mut reg, clock, &policy, b"initial v4", ts::ctx(scenario),
    );
    ts::return_shared(policy);
    ts::return_shared(reg);
    version_id
}

// ============================================================================
// Test 1: PolicyV4 receipt – allowed
// ============================================================================

#[test]
fun test_v4_mint_receipt_allowed() {
    let mut scenario = ts::begin(ADMIN);
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut clock, 1_000_000_000);

    let _reg_id = setup_registry(&mut scenario, &clock);
    let _version_id = register_v4_policy_version(&mut scenario, &clock);

    ts::next_tx(&mut scenario, ADMIN);
    let reg = ts::take_shared<PolicyRegistry>(&scenario);
    let _binding_id = registry::create_and_share_policy_binding(
        &reg, &clock, b"dwallet-v4", b"test-v4-policy", ts::ctx(&mut scenario),
    );
    ts::return_shared(reg);

    ts::next_tx(&mut scenario, ADMIN);
    let reg = ts::take_shared<PolicyRegistry>(&scenario);
    let policy = ts::take_shared<PolicyV4>(&scenario);
    let mut binding = ts::take_shared<PolicyBinding>(&scenario);
    let receipt = registry::mint_receipt_v4(
        &reg,
        &policy,
        &mut binding,
        &clock,
        1,
        b"00000001",
        x"0000000000000000000000000000000000000000000000000000000000000001",
        x"0000000000000000000000000000000000000000",
        x"0000000000000000000000000000000000000000000000000000000000000001",
        vector[],
        ts::ctx(&mut scenario),
    );
    assert!(registry::receipt_v4_is_allowed(&receipt) == true);
    registry::consume_receipt_v4(receipt);
    ts::return_shared(binding);
    ts::return_shared(policy);
    ts::return_shared(reg);

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// ============================================================================
// Test 2: PolicyV4 receipt – native value exceeded
// ============================================================================

#[test]
fun test_v4_mint_receipt_native_value_exceeded() {
    let mut scenario = ts::begin(ADMIN);
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut clock, 1_000_000_000);

    let _reg_id = setup_registry(&mut scenario, &clock);
    let _version_id = register_v4_policy_version(&mut scenario, &clock);

    ts::next_tx(&mut scenario, ADMIN);
    let reg = ts::take_shared<PolicyRegistry>(&scenario);
    let _binding_id = registry::create_and_share_policy_binding(
        &reg, &clock, b"dwallet-v4-2", b"test-v4-policy", ts::ctx(&mut scenario),
    );
    ts::return_shared(reg);

    ts::next_tx(&mut scenario, ADMIN);
    let reg = ts::take_shared<PolicyRegistry>(&scenario);
    let policy = ts::take_shared<PolicyV4>(&scenario);
    let mut binding = ts::take_shared<PolicyBinding>(&scenario);
    let receipt = registry::mint_receipt_v4(
        &reg,
        &policy,
        &mut binding,
        &clock,
        1,
        b"00000001",
        x"0000000000000000000000000000000000000000000000000000000000000001",
        x"0000000000000000000000000000000000000000",
        x"00000000000000000000000000000000000000000000000000000000FFFFFFFF",
        vector[],
        ts::ctx(&mut scenario),
    );
    assert!(registry::receipt_v4_is_allowed(&receipt) == false);
    assert!(registry::receipt_v4_denial_reason(&receipt) == 30);
    registry::consume_receipt_v4(receipt);
    ts::return_shared(binding);
    ts::return_shared(policy);
    ts::return_shared(reg);

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// ============================================================================
// Test 3: Governance V2 – full flow
// ============================================================================

#[test]
fun test_governance_v2_full_flow() {
    let mut scenario = ts::begin(ADMIN);
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut clock, 1_000_000_000);

    let _reg_id = setup_registry(&mut scenario, &clock);
    let _version_id = register_v4_policy_version(&mut scenario, &clock);

    ts::next_tx(&mut scenario, ADMIN);
    let reg = ts::take_shared<PolicyRegistry>(&scenario);
    let _binding_id = registry::create_and_share_policy_binding(
        &reg, &clock, b"dwallet-gov", b"test-v4-policy", ts::ctx(&mut scenario),
    );
    ts::return_shared(reg);

    ts::next_tx(&mut scenario, ADMIN);
    let mut reg = ts::take_shared<PolicyRegistry>(&scenario);
    let v2_id = registry::register_policy_version(
        &mut reg, &clock,
        b"test-v4-policy", b"2.0.0",
        x"0000000000000000000000000000000000000000000000000000000000000002",
        b"v2", ts::ctx(&mut scenario),
    );
    ts::return_shared(reg);

    ts::next_tx(&mut scenario, ADMIN);
    let _gov_id = gov::create_governance_v2(
        b"test-v4-policy",
        vector[APPROVER1, APPROVER2, APPROVER3],
        2, 0,
        ts::ctx(&mut scenario),
    );

    ts::next_tx(&mut scenario, ADMIN);
    let mut binding = ts::take_shared<PolicyBinding>(&scenario);
    let governance = ts::take_shared<PolicyGovernanceV2>(&scenario);
    registry::set_binding_governance_v2(&mut binding, object::id(&governance), 1);
    let binding_obj_id = object::id(&binding);
    ts::return_shared(governance);
    ts::return_shared(binding);

    ts::next_tx(&mut scenario, APPROVER1);
    let mut governance = ts::take_shared<PolicyGovernanceV2>(&scenario);
    let _proposal_id = gov::propose_change_v2(
        &mut governance, binding_obj_id, v2_id, &clock, ts::ctx(&mut scenario),
    );
    ts::return_shared(governance);

    ts::next_tx(&mut scenario, APPROVER2);
    let governance = ts::take_shared<PolicyGovernanceV2>(&scenario);
    let mut proposal = ts::take_shared<PolicyChangeProposalV2>(&scenario);
    gov::approve_proposal_v2(&governance, &mut proposal, &clock, ts::ctx(&mut scenario));
    ts::return_shared(proposal);
    ts::return_shared(governance);

    ts::next_tx(&mut scenario, APPROVER1);
    let governance = ts::take_shared<PolicyGovernanceV2>(&scenario);
    let mut proposal = ts::take_shared<PolicyChangeProposalV2>(&scenario);
    let receipt = gov::execute_proposal_v2(
        &governance, &mut proposal, &clock, ts::ctx(&mut scenario),
    );
    ts::return_shared(proposal);
    ts::return_shared(governance);

    ts::next_tx(&mut scenario, ADMIN);
    let reg = ts::take_shared<PolicyRegistry>(&scenario);
    let mut binding = ts::take_shared<PolicyBinding>(&scenario);
    let new_version = registry::governed_reaffirm_policy_binding_v2(
        &mut binding, &reg, &clock, receipt,
    );
    assert!(new_version == v2_id);
    assert!(registry::binding_active_version_id(&binding) == v2_id);
    ts::return_shared(binding);
    ts::return_shared(reg);

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// ============================================================================
// Test 4: Governance V2 – wrong governance receipt rejected
// ============================================================================

#[test]
#[expected_failure(abort_code = 121)]
fun test_governance_v2_wrong_governance_id() {
    let mut scenario = ts::begin(ADMIN);
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut clock, 1_000_000_000);

    let _reg_id = setup_registry(&mut scenario, &clock);
    let _version_id = register_v4_policy_version(&mut scenario, &clock);

    ts::next_tx(&mut scenario, ADMIN);
    let reg = ts::take_shared<PolicyRegistry>(&scenario);
    let _binding_id = registry::create_and_share_policy_binding(
        &reg, &clock, b"dwallet-gov2", b"test-v4-policy", ts::ctx(&mut scenario),
    );
    ts::return_shared(reg);

    ts::next_tx(&mut scenario, ADMIN);
    let _gov1_id = gov::create_governance_v2(
        b"test-v4-policy", vector[APPROVER1, APPROVER2], 2, 0, ts::ctx(&mut scenario),
    );

    ts::next_tx(&mut scenario, ADMIN);
    let _gov2_id = gov::create_governance_v2(
        b"test-v4-policy", vector[APPROVER1], 1, 0, ts::ctx(&mut scenario),
    );

    ts::next_tx(&mut scenario, ADMIN);
    let mut binding = ts::take_shared<PolicyBinding>(&scenario);
    let gov1 = ts::take_shared_by_id<PolicyGovernanceV2>(&scenario, _gov1_id);
    registry::set_binding_governance_v2(&mut binding, object::id(&gov1), 1);
    let binding_obj_id = object::id(&binding);
    ts::return_shared(gov1);
    ts::return_shared(binding);

    ts::next_tx(&mut scenario, APPROVER1);
    let mut gov2 = ts::take_shared_by_id<PolicyGovernanceV2>(&scenario, _gov2_id);
    let _proposal_id = gov::propose_change_v2(
        &mut gov2, binding_obj_id, _version_id, &clock, ts::ctx(&mut scenario),
    );
    ts::return_shared(gov2);

    ts::next_tx(&mut scenario, APPROVER1);
    let gov2 = ts::take_shared_by_id<PolicyGovernanceV2>(&scenario, _gov2_id);
    let mut proposal = ts::take_shared<PolicyChangeProposalV2>(&scenario);
    let receipt = gov::execute_proposal_v2(
        &gov2, &mut proposal, &clock, ts::ctx(&mut scenario),
    );
    ts::return_shared(proposal);
    ts::return_shared(gov2);

    ts::next_tx(&mut scenario, ADMIN);
    let reg = ts::take_shared<PolicyRegistry>(&scenario);
    let mut binding = ts::take_shared<PolicyBinding>(&scenario);
    let _new_version = registry::governed_reaffirm_policy_binding_v2(
        &mut binding, &reg, &clock, receipt,
    );

    ts::return_shared(binding);
    ts::return_shared(reg);
    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// ============================================================================
// Test 5: Recovery – full flow
// ============================================================================

#[test]
fun test_recovery_full_flow() {
    let mut scenario = ts::begin(ADMIN);
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut clock, 1_000_000_000);

    let dwallet_id = b"test_dwallet_recovery_id_32byte!";

    // Create vault
    ts::next_tx(&mut scenario, ADMIN);
    let _vault_id = vault::create_and_share_vault(&clock, ts::ctx(&mut scenario));

    // Create registry and binding first, so we get the real binding ID
    let _reg_id = setup_registry(&mut scenario, &clock);

    ts::next_tx(&mut scenario, ADMIN);
    let mut reg = ts::take_shared<PolicyRegistry>(&scenario);
    let _ver_id = registry::register_policy_version(
        &mut reg, &clock,
        b"test-recovery-policy", b"1.0.0",
        x"0000000000000000000000000000000000000000000000000000000000000001",
        b"note", ts::ctx(&mut scenario),
    );
    ts::return_shared(reg);

    ts::next_tx(&mut scenario, ADMIN);
    let reg = ts::take_shared<PolicyRegistry>(&scenario);
    let binding_id = registry::create_and_share_policy_binding(
        &reg, &clock, *&dwallet_id, b"test-recovery-policy", ts::ctx(&mut scenario),
    );
    ts::return_shared(reg);

    // Register dWallet into vault with the real binding ID
    ts::next_tx(&mut scenario, ADMIN);
    let mut v = ts::take_shared<PolicyVault>(&scenario);
    vault::register_dwallet_into_vault(
        &mut v, &clock, *&dwallet_id, binding_id,
        b"test-recovery-policy", false, ts::ctx(&mut scenario),
    );
    ts::return_shared(v);

    // Create recovery config
    ts::next_tx(&mut scenario, ADMIN);
    let _config_id = gov::create_recovery_config(
        *&dwallet_id,
        b"test-recovery-policy",
        vector[GUARDIAN1, GUARDIAN2, GUARDIAN3],
        2, 0,
        &clock,
        ts::ctx(&mut scenario),
    );

    // Put vault in emergency bypass
    ts::next_tx(&mut scenario, ADMIN);
    let mut v = ts::take_shared<PolicyVault>(&scenario);
    let admin_cap = ts::take_from_sender<VaultAdminCap>(&scenario);
    vault::set_enforcement_mode(&mut v, &admin_cap, 2, &clock);
    assert!(vault::enforcement_mode(&v) == 2);
    ts::return_to_sender(&scenario, admin_cap);
    ts::return_shared(v);

    // Propose recovery
    ts::next_tx(&mut scenario, GUARDIAN1);
    let config = ts::take_shared<RecoveryConfig>(&scenario);
    let _proposal_id = gov::propose_recovery(&config, &clock, ts::ctx(&mut scenario));
    ts::return_shared(config);

    // Approve
    ts::next_tx(&mut scenario, GUARDIAN2);
    let config = ts::take_shared<RecoveryConfig>(&scenario);
    let mut proposal = ts::take_shared<RecoveryProposal>(&scenario);
    gov::approve_recovery(&config, &mut proposal, &clock, ts::ctx(&mut scenario));
    ts::return_shared(proposal);
    ts::return_shared(config);

    // Execute
    ts::next_tx(&mut scenario, GUARDIAN1);
    let config = ts::take_shared<RecoveryConfig>(&scenario);
    let mut proposal = ts::take_shared<RecoveryProposal>(&scenario);
    let receipt = gov::execute_recovery(&config, &mut proposal, &clock, ts::ctx(&mut scenario));
    ts::return_shared(proposal);
    ts::return_shared(config);

    // Complete recovery on vault
    ts::next_tx(&mut scenario, ADMIN);
    let mut v = ts::take_shared<PolicyVault>(&scenario);
    let binding = ts::take_shared_by_id<PolicyBinding>(&scenario, binding_id);
    vault::complete_recovery(&mut v, receipt, &binding, &clock, ts::ctx(&mut scenario));

    assert!(vault::enforcement_mode(&v) == 1);

    ts::return_shared(binding);
    ts::return_shared(v);

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// ============================================================================
// Test 6: Recovery – non-guardian cannot propose
// ============================================================================

#[test]
#[expected_failure(abort_code = 400)]
fun test_recovery_non_guardian_cannot_propose() {
    let mut scenario = ts::begin(ADMIN);
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut clock, 1_000_000_000);

    ts::next_tx(&mut scenario, ADMIN);
    let _config_id = gov::create_recovery_config(
        b"some-dwallet-id-32-bytes-long!!!", b"stable-1",
        vector[GUARDIAN1, GUARDIAN2], 2, 0,
        &clock, ts::ctx(&mut scenario),
    );

    ts::next_tx(&mut scenario, ADMIN);
    let config = ts::take_shared<RecoveryConfig>(&scenario);
    let _proposal_id = gov::propose_recovery(&config, &clock, ts::ctx(&mut scenario));
    ts::return_shared(config);

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// ============================================================================
// Test 7: Governance V2 – duplicate approvers rejected
// ============================================================================

#[test]
#[expected_failure(abort_code = 313)]
fun test_governance_v2_duplicate_approvers() {
    let mut scenario = ts::begin(ADMIN);

    ts::next_tx(&mut scenario, ADMIN);
    let _gov_id = gov::create_governance_v2(
        b"test-dup",
        vector[APPROVER1, APPROVER2, APPROVER1],
        2, 0,
        ts::ctx(&mut scenario),
    );

    ts::end(scenario);
}

// ============================================================================
// Test 8: Governance V2 – update approvers
// ============================================================================

#[test]
fun test_governance_v2_update_approvers() {
    let mut scenario = ts::begin(ADMIN);

    ts::next_tx(&mut scenario, ADMIN);
    let _gov_id = gov::create_governance_v2(
        b"test-update", vector[APPROVER1, APPROVER2], 2, 0, ts::ctx(&mut scenario),
    );

    ts::next_tx(&mut scenario, ADMIN);
    let mut governance = ts::take_shared<PolicyGovernanceV2>(&scenario);
    let admin_cap = ts::take_from_sender<GovernanceAdminCapV2>(&scenario);

    gov::update_approvers_v2(
        &admin_cap, &mut governance, vector[APPROVER1, APPROVER3], 1,
    );
    assert!(gov::governance_v2_threshold(&governance) == 1);

    ts::return_to_sender(&scenario, admin_cap);
    ts::return_shared(governance);
    ts::end(scenario);
}
