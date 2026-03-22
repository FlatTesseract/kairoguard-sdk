/// In-package M-of-N approval governance and guardian-based recovery.
///
/// Governance V2 is a port of the standalone `kairo_governance` package,
/// now co-located inside `kairo_policy_engine` so that new V4+ flows
/// do not require a cross-package dependency.  Existing V3 governed
/// bindings continue to work via the old external package.
///
/// Recovery adds guardian-based key recovery: a separate set of guardians
/// can approve re-enablement of a locked vault through timelocked
/// M-of-N proposals that mint a single-use `RecoveryReceiptV1`.
#[allow(duplicate_alias, unused_const)]
module kairo_policy_engine::policy_governance;

use sui::clock::Clock;
use sui::object::{Self, UID, ID};
use sui::tx_context::{Self, TxContext};
use sui::transfer;
use sui::event;
use std::vector;

// ============================================================================
// Error codes – governance
// ============================================================================

const E_NOT_APPROVER: u64 = 300;
const E_ALREADY_APPROVED: u64 = 301;
const E_THRESHOLD_NOT_MET: u64 = 302;
const E_TIMELOCK_NOT_PASSED: u64 = 303;
const E_PROPOSAL_EXECUTED: u64 = 304;
const E_PROPOSAL_CANCELLED: u64 = 305;
const E_NOT_PROPOSER_OR_ADMIN: u64 = 306;
const E_INVALID_THRESHOLD: u64 = 307;
const E_WRONG_GOVERNANCE: u64 = 310;
const E_NO_APPROVERS: u64 = 311;
const E_DUPLICATE_APPROVER: u64 = 313;

// ============================================================================
// Error codes – recovery
// ============================================================================

const E_NOT_GUARDIAN: u64 = 400;
const E_ALREADY_APPROVED_RECOVERY: u64 = 401;
const E_RECOVERY_THRESHOLD_NOT_MET: u64 = 402;
const E_RECOVERY_TIMELOCK_NOT_PASSED: u64 = 403;
const E_RECOVERY_EXECUTED: u64 = 404;
const E_RECOVERY_CANCELLED: u64 = 405;
const E_NO_GUARDIANS: u64 = 406;
const E_INVALID_RECOVERY_THRESHOLD: u64 = 407;
const E_WRONG_RECOVERY_CONFIG: u64 = 410;
const E_DUPLICATE_GUARDIAN: u64 = 413;
const E_NOT_CONFIG_ADMIN: u64 = 414;

// ============================================================================
// Recovery type constants
// ============================================================================

const RECOVERY_TYPE_GUARDIAN: u8 = 1;
const RECOVERY_TYPE_BACKUP: u8 = 2;

// ============================================================================
// Governance V2 structs
// ============================================================================

public struct PolicyGovernanceV2 has key {
    id: UID,
    stable_id: vector<u8>,
    approvers: vector<address>,
    threshold: u64,
    timelock_duration_ms: u64,
    proposal_count: u64,
    admin: address,
}

public struct GovernanceAdminCapV2 has key, store {
    id: UID,
    governance_id: ID,
}

public struct PolicyChangeProposalV2 has key {
    id: UID,
    governance_id: ID,
    binding_id: ID,
    target_version_id: ID,
    proposer: address,
    approvals: vector<address>,
    created_at_ms: u64,
    threshold_met_at_ms: u64,
    executed: bool,
    cancelled: bool,
}

public struct GovernanceReceiptV2 has key, store {
    id: UID,
    governance_id: ID,
    binding_id: ID,
    target_version_id: ID,
    proposal_id: ID,
    executed_at_ms: u64,
}

// ============================================================================
// Governance V2 events
// ============================================================================

public struct GovernanceV2CreatedEvent has copy, drop {
    governance_id: ID,
    stable_id: vector<u8>,
    approvers: vector<address>,
    threshold: u64,
    timelock_duration_ms: u64,
    admin: address,
}

public struct ProposalV2CreatedEvent has copy, drop {
    proposal_id: ID,
    governance_id: ID,
    binding_id: ID,
    target_version_id: ID,
    proposer: address,
}

public struct ProposalV2ApprovedEvent has copy, drop {
    proposal_id: ID,
    approver: address,
    approval_count: u64,
    threshold_met: bool,
}

public struct ProposalV2ExecutedEvent has copy, drop {
    proposal_id: ID,
    governance_id: ID,
    binding_id: ID,
    target_version_id: ID,
    receipt_id: ID,
}

public struct ProposalV2CancelledEvent has copy, drop {
    proposal_id: ID,
    cancelled_by: address,
}

public struct ApproversV2UpdatedEvent has copy, drop {
    governance_id: ID,
    new_approvers: vector<address>,
    new_threshold: u64,
}

public struct AdminV2TransferredEvent has copy, drop {
    governance_id: ID,
    old_admin: address,
    new_admin: address,
}

// ============================================================================
// Recovery structs
// ============================================================================

/// Per-dWallet guardian configuration (shared object).
public struct RecoveryConfig has key {
    id: UID,
    dwallet_id: vector<u8>,
    stable_id: vector<u8>,
    guardians: vector<address>,
    threshold: u64,
    timelock_duration_ms: u64,
    admin: address,
    created_at_ms: u64,
}

/// Admin capability for recovery config management.
public struct RecoveryAdminCap has key, store {
    id: UID,
    config_id: ID,
}

/// A pending recovery proposal (shared object).
public struct RecoveryProposal has key {
    id: UID,
    config_id: ID,
    dwallet_id: vector<u8>,
    stable_id: vector<u8>,
    proposer: address,
    approvals: vector<address>,
    created_at_ms: u64,
    threshold_met_at_ms: u64,
    executed: bool,
    cancelled: bool,
}

/// Single-use proof that guardians approved recovery.
/// Consumed by `dwallet_policy_vault::complete_recovery`.
public struct RecoveryReceiptV1 has key, store {
    id: UID,
    config_id: ID,
    dwallet_id: vector<u8>,
    stable_id: vector<u8>,
    recovery_type: u8,
    proposal_id: ID,
    timelock_start_ms: u64,
    timelock_duration_ms: u64,
    executed_at_ms: u64,
}

// ============================================================================
// Recovery events
// ============================================================================

public struct RecoveryConfigCreatedEvent has copy, drop {
    config_id: ID,
    dwallet_id: vector<u8>,
    stable_id: vector<u8>,
    guardians: vector<address>,
    threshold: u64,
    timelock_duration_ms: u64,
    admin: address,
}

public struct RecoveryProposalCreatedEvent has copy, drop {
    proposal_id: ID,
    config_id: ID,
    dwallet_id: vector<u8>,
    proposer: address,
}

public struct RecoveryApprovedEvent has copy, drop {
    proposal_id: ID,
    approver: address,
    approval_count: u64,
    threshold_met: bool,
}

public struct RecoveryExecutedEvent has copy, drop {
    proposal_id: ID,
    config_id: ID,
    dwallet_id: vector<u8>,
    receipt_id: ID,
}

public struct RecoveryCancelledEvent has copy, drop {
    proposal_id: ID,
    cancelled_by: address,
}

public struct GuardiansUpdatedEvent has copy, drop {
    config_id: ID,
    new_guardians: vector<address>,
    new_threshold: u64,
}

public struct RecoveryCompletedEvent has copy, drop {
    config_id: ID,
    dwallet_id: vector<u8>,
    receipt_id: ID,
    completed_at_ms: u64,
}

// ============================================================================
// Governance V2 – entry functions
// ============================================================================

public fun create_governance_v2(
    stable_id: vector<u8>,
    approvers: vector<address>,
    threshold: u64,
    timelock_duration_ms: u64,
    ctx: &mut TxContext,
): ID {
    assert!(vector::length(&approvers) > 0, E_NO_APPROVERS);
    assert!(threshold > 0 && threshold <= vector::length(&approvers), E_INVALID_THRESHOLD);
    assert_no_duplicates(&approvers);

    let sender = tx_context::sender(ctx);
    let governance = PolicyGovernanceV2 {
        id: object::new(ctx),
        stable_id,
        approvers,
        threshold,
        timelock_duration_ms,
        proposal_count: 0,
        admin: sender,
    };
    let governance_id = object::id(&governance);

    let admin_cap = GovernanceAdminCapV2 {
        id: object::new(ctx),
        governance_id,
    };

    event::emit(GovernanceV2CreatedEvent {
        governance_id,
        stable_id: governance.stable_id,
        approvers: governance.approvers,
        threshold,
        timelock_duration_ms,
        admin: sender,
    });

    transfer::share_object(governance);
    transfer::transfer(admin_cap, sender);

    governance_id
}

public fun propose_change_v2(
    governance: &mut PolicyGovernanceV2,
    binding_id: ID,
    target_version_id: ID,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    let sender = tx_context::sender(ctx);
    assert!(is_approver(&governance.approvers, sender), E_NOT_APPROVER);

    governance.proposal_count = governance.proposal_count + 1;

    let mut approvals = vector::empty<address>();
    vector::push_back(&mut approvals, sender);

    let now = clock.timestamp_ms();
    let threshold_met = vector::length(&approvals) >= governance.threshold;

    let proposal = PolicyChangeProposalV2 {
        id: object::new(ctx),
        governance_id: object::id(governance),
        binding_id,
        target_version_id,
        proposer: sender,
        approvals,
        created_at_ms: now,
        threshold_met_at_ms: if (threshold_met) { now } else { 0 },
        executed: false,
        cancelled: false,
    };
    let proposal_id = object::id(&proposal);

    event::emit(ProposalV2CreatedEvent {
        proposal_id,
        governance_id: object::id(governance),
        binding_id,
        target_version_id,
        proposer: sender,
    });

    if (threshold_met) {
        event::emit(ProposalV2ApprovedEvent {
            proposal_id,
            approver: sender,
            approval_count: 1,
            threshold_met: true,
        });
    };

    transfer::share_object(proposal);
    proposal_id
}

public fun approve_proposal_v2(
    governance: &PolicyGovernanceV2,
    proposal: &mut PolicyChangeProposalV2,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(!proposal.executed, E_PROPOSAL_EXECUTED);
    assert!(!proposal.cancelled, E_PROPOSAL_CANCELLED);
    assert!(proposal.governance_id == object::id(governance), E_WRONG_GOVERNANCE);

    let sender = tx_context::sender(ctx);
    assert!(is_approver(&governance.approvers, sender), E_NOT_APPROVER);
    assert!(!has_approved(&proposal.approvals, sender), E_ALREADY_APPROVED);

    vector::push_back(&mut proposal.approvals, sender);

    let approval_count = vector::length(&proposal.approvals);
    let threshold_met = approval_count >= governance.threshold;

    if (threshold_met && proposal.threshold_met_at_ms == 0) {
        proposal.threshold_met_at_ms = clock.timestamp_ms();
    };

    event::emit(ProposalV2ApprovedEvent {
        proposal_id: object::id(proposal),
        approver: sender,
        approval_count,
        threshold_met,
    });
}

public fun execute_proposal_v2(
    governance: &PolicyGovernanceV2,
    proposal: &mut PolicyChangeProposalV2,
    clock: &Clock,
    ctx: &mut TxContext,
): GovernanceReceiptV2 {
    assert!(!proposal.executed, E_PROPOSAL_EXECUTED);
    assert!(!proposal.cancelled, E_PROPOSAL_CANCELLED);
    assert!(proposal.governance_id == object::id(governance), E_WRONG_GOVERNANCE);

    assert!(
        vector::length(&proposal.approvals) >= governance.threshold,
        E_THRESHOLD_NOT_MET
    );
    assert!(proposal.threshold_met_at_ms > 0, E_THRESHOLD_NOT_MET);

    let now = clock.timestamp_ms();
    if (governance.timelock_duration_ms > 0) {
        let elapsed = now - proposal.threshold_met_at_ms;
        assert!(elapsed >= governance.timelock_duration_ms, E_TIMELOCK_NOT_PASSED);
    };

    proposal.executed = true;

    let receipt = GovernanceReceiptV2 {
        id: object::new(ctx),
        governance_id: object::id(governance),
        binding_id: proposal.binding_id,
        target_version_id: proposal.target_version_id,
        proposal_id: object::id(proposal),
        executed_at_ms: now,
    };
    let receipt_id = object::id(&receipt);

    event::emit(ProposalV2ExecutedEvent {
        proposal_id: object::id(proposal),
        governance_id: object::id(governance),
        binding_id: proposal.binding_id,
        target_version_id: proposal.target_version_id,
        receipt_id,
    });

    receipt
}

public fun cancel_proposal_v2(
    proposal: &mut PolicyChangeProposalV2,
    ctx: &mut TxContext,
) {
    assert!(!proposal.executed, E_PROPOSAL_EXECUTED);
    assert!(!proposal.cancelled, E_PROPOSAL_CANCELLED);

    let sender = tx_context::sender(ctx);
    assert!(sender == proposal.proposer, E_NOT_PROPOSER_OR_ADMIN);

    proposal.cancelled = true;

    event::emit(ProposalV2CancelledEvent {
        proposal_id: object::id(proposal),
        cancelled_by: sender,
    });
}

public fun admin_cancel_proposal_v2(
    admin_cap: &GovernanceAdminCapV2,
    governance: &PolicyGovernanceV2,
    proposal: &mut PolicyChangeProposalV2,
    ctx: &mut TxContext,
) {
    assert!(admin_cap.governance_id == object::id(governance), E_WRONG_GOVERNANCE);
    assert!(proposal.governance_id == object::id(governance), E_WRONG_GOVERNANCE);
    assert!(!proposal.executed, E_PROPOSAL_EXECUTED);
    assert!(!proposal.cancelled, E_PROPOSAL_CANCELLED);

    proposal.cancelled = true;

    event::emit(ProposalV2CancelledEvent {
        proposal_id: object::id(proposal),
        cancelled_by: tx_context::sender(ctx),
    });
}

public fun update_approvers_v2(
    admin_cap: &GovernanceAdminCapV2,
    governance: &mut PolicyGovernanceV2,
    new_approvers: vector<address>,
    new_threshold: u64,
) {
    assert!(admin_cap.governance_id == object::id(governance), E_WRONG_GOVERNANCE);
    assert!(vector::length(&new_approvers) > 0, E_NO_APPROVERS);
    assert!(new_threshold > 0 && new_threshold <= vector::length(&new_approvers), E_INVALID_THRESHOLD);
    assert_no_duplicates(&new_approvers);

    governance.approvers = new_approvers;
    governance.threshold = new_threshold;

    event::emit(ApproversV2UpdatedEvent {
        governance_id: object::id(governance),
        new_approvers: governance.approvers,
        new_threshold,
    });
}

public fun transfer_admin_v2(
    admin_cap: &GovernanceAdminCapV2,
    governance: &mut PolicyGovernanceV2,
    new_admin: address,
) {
    assert!(admin_cap.governance_id == object::id(governance), E_WRONG_GOVERNANCE);
    let old_admin = governance.admin;
    governance.admin = new_admin;

    event::emit(AdminV2TransferredEvent {
        governance_id: object::id(governance),
        old_admin,
        new_admin,
    });
}

// ============================================================================
// Governance V2 – receipt consumption
// ============================================================================

/// Consume (delete) a GovernanceReceiptV2 and return its validated fields.
/// Called by `policy_registry::governed_reaffirm_policy_binding_v2`.
public fun consume_governance_receipt_v2(receipt: GovernanceReceiptV2): (ID, ID, ID, ID) {
    let GovernanceReceiptV2 {
        id,
        governance_id,
        binding_id,
        target_version_id,
        proposal_id,
        executed_at_ms: _,
    } = receipt;
    object::delete(id);
    (governance_id, binding_id, target_version_id, proposal_id)
}

// ============================================================================
// Governance V2 – accessors
// ============================================================================

public fun governance_v2_stable_id(g: &PolicyGovernanceV2): vector<u8> { g.stable_id }
public fun governance_v2_approvers(g: &PolicyGovernanceV2): vector<address> { g.approvers }
public fun governance_v2_threshold(g: &PolicyGovernanceV2): u64 { g.threshold }
public fun governance_v2_timelock_ms(g: &PolicyGovernanceV2): u64 { g.timelock_duration_ms }
public fun governance_v2_proposal_count(g: &PolicyGovernanceV2): u64 { g.proposal_count }
public fun governance_v2_admin(g: &PolicyGovernanceV2): address { g.admin }

public fun proposal_v2_governance_id(p: &PolicyChangeProposalV2): ID { p.governance_id }
public fun proposal_v2_binding_id(p: &PolicyChangeProposalV2): ID { p.binding_id }
public fun proposal_v2_target_version_id(p: &PolicyChangeProposalV2): ID { p.target_version_id }
public fun proposal_v2_proposer(p: &PolicyChangeProposalV2): address { p.proposer }
public fun proposal_v2_approvals(p: &PolicyChangeProposalV2): vector<address> { p.approvals }
public fun proposal_v2_created_at_ms(p: &PolicyChangeProposalV2): u64 { p.created_at_ms }
public fun proposal_v2_threshold_met_at_ms(p: &PolicyChangeProposalV2): u64 { p.threshold_met_at_ms }
public fun proposal_v2_is_executed(p: &PolicyChangeProposalV2): bool { p.executed }
public fun proposal_v2_is_cancelled(p: &PolicyChangeProposalV2): bool { p.cancelled }

public fun receipt_v2_governance_id(r: &GovernanceReceiptV2): ID { r.governance_id }
public fun receipt_v2_binding_id(r: &GovernanceReceiptV2): ID { r.binding_id }
public fun receipt_v2_target_version_id(r: &GovernanceReceiptV2): ID { r.target_version_id }
public fun receipt_v2_proposal_id(r: &GovernanceReceiptV2): ID { r.proposal_id }
public fun receipt_v2_executed_at_ms(r: &GovernanceReceiptV2): u64 { r.executed_at_ms }

// ============================================================================
// Recovery – entry functions
// ============================================================================

/// Create a recovery config for a dWallet. One per dWallet.
/// The caller receives a RecoveryAdminCap.
public fun create_recovery_config(
    dwallet_id: vector<u8>,
    stable_id: vector<u8>,
    guardians: vector<address>,
    threshold: u64,
    timelock_duration_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    assert!(vector::length(&guardians) > 0, E_NO_GUARDIANS);
    assert!(threshold > 0 && threshold <= vector::length(&guardians), E_INVALID_RECOVERY_THRESHOLD);
    assert_no_duplicates(&guardians);

    let sender = tx_context::sender(ctx);
    let now = clock.timestamp_ms();

    let config = RecoveryConfig {
        id: object::new(ctx),
        dwallet_id,
        stable_id,
        guardians,
        threshold,
        timelock_duration_ms,
        admin: sender,
        created_at_ms: now,
    };
    let config_id = object::id(&config);

    let admin_cap = RecoveryAdminCap {
        id: object::new(ctx),
        config_id,
    };

    event::emit(RecoveryConfigCreatedEvent {
        config_id,
        dwallet_id: config.dwallet_id,
        stable_id: config.stable_id,
        guardians: config.guardians,
        threshold,
        timelock_duration_ms,
        admin: sender,
    });

    transfer::share_object(config);
    transfer::transfer(admin_cap, sender);

    config_id
}

/// Update guardians and threshold. Admin-only.
public fun update_guardians(
    admin_cap: &RecoveryAdminCap,
    config: &mut RecoveryConfig,
    new_guardians: vector<address>,
    new_threshold: u64,
) {
    assert!(admin_cap.config_id == object::id(config), E_NOT_CONFIG_ADMIN);
    assert!(vector::length(&new_guardians) > 0, E_NO_GUARDIANS);
    assert!(new_threshold > 0 && new_threshold <= vector::length(&new_guardians), E_INVALID_RECOVERY_THRESHOLD);
    assert_no_duplicates(&new_guardians);

    config.guardians = new_guardians;
    config.threshold = new_threshold;

    event::emit(GuardiansUpdatedEvent {
        config_id: object::id(config),
        new_guardians: config.guardians,
        new_threshold,
    });
}

/// Propose a recovery. Proposer must be a guardian and auto-approves.
public fun propose_recovery(
    config: &RecoveryConfig,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    let sender = tx_context::sender(ctx);
    assert!(is_approver(&config.guardians, sender), E_NOT_GUARDIAN);

    let mut approvals = vector::empty<address>();
    vector::push_back(&mut approvals, sender);

    let now = clock.timestamp_ms();
    let threshold_met = vector::length(&approvals) >= config.threshold;

    let proposal = RecoveryProposal {
        id: object::new(ctx),
        config_id: object::id(config),
        dwallet_id: config.dwallet_id,
        stable_id: config.stable_id,
        proposer: sender,
        approvals,
        created_at_ms: now,
        threshold_met_at_ms: if (threshold_met) { now } else { 0 },
        executed: false,
        cancelled: false,
    };
    let proposal_id = object::id(&proposal);

    event::emit(RecoveryProposalCreatedEvent {
        proposal_id,
        config_id: object::id(config),
        dwallet_id: config.dwallet_id,
        proposer: sender,
    });

    if (threshold_met) {
        event::emit(RecoveryApprovedEvent {
            proposal_id,
            approver: sender,
            approval_count: 1,
            threshold_met: true,
        });
    };

    transfer::share_object(proposal);
    proposal_id
}

/// Approve a pending recovery proposal. Caller must be a guardian.
public fun approve_recovery(
    config: &RecoveryConfig,
    proposal: &mut RecoveryProposal,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(!proposal.executed, E_RECOVERY_EXECUTED);
    assert!(!proposal.cancelled, E_RECOVERY_CANCELLED);
    assert!(proposal.config_id == object::id(config), E_WRONG_RECOVERY_CONFIG);

    let sender = tx_context::sender(ctx);
    assert!(is_approver(&config.guardians, sender), E_NOT_GUARDIAN);
    assert!(!has_approved(&proposal.approvals, sender), E_ALREADY_APPROVED_RECOVERY);

    vector::push_back(&mut proposal.approvals, sender);

    let approval_count = vector::length(&proposal.approvals);
    let threshold_met = approval_count >= config.threshold;

    if (threshold_met && proposal.threshold_met_at_ms == 0) {
        proposal.threshold_met_at_ms = clock.timestamp_ms();
    };

    event::emit(RecoveryApprovedEvent {
        proposal_id: object::id(proposal),
        approver: sender,
        approval_count,
        threshold_met,
    });
}

/// Execute an approved recovery after the timelock has passed.
/// Mints a RecoveryReceiptV1 for the vault's `complete_recovery`.
public fun execute_recovery(
    config: &RecoveryConfig,
    proposal: &mut RecoveryProposal,
    clock: &Clock,
    ctx: &mut TxContext,
): RecoveryReceiptV1 {
    assert!(!proposal.executed, E_RECOVERY_EXECUTED);
    assert!(!proposal.cancelled, E_RECOVERY_CANCELLED);
    assert!(proposal.config_id == object::id(config), E_WRONG_RECOVERY_CONFIG);

    assert!(
        vector::length(&proposal.approvals) >= config.threshold,
        E_RECOVERY_THRESHOLD_NOT_MET
    );
    assert!(proposal.threshold_met_at_ms > 0, E_RECOVERY_THRESHOLD_NOT_MET);

    let now = clock.timestamp_ms();
    if (config.timelock_duration_ms > 0) {
        let elapsed = now - proposal.threshold_met_at_ms;
        assert!(elapsed >= config.timelock_duration_ms, E_RECOVERY_TIMELOCK_NOT_PASSED);
    };

    proposal.executed = true;

    let receipt = RecoveryReceiptV1 {
        id: object::new(ctx),
        config_id: object::id(config),
        dwallet_id: proposal.dwallet_id,
        stable_id: proposal.stable_id,
        recovery_type: RECOVERY_TYPE_GUARDIAN,
        proposal_id: object::id(proposal),
        timelock_start_ms: proposal.threshold_met_at_ms,
        timelock_duration_ms: config.timelock_duration_ms,
        executed_at_ms: now,
    };
    let receipt_id = object::id(&receipt);

    event::emit(RecoveryExecutedEvent {
        proposal_id: object::id(proposal),
        config_id: object::id(config),
        dwallet_id: proposal.dwallet_id,
        receipt_id,
    });

    receipt
}

/// Cancel a pending recovery proposal. Only the proposer can cancel.
public fun cancel_recovery(
    proposal: &mut RecoveryProposal,
    ctx: &mut TxContext,
) {
    assert!(!proposal.executed, E_RECOVERY_EXECUTED);
    assert!(!proposal.cancelled, E_RECOVERY_CANCELLED);

    let sender = tx_context::sender(ctx);
    assert!(sender == proposal.proposer, E_NOT_PROPOSER_OR_ADMIN);

    proposal.cancelled = true;

    event::emit(RecoveryCancelledEvent {
        proposal_id: object::id(proposal),
        cancelled_by: sender,
    });
}

// ============================================================================
// Recovery – receipt consumption
// ============================================================================

/// Consume (delete) a RecoveryReceiptV1 and return validated fields.
/// Called by `dwallet_policy_vault::complete_recovery`.
/// Returns (config_id, dwallet_id, stable_id).
public fun consume_recovery_receipt(receipt: RecoveryReceiptV1): (ID, vector<u8>, vector<u8>) {
    let RecoveryReceiptV1 {
        id,
        config_id,
        dwallet_id,
        stable_id,
        recovery_type: _,
        proposal_id: _,
        timelock_start_ms: _,
        timelock_duration_ms: _,
        executed_at_ms: _,
    } = receipt;
    object::delete(id);
    (config_id, dwallet_id, stable_id)
}

// ============================================================================
// Recovery – accessors
// ============================================================================

public fun recovery_config_dwallet_id(c: &RecoveryConfig): vector<u8> { c.dwallet_id }
public fun recovery_config_stable_id(c: &RecoveryConfig): vector<u8> { c.stable_id }
public fun recovery_config_guardians(c: &RecoveryConfig): vector<address> { c.guardians }
public fun recovery_config_threshold(c: &RecoveryConfig): u64 { c.threshold }
public fun recovery_config_timelock_ms(c: &RecoveryConfig): u64 { c.timelock_duration_ms }
public fun recovery_config_admin(c: &RecoveryConfig): address { c.admin }

public fun recovery_proposal_config_id(p: &RecoveryProposal): ID { p.config_id }
public fun recovery_proposal_dwallet_id(p: &RecoveryProposal): vector<u8> { p.dwallet_id }
public fun recovery_proposal_proposer(p: &RecoveryProposal): address { p.proposer }
public fun recovery_proposal_approvals(p: &RecoveryProposal): vector<address> { p.approvals }
public fun recovery_proposal_threshold_met_at_ms(p: &RecoveryProposal): u64 { p.threshold_met_at_ms }
public fun recovery_proposal_is_executed(p: &RecoveryProposal): bool { p.executed }
public fun recovery_proposal_is_cancelled(p: &RecoveryProposal): bool { p.cancelled }

public fun recovery_receipt_config_id(r: &RecoveryReceiptV1): ID { r.config_id }
public fun recovery_receipt_dwallet_id(r: &RecoveryReceiptV1): vector<u8> { r.dwallet_id }
public fun recovery_receipt_stable_id(r: &RecoveryReceiptV1): vector<u8> { r.stable_id }
public fun recovery_receipt_recovery_type(r: &RecoveryReceiptV1): u8 { r.recovery_type }
public fun recovery_receipt_proposal_id(r: &RecoveryReceiptV1): ID { r.proposal_id }
public fun recovery_receipt_executed_at_ms(r: &RecoveryReceiptV1): u64 { r.executed_at_ms }

// ============================================================================
// Exported constants
// ============================================================================

public fun recovery_type_guardian(): u8 { RECOVERY_TYPE_GUARDIAN }
public fun recovery_type_backup(): u8 { RECOVERY_TYPE_BACKUP }

// ============================================================================
// Internal helpers (shared by governance and recovery)
// ============================================================================

fun is_approver(approvers: &vector<address>, addr: address): bool {
    let len = vector::length(approvers);
    let mut i = 0;
    while (i < len) {
        if (*vector::borrow(approvers, i) == addr) return true;
        i = i + 1;
    };
    false
}

fun has_approved(approvals: &vector<address>, addr: address): bool {
    let len = vector::length(approvals);
    let mut i = 0;
    while (i < len) {
        if (*vector::borrow(approvals, i) == addr) return true;
        i = i + 1;
    };
    false
}

fun assert_no_duplicates(addrs: &vector<address>) {
    let len = vector::length(addrs);
    let mut i = 0;
    while (i < len) {
        let mut j = i + 1;
        while (j < len) {
            assert!(
                *vector::borrow(addrs, i) != *vector::borrow(addrs, j),
                E_DUPLICATE_APPROVER
            );
            j = j + 1;
        };
        i = i + 1;
    };
}
