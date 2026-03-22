/// Standalone M-of-N approval governance for policy binding changes.
///
/// This package is completely independent of `kairo_policy_engine`.
/// It mints a single-use `GovernanceReceipt` on proposal execution,
/// which `kairo_policy_engine` consumes inside `governed_reaffirm_policy_binding`
/// to apply the approved version change.
///
/// The policy engine's dynamic-field marker on `PolicyBinding` is the single
/// source of truth for whether a binding is governed.  This module does NOT
/// maintain its own governed-bindings mapping.
module kairo_governance::policy_governance;

use sui::clock::Clock;
use sui::object::{Self, UID, ID};
use sui::tx_context::{Self, TxContext};
use sui::transfer;
use sui::event;
use std::vector;

// ---- Error codes ----

const E_NOT_APPROVER: u64 = 200;
const E_ALREADY_APPROVED: u64 = 201;
const E_THRESHOLD_NOT_MET: u64 = 202;
const E_TIMELOCK_NOT_PASSED: u64 = 203;
const E_PROPOSAL_EXECUTED: u64 = 204;
const E_PROPOSAL_CANCELLED: u64 = 205;
const E_NOT_PROPOSER_OR_ADMIN: u64 = 206;
const E_INVALID_THRESHOLD: u64 = 207;
const E_WRONG_GOVERNANCE: u64 = 210;
const E_NO_APPROVERS: u64 = 211;
const E_DUPLICATE_APPROVER: u64 = 213;

// ---- Core structs ----

/// Shared governance object controlling a policy series.
public struct PolicyGovernance has key {
    id: UID,
    /// Which policy series this governs (matches PolicyBinding.stable_id).
    stable_id: vector<u8>,
    /// N approved signer addresses (must be unique).
    approvers: vector<address>,
    /// M required approvals.
    threshold: u64,
    /// Delay in ms after threshold is met before execution is allowed (0 = instant).
    timelock_duration_ms: u64,
    /// Running counter for proposals.
    proposal_count: u64,
    /// Admin address for display/audit. Updated via cap-gated `transfer_admin`.
    admin: address,
}

/// Capability returned to the creator for admin operations (update approvers, etc.).
public struct GovernanceAdminCap has key, store {
    id: UID,
    governance_id: ID,
}

/// A pending policy change proposal (shared object).
public struct PolicyChangeProposal has key {
    id: UID,
    governance_id: ID,
    /// The binding ID this proposal targets.
    binding_id: ID,
    /// The PolicyVersion object ID to activate on the binding.
    target_version_id: ID,
    /// Who created this proposal.
    proposer: address,
    /// Addresses that have approved so far.
    approvals: vector<address>,
    /// Timestamp (ms) when the proposal was created.
    created_at_ms: u64,
    /// Timestamp (ms) when threshold was met (0 until then).
    threshold_met_at_ms: u64,
    /// Whether the proposal has been executed.
    executed: bool,
    /// Whether the proposal has been cancelled.
    cancelled: bool,
}

/// Single-use proof that M-of-N approvers approved a specific binding/version change.
/// Owned object (key, store) so it can survive across transactions.
/// Consumed (deleted) by `kairo_policy_engine::governed_reaffirm_policy_binding`.
public struct GovernanceReceipt has key, store {
    id: UID,
    governance_id: ID,
    binding_id: ID,
    target_version_id: ID,
    proposal_id: ID,
    executed_at_ms: u64,
}

// ---- Events ----

public struct GovernanceCreatedEvent has copy, drop {
    governance_id: ID,
    stable_id: vector<u8>,
    approvers: vector<address>,
    threshold: u64,
    timelock_duration_ms: u64,
    admin: address,
}

public struct ProposalCreatedEvent has copy, drop {
    proposal_id: ID,
    governance_id: ID,
    binding_id: ID,
    target_version_id: ID,
    proposer: address,
}

public struct ProposalApprovedEvent has copy, drop {
    proposal_id: ID,
    approver: address,
    approval_count: u64,
    threshold_met: bool,
}

public struct ProposalExecutedEvent has copy, drop {
    proposal_id: ID,
    governance_id: ID,
    binding_id: ID,
    target_version_id: ID,
    receipt_id: ID,
}

public struct ProposalCancelledEvent has copy, drop {
    proposal_id: ID,
    cancelled_by: address,
}

public struct ApproversUpdatedEvent has copy, drop {
    governance_id: ID,
    new_approvers: vector<address>,
    new_threshold: u64,
}

public struct AdminTransferredEvent has copy, drop {
    governance_id: ID,
    old_admin: address,
    new_admin: address,
}

// ---- Entry functions ----

/// Create a new governance object for a policy series.
/// The caller receives a GovernanceAdminCap.
public fun create_governance(
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
    let governance = PolicyGovernance {
        id: object::new(ctx),
        stable_id,
        approvers,
        threshold,
        timelock_duration_ms,
        proposal_count: 0,
        admin: sender,
    };
    let governance_id = object::id(&governance);

    let admin_cap = GovernanceAdminCap {
        id: object::new(ctx),
        governance_id,
    };

    event::emit(GovernanceCreatedEvent {
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

/// Create a proposal to change the active policy version for a binding.
/// The proposer auto-approves. Proposer must be an approver.
///
/// Note: this module does not track which bindings are governed.
/// The policy engine's dynamic-field marker is the source of truth.
/// If a receipt is minted for an ungoverned binding, it simply cannot
/// be consumed (the policy engine will reject it).
public fun propose_change(
    governance: &mut PolicyGovernance,
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

    let proposal = PolicyChangeProposal {
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

    event::emit(ProposalCreatedEvent {
        proposal_id,
        governance_id: object::id(governance),
        binding_id,
        target_version_id,
        proposer: sender,
    });

    if (threshold_met) {
        event::emit(ProposalApprovedEvent {
            proposal_id,
            approver: sender,
            approval_count: 1,
            threshold_met: true,
        });
    };

    transfer::share_object(proposal);
    proposal_id
}

/// Approve a pending proposal. Caller must be an approver.
public fun approve_proposal(
    governance: &PolicyGovernance,
    proposal: &mut PolicyChangeProposal,
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

    event::emit(ProposalApprovedEvent {
        proposal_id: object::id(proposal),
        approver: sender,
        approval_count,
        threshold_met,
    });
}

/// Execute an approved proposal after the timelock has passed.
/// Returns a `GovernanceReceipt` that the caller feeds into
/// `kairo_policy_engine::governed_reaffirm_policy_binding` (same or later PTB).
public fun execute_proposal(
    governance: &PolicyGovernance,
    proposal: &mut PolicyChangeProposal,
    clock: &Clock,
    ctx: &mut TxContext,
): GovernanceReceipt {
    assert!(!proposal.executed, E_PROPOSAL_EXECUTED);
    assert!(!proposal.cancelled, E_PROPOSAL_CANCELLED);
    assert!(proposal.governance_id == object::id(governance), E_WRONG_GOVERNANCE);

    // Verify threshold is met.
    assert!(
        vector::length(&proposal.approvals) >= governance.threshold,
        E_THRESHOLD_NOT_MET
    );
    assert!(proposal.threshold_met_at_ms > 0, E_THRESHOLD_NOT_MET);

    // Verify timelock has passed.
    let now = clock.timestamp_ms();
    if (governance.timelock_duration_ms > 0) {
        let elapsed = now - proposal.threshold_met_at_ms;
        assert!(elapsed >= governance.timelock_duration_ms, E_TIMELOCK_NOT_PASSED);
    };

    proposal.executed = true;

    let receipt = GovernanceReceipt {
        id: object::new(ctx),
        governance_id: object::id(governance),
        binding_id: proposal.binding_id,
        target_version_id: proposal.target_version_id,
        proposal_id: object::id(proposal),
        executed_at_ms: now,
    };
    let receipt_id = object::id(&receipt);

    event::emit(ProposalExecutedEvent {
        proposal_id: object::id(proposal),
        governance_id: object::id(governance),
        binding_id: proposal.binding_id,
        target_version_id: proposal.target_version_id,
        receipt_id,
    });

    receipt
}

/// Cancel a pending proposal. Only the proposer can cancel.
public fun cancel_proposal(
    proposal: &mut PolicyChangeProposal,
    ctx: &mut TxContext,
) {
    assert!(!proposal.executed, E_PROPOSAL_EXECUTED);
    assert!(!proposal.cancelled, E_PROPOSAL_CANCELLED);

    let sender = tx_context::sender(ctx);
    assert!(sender == proposal.proposer, E_NOT_PROPOSER_OR_ADMIN);

    proposal.cancelled = true;

    event::emit(ProposalCancelledEvent {
        proposal_id: object::id(proposal),
        cancelled_by: sender,
    });
}

/// Admin-only: cancel any proposal.
public fun admin_cancel_proposal(
    _admin_cap: &GovernanceAdminCap,
    governance: &PolicyGovernance,
    proposal: &mut PolicyChangeProposal,
    ctx: &mut TxContext,
) {
    assert!(_admin_cap.governance_id == object::id(governance), E_WRONG_GOVERNANCE);
    assert!(proposal.governance_id == object::id(governance), E_WRONG_GOVERNANCE);
    assert!(!proposal.executed, E_PROPOSAL_EXECUTED);
    assert!(!proposal.cancelled, E_PROPOSAL_CANCELLED);

    proposal.cancelled = true;

    event::emit(ProposalCancelledEvent {
        proposal_id: object::id(proposal),
        cancelled_by: tx_context::sender(ctx),
    });
}

/// Admin-only: update the set of approvers and threshold.
public fun update_approvers(
    admin_cap: &GovernanceAdminCap,
    governance: &mut PolicyGovernance,
    new_approvers: vector<address>,
    new_threshold: u64,
) {
    assert!(admin_cap.governance_id == object::id(governance), E_WRONG_GOVERNANCE);
    assert!(vector::length(&new_approvers) > 0, E_NO_APPROVERS);
    assert!(new_threshold > 0 && new_threshold <= vector::length(&new_approvers), E_INVALID_THRESHOLD);
    assert_no_duplicates(&new_approvers);

    governance.approvers = new_approvers;
    governance.threshold = new_threshold;

    event::emit(ApproversUpdatedEvent {
        governance_id: object::id(governance),
        new_approvers: governance.approvers,
        new_threshold,
    });
}

/// Admin-only: update the stored admin address (for audit/UI display).
/// Must be called after transferring the GovernanceAdminCap to keep in sync.
public fun transfer_admin(
    admin_cap: &GovernanceAdminCap,
    governance: &mut PolicyGovernance,
    new_admin: address,
) {
    assert!(admin_cap.governance_id == object::id(governance), E_WRONG_GOVERNANCE);
    let old_admin = governance.admin;
    governance.admin = new_admin;

    event::emit(AdminTransferredEvent {
        governance_id: object::id(governance),
        old_admin,
        new_admin,
    });
}

// ---- Receipt consumption ----

/// Consume (delete) a GovernanceReceipt and return its validated fields.
/// Called by `kairo_policy_engine::governed_reaffirm_policy_binding`.
/// Returns (governance_id, binding_id, target_version_id, proposal_id).
public fun consume_governance_receipt(receipt: GovernanceReceipt): (ID, ID, ID, ID) {
    let GovernanceReceipt {
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

// ---- View / accessor functions ----

// -- PolicyGovernance accessors --
public fun governance_stable_id(g: &PolicyGovernance): vector<u8> { g.stable_id }
public fun governance_approvers(g: &PolicyGovernance): vector<address> { g.approvers }
public fun governance_threshold(g: &PolicyGovernance): u64 { g.threshold }
public fun governance_timelock_ms(g: &PolicyGovernance): u64 { g.timelock_duration_ms }
public fun governance_proposal_count(g: &PolicyGovernance): u64 { g.proposal_count }
public fun governance_admin(g: &PolicyGovernance): address { g.admin }

// -- PolicyChangeProposal accessors --
public fun proposal_governance_id(p: &PolicyChangeProposal): ID { p.governance_id }
public fun proposal_binding_id(p: &PolicyChangeProposal): ID { p.binding_id }
public fun proposal_target_version_id(p: &PolicyChangeProposal): ID { p.target_version_id }
public fun proposal_proposer(p: &PolicyChangeProposal): address { p.proposer }
public fun proposal_approvals(p: &PolicyChangeProposal): vector<address> { p.approvals }
public fun proposal_created_at_ms(p: &PolicyChangeProposal): u64 { p.created_at_ms }
public fun proposal_threshold_met_at_ms(p: &PolicyChangeProposal): u64 { p.threshold_met_at_ms }
public fun proposal_is_executed(p: &PolicyChangeProposal): bool { p.executed }
public fun proposal_is_cancelled(p: &PolicyChangeProposal): bool { p.cancelled }

// -- GovernanceReceipt accessors --
public fun receipt_governance_id(r: &GovernanceReceipt): ID { r.governance_id }
public fun receipt_binding_id(r: &GovernanceReceipt): ID { r.binding_id }
public fun receipt_target_version_id(r: &GovernanceReceipt): ID { r.target_version_id }
public fun receipt_proposal_id(r: &GovernanceReceipt): ID { r.proposal_id }
public fun receipt_executed_at_ms(r: &GovernanceReceipt): u64 { r.executed_at_ms }

// ---- Internal helpers ----

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

/// Abort if the address vector contains duplicates (O(n^2), fine for small N).
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
