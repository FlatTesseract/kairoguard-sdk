#[allow(duplicate_alias, unused_const)]
module kairo_policy_engine::policy_registry;

use sui::clock::Clock;
use sui::dynamic_field;
use sui::hash;
use sui::object::{Self, UID};
use sui::tx_context::{Self, TxContext};
use sui::transfer;
use std::bcs;
use std::option;
use std::vector;

use kairo_governance::policy_governance::{GovernanceReceipt, consume_governance_receipt};

/// Minimal MVP policy engine:
/// - policy is a versioned object
/// - policy can gate EVM destination (`to_evm`) against allow/deny lists
/// - mints a PolicyReceipt object (hard gate artifact)
///
/// Extended (Phase 1):
/// - on-chain PolicyRegistry with immutable PolicyVersion + PolicyChange objects
/// - PolicyBinding: dWallet ↔ stable policy id binding with reaffirmation checkpoints

public struct Policy has key, store {
    id: UID,
    /// Stable ID for grouping versions (string for simplicity in MVP).
    policy_id: vector<u8>,
    /// Semantic version string bytes, e.g. "1.0.0"
    policy_version: vector<u8>,
    /// Allowlist-only (MVP):
    /// Destination MUST be present in allowlist for the action to be allowed.
    /// Empty allowlist means "deny all".
    allow_to_evm: vector<vector<u8>>,
    /// If present in denylist, always denied.
    deny_to_evm: vector<vector<u8>>,
    /// Optional expiry (unix ms). 0 means no expiry.
    expires_at_ms: u64,
}

public struct PolicyReceipt has key, store {
    id: UID,
    /// Sui object id of the Policy object this receipt was minted from.
    policy_id: object::ID,
    /// Policy version bytes (copied from Policy).
    policy_version: vector<u8>,
    /// EVM chain id.
    evm_chain_id: u64,
    /// 32-byte commitment to the signed intent (keccak256 over unsigned tx bytes).
    intent_hash: vector<u8>,
    /// Optional destination address (20 bytes) this policy evaluated.
    to_evm: vector<u8>,
    /// Whether the policy allowed the action.
    allowed: bool,
    /// Reason code for denial (0=none/allowed).
    denial_reason: u64,
    /// Timestamp (ms) when minted.
    minted_at_ms: u64,
}

/// ---------------- Policy V2 + Receipt V2 (RFP-ready commitments) ----------------
///
/// V2 adds:
/// - chain allowlist
/// - function selector allow/deny
/// - ERC20 amount rule (bound to token contract = `to_evm`)
/// - receipt includes policy_root + policy_version_id for machine-verifiable audit

public struct Erc20Rule has copy, drop, store {
    /// Token contract address (20 bytes).
    token: vector<u8>,
    /// Max amount (32 bytes, big-endian).
    max_amount: vector<u8>,
}

public struct PolicyV2 has key, store {
    id: UID,
    /// Stable id grouping versions.
    policy_id: vector<u8>,
    /// Semantic version string bytes.
    policy_version: vector<u8>,
    /// Allowlist-only destination gating (empty allowlist = deny all).
    allow_to_evm: vector<vector<u8>>,
    /// Denylist destination gating.
    deny_to_evm: vector<vector<u8>>,
    /// Optional expiry (unix ms). 0 means no expiry.
    expires_at_ms: u64,

    /// Optional chain allowlist (empty = allow all).
    allow_evm_chain_ids: vector<u64>,
    /// Optional selector allowlist (each is 4 bytes). Empty = allow all (unless denylist hits).
    allow_evm_selectors: vector<vector<u8>>,
    /// Selector denylist (each is 4 bytes).
    deny_evm_selectors: vector<vector<u8>>,
    /// ERC20 rules (token contract -> max amount). Empty means no token limits.
    erc20_rules: vector<Erc20Rule>,
}

public struct PolicyReceiptV2 has key, store {
    id: UID,
    /// Sui object id of the PolicyV2 object this receipt was minted from.
    policy_object_id: object::ID,
    /// Stable id bytes (copied from PolicyV2).
    policy_stable_id: vector<u8>,
    /// Policy version bytes (copied from PolicyV2).
    policy_version: vector<u8>,
    /// The PolicyVersion object id (from PolicyRegistry).
    policy_version_id: object::ID,
    /// 32-byte commitment to policy contents (keccak256 over canonical bytes).
    policy_root: vector<u8>,

    /// EVM chain id.
    evm_chain_id: u64,
    /// 32-byte commitment to the signed intent (keccak256 over unsigned tx bytes).
    intent_hash: vector<u8>,
    /// Destination address (20 bytes).
    to_evm: vector<u8>,
    /// Function selector (4 bytes). Empty allowed if unknown.
    evm_selector: vector<u8>,
    /// ERC20 amount (32 bytes big-endian). Empty if N/A.
    erc20_amount: vector<u8>,

    /// Whether the policy allowed the action.
    allowed: bool,
    /// Reason code for denial (0=none/allowed).
    denial_reason: u64,
    /// Timestamp (ms) when minted.
    minted_at_ms: u64,
}

/// -------- Public helpers (cross-module accessors) --------
///
/// Move struct fields are module-private; other modules (e.g. custody ledger)
/// must use these accessors to bind their logic to receipt contents.

public fun receipt_is_allowed(r: &PolicyReceipt): bool { r.allowed }
public fun receipt_policy_object_id(r: &PolicyReceipt): object::ID { r.policy_id }
public fun receipt_policy_version_bytes(r: &PolicyReceipt): vector<u8> { copy_u8_vec(&r.policy_version) }
public fun receipt_intent_hash_bytes(r: &PolicyReceipt): vector<u8> { copy_u8_vec(&r.intent_hash) }
public fun receipt_to_evm_bytes(r: &PolicyReceipt): vector<u8> { copy_u8_vec(&r.to_evm) }
public fun receipt_evm_chain_id(r: &PolicyReceipt): u64 { r.evm_chain_id }
public fun receipt_denial_reason(r: &PolicyReceipt): u64 { r.denial_reason }
public fun receipt_minted_at_ms(r: &PolicyReceipt): u64 { r.minted_at_ms }

/// V2 receipt helpers (for custody ledger + off-chain verifiers).
public fun receipt_v2_is_allowed(r: &PolicyReceiptV2): bool { r.allowed }
public fun receipt_v2_policy_object_id(r: &PolicyReceiptV2): object::ID { r.policy_object_id }
public fun receipt_v2_policy_stable_id_bytes(r: &PolicyReceiptV2): vector<u8> { copy_u8_vec(&r.policy_stable_id) }
public fun receipt_v2_policy_version_bytes(r: &PolicyReceiptV2): vector<u8> { copy_u8_vec(&r.policy_version) }
public fun receipt_v2_policy_version_id(r: &PolicyReceiptV2): object::ID { r.policy_version_id }
public fun receipt_v2_policy_root_bytes(r: &PolicyReceiptV2): vector<u8> { copy_u8_vec(&r.policy_root) }
public fun receipt_v2_intent_hash_bytes(r: &PolicyReceiptV2): vector<u8> { copy_u8_vec(&r.intent_hash) }
public fun receipt_v2_to_evm_bytes(r: &PolicyReceiptV2): vector<u8> { copy_u8_vec(&r.to_evm) }
public fun receipt_v2_evm_chain_id(r: &PolicyReceiptV2): u64 { r.evm_chain_id }
public fun receipt_v2_evm_selector_bytes(r: &PolicyReceiptV2): vector<u8> { copy_u8_vec(&r.evm_selector) }
public fun receipt_v2_erc20_amount_bytes(r: &PolicyReceiptV2): vector<u8> { copy_u8_vec(&r.erc20_amount) }
public fun receipt_v2_denial_reason(r: &PolicyReceiptV2): u64 { r.denial_reason }
public fun receipt_v2_minted_at_ms(r: &PolicyReceiptV2): u64 { r.minted_at_ms }

/// Denial reason codes (MVP)
const DENIAL_NONE: u64 = 0;
const DENIAL_EXPIRED: u64 = 1;
const DENIAL_DENYLIST: u64 = 2;
const DENIAL_NOT_IN_ALLOWLIST: u64 = 3;
const DENIAL_BAD_FORMAT: u64 = 4;

// V2 denial codes
const DENIAL_CHAIN_NOT_ALLOWED: u64 = 10;
const DENIAL_BAD_SELECTOR_FORMAT: u64 = 11;
const DENIAL_SELECTOR_DENYLIST: u64 = 12;
const DENIAL_SELECTOR_NOT_ALLOWED: u64 = 13;
const DENIAL_BAD_AMOUNT_FORMAT: u64 = 14;
const DENIAL_ERC20_AMOUNT_EXCEEDS_MAX: u64 = 15;
const DENIAL_NO_POLICY_VERSION: u64 = 16;

/// Create a new policy (V2).
public fun create_policy_v2(
    policy_id: vector<u8>,
    policy_version: vector<u8>,
    allow_to_evm: vector<vector<u8>>,
    deny_to_evm: vector<vector<u8>>,
    expires_at_ms: u64,
    allow_evm_chain_ids: vector<u64>,
    allow_evm_selectors: vector<vector<u8>>,
    deny_evm_selectors: vector<vector<u8>>,
    erc20_rules: vector<Erc20Rule>,
    ctx: &mut TxContext
): PolicyV2 {
    PolicyV2 {
        id: object::new(ctx),
        policy_id,
        policy_version,
        allow_to_evm,
        deny_to_evm,
        expires_at_ms,
        allow_evm_chain_ids,
        allow_evm_selectors,
        deny_evm_selectors,
        erc20_rules,
    }
}

public fun create_and_share_policy_v2(
    policy_id: vector<u8>,
    policy_version: vector<u8>,
    allow_to_evm: vector<vector<u8>>,
    deny_to_evm: vector<vector<u8>>,
    expires_at_ms: u64,
    allow_evm_chain_ids: vector<u64>,
    allow_evm_selectors: vector<vector<u8>>,
    deny_evm_selectors: vector<vector<u8>>,
    erc20_rules: vector<Erc20Rule>,
    ctx: &mut TxContext
): object::ID {
    let policy = create_policy_v2(
        policy_id,
        policy_version,
        allow_to_evm,
        deny_to_evm,
        expires_at_ms,
        allow_evm_chain_ids,
        allow_evm_selectors,
        deny_evm_selectors,
        erc20_rules,
        ctx
    );
    let id = object::id(&policy);
    transfer::share_object(policy);
    id
}

/// Canonical bytes for PolicyV2 commitments.
public struct PolicyV2CanonicalV1 has copy, drop, store {
    policy_id: vector<u8>,
    policy_version: vector<u8>,
    allow_to_evm: vector<vector<u8>>,
    deny_to_evm: vector<vector<u8>>,
    expires_at_ms: u64,
    allow_evm_chain_ids: vector<u64>,
    allow_evm_selectors: vector<vector<u8>>,
    deny_evm_selectors: vector<vector<u8>>,
    erc20_rules: vector<Erc20Rule>,
}

public fun canonical_policy_v2_bytes(policy: &PolicyV2): vector<u8> {
    let canon = PolicyV2CanonicalV1 {
        policy_id: copy_u8_vec(&policy.policy_id),
        policy_version: copy_u8_vec(&policy.policy_version),
        allow_to_evm: copy_vec_vec_u8(&policy.allow_to_evm),
        deny_to_evm: copy_vec_vec_u8(&policy.deny_to_evm),
        expires_at_ms: policy.expires_at_ms,
        allow_evm_chain_ids: copy_u64_vec(&policy.allow_evm_chain_ids),
        allow_evm_selectors: copy_vec_vec_u8(&policy.allow_evm_selectors),
        deny_evm_selectors: copy_vec_vec_u8(&policy.deny_evm_selectors),
        erc20_rules: copy_erc20_rules(&policy.erc20_rules),
    };
    bcs::to_bytes(&canon)
}

public fun compute_policy_root_v2(policy: &PolicyV2): vector<u8> {
    let b = canonical_policy_v2_bytes(policy);
    let h = hash::keccak256(&b);
    assert!(vector::length(&h) == 32, E_BAD_ROOT_LEN);
    h
}

fun copy_u64_vec(v: &vector<u64>): vector<u64> {
    let mut out = vector::empty<u64>();
    let mut i = 0;
    let n = vector::length(v);
    while (i < n) { vector::push_back(&mut out, *vector::borrow(v, i)); i = i + 1; };
    out
}

fun copy_erc20_rules(v: &vector<Erc20Rule>): vector<Erc20Rule> {
    let mut out = vector::empty<Erc20Rule>();
    let mut i = 0;
    let n = vector::length(v);
    while (i < n) {
        let r = vector::borrow(v, i);
        vector::push_back(&mut out, Erc20Rule { token: copy_u8_vec(&r.token), max_amount: copy_u8_vec(&r.max_amount) });
        i = i + 1;
    };
    out
}

fun contains_u64(list: &vector<u64>, x: u64): bool {
    let mut i = 0;
    let n = vector::length(list);
    while (i < n) {
        if (*vector::borrow(list, i) == x) return true;
        i = i + 1;
    };
    false
}

fun contains_selector(list: &vector<vector<u8>>, selector: &vector<u8>): bool {
    contains_addr(list, selector)
}

fun u256_be_lte(a: &vector<u8>, b: &vector<u8>): bool {
    // Both are expected to be 32 bytes big-endian.
    let mut i = 0;
    while (i < 32) {
        let av = *vector::borrow(a, i);
        let bv = *vector::borrow(b, i);
        if (av < bv) return true;
        if (av > bv) return false;
        i = i + 1;
    };
    true
}

fun find_erc20_rule_max(policy: &PolicyV2, token: &vector<u8>): option::Option<vector<u8>> {
    let mut i = 0;
    let n = vector::length(&policy.erc20_rules);
    while (i < n) {
        let r = vector::borrow(&policy.erc20_rules, i);
        if (u8_vec_equal(&r.token, token)) {
            return option::some<vector<u8>>(copy_u8_vec(&r.max_amount))
        };
        i = i + 1;
    };
    option::none<vector<u8>>()
}

/// Mint a V2 receipt and transfer it to the transaction sender.
public fun mint_receipt_evm_v2_to_sender(
    registry: &PolicyRegistry,
    policy: &PolicyV2,
    clock: &Clock,
    evm_chain_id: u64,
    intent_hash: vector<u8>,
    to_evm: vector<u8>,
    evm_selector: vector<u8>,
    erc20_amount: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    let receipt = mint_receipt_evm_v2(registry, policy, clock, evm_chain_id, intent_hash, to_evm, evm_selector, erc20_amount, ctx);
    let id = object::id(&receipt);
    transfer::transfer(receipt, tx_context::sender(ctx));
    id
}

/// Mint a V2 receipt for an EVM intent.
public fun mint_receipt_evm_v2(
    registry: &PolicyRegistry,
    policy: &PolicyV2,
    clock: &Clock,
    evm_chain_id: u64,
    intent_hash: vector<u8>,
    to_evm: vector<u8>,
    evm_selector: vector<u8>,
    erc20_amount: vector<u8>,
    ctx: &mut TxContext
): PolicyReceiptV2 {
    let now = clock.timestamp_ms();

    // Require registry version to exist (RFP: every signing references a policy proof).
    let mut latest_opt = get_latest_policy_version_id(registry, &policy.policy_id);
    if (!option::is_some(&latest_opt)) {
        return PolicyReceiptV2 {
            id: object::new(ctx),
            policy_object_id: object::id(policy),
            policy_stable_id: copy_u8_vec(&policy.policy_id),
            policy_version: copy_u8_vec(&policy.policy_version),
            policy_version_id: object::id(policy), // placeholder; consumers should check allowed+denial_reason
            policy_root: compute_policy_root_v2(policy),
            evm_chain_id,
            intent_hash,
            to_evm,
            evm_selector,
            erc20_amount,
            allowed: false,
            denial_reason: DENIAL_NO_POLICY_VERSION,
            minted_at_ms: now,
        }
    };
    let latest = option::extract(&mut latest_opt);

    // Basic format checks
    if (vector::length(&intent_hash) != 32 || vector::length(&to_evm) != 20) {
        return PolicyReceiptV2 {
            id: object::new(ctx),
            policy_object_id: object::id(policy),
            policy_stable_id: copy_u8_vec(&policy.policy_id),
            policy_version: copy_u8_vec(&policy.policy_version),
            policy_version_id: latest,
            policy_root: compute_policy_root_v2(policy),
            evm_chain_id,
            intent_hash,
            to_evm,
            evm_selector,
            erc20_amount,
            allowed: false,
            denial_reason: DENIAL_BAD_FORMAT,
            minted_at_ms: now,
        }
    };
    if (vector::length(&evm_selector) != 0 && vector::length(&evm_selector) != 4) {
        return PolicyReceiptV2 {
            id: object::new(ctx),
            policy_object_id: object::id(policy),
            policy_stable_id: copy_u8_vec(&policy.policy_id),
            policy_version: copy_u8_vec(&policy.policy_version),
            policy_version_id: latest,
            policy_root: compute_policy_root_v2(policy),
            evm_chain_id,
            intent_hash,
            to_evm,
            evm_selector,
            erc20_amount,
            allowed: false,
            denial_reason: DENIAL_BAD_SELECTOR_FORMAT,
            minted_at_ms: now,
        }
    };
    if (vector::length(&erc20_amount) != 0 && vector::length(&erc20_amount) != 32) {
        return PolicyReceiptV2 {
            id: object::new(ctx),
            policy_object_id: object::id(policy),
            policy_stable_id: copy_u8_vec(&policy.policy_id),
            policy_version: copy_u8_vec(&policy.policy_version),
            policy_version_id: latest,
            policy_root: compute_policy_root_v2(policy),
            evm_chain_id,
            intent_hash,
            to_evm,
            evm_selector,
            erc20_amount,
            allowed: false,
            denial_reason: DENIAL_BAD_AMOUNT_FORMAT,
            minted_at_ms: now,
        }
    };

    // Expiry check
    if (policy.expires_at_ms != 0 && now > policy.expires_at_ms) {
        return PolicyReceiptV2 {
            id: object::new(ctx),
            policy_object_id: object::id(policy),
            policy_stable_id: copy_u8_vec(&policy.policy_id),
            policy_version: copy_u8_vec(&policy.policy_version),
            policy_version_id: latest,
            policy_root: compute_policy_root_v2(policy),
            evm_chain_id,
            intent_hash,
            to_evm,
            evm_selector,
            erc20_amount,
            allowed: false,
            denial_reason: DENIAL_EXPIRED,
            minted_at_ms: now,
        }
    };

    // Chain allowlist
    if (vector::length(&policy.allow_evm_chain_ids) != 0 && !contains_u64(&policy.allow_evm_chain_ids, evm_chain_id)) {
        return PolicyReceiptV2 {
            id: object::new(ctx),
            policy_object_id: object::id(policy),
            policy_stable_id: copy_u8_vec(&policy.policy_id),
            policy_version: copy_u8_vec(&policy.policy_version),
            policy_version_id: latest,
            policy_root: compute_policy_root_v2(policy),
            evm_chain_id,
            intent_hash,
            to_evm,
            evm_selector,
            erc20_amount,
            allowed: false,
            denial_reason: DENIAL_CHAIN_NOT_ALLOWED,
            minted_at_ms: now,
        }
    };

    // Denylist check
    if (contains_addr(&policy.deny_to_evm, &to_evm)) {
        return PolicyReceiptV2 {
            id: object::new(ctx),
            policy_object_id: object::id(policy),
            policy_stable_id: copy_u8_vec(&policy.policy_id),
            policy_version: copy_u8_vec(&policy.policy_version),
            policy_version_id: latest,
            policy_root: compute_policy_root_v2(policy),
            evm_chain_id,
            intent_hash,
            to_evm,
            evm_selector,
            erc20_amount,
            allowed: false,
            denial_reason: DENIAL_DENYLIST,
            minted_at_ms: now,
        }
    };

    // Allowlist-only: always require membership.
    let allowlist_len = vector::length(&policy.allow_to_evm);
    if (allowlist_len == 0 || !contains_addr(&policy.allow_to_evm, &to_evm)) {
        return PolicyReceiptV2 {
            id: object::new(ctx),
            policy_object_id: object::id(policy),
            policy_stable_id: copy_u8_vec(&policy.policy_id),
            policy_version: copy_u8_vec(&policy.policy_version),
            policy_version_id: latest,
            policy_root: compute_policy_root_v2(policy),
            evm_chain_id,
            intent_hash,
            to_evm,
            evm_selector,
            erc20_amount,
            allowed: false,
            denial_reason: DENIAL_NOT_IN_ALLOWLIST,
            minted_at_ms: now,
        }
    };

    // Selector checks (if selector present)
    if (vector::length(&evm_selector) == 4) {
        if (contains_selector(&policy.deny_evm_selectors, &evm_selector)) {
            return PolicyReceiptV2 {
                id: object::new(ctx),
                policy_object_id: object::id(policy),
                policy_stable_id: copy_u8_vec(&policy.policy_id),
                policy_version: copy_u8_vec(&policy.policy_version),
                policy_version_id: latest,
                policy_root: compute_policy_root_v2(policy),
                evm_chain_id,
                intent_hash,
                to_evm,
                evm_selector,
                erc20_amount,
                allowed: false,
                denial_reason: DENIAL_SELECTOR_DENYLIST,
                minted_at_ms: now,
            }
        };
        if (vector::length(&policy.allow_evm_selectors) != 0 && !contains_selector(&policy.allow_evm_selectors, &evm_selector)) {
            return PolicyReceiptV2 {
                id: object::new(ctx),
                policy_object_id: object::id(policy),
                policy_stable_id: copy_u8_vec(&policy.policy_id),
                policy_version: copy_u8_vec(&policy.policy_version),
                policy_version_id: latest,
                policy_root: compute_policy_root_v2(policy),
                evm_chain_id,
                intent_hash,
                to_evm,
                evm_selector,
                erc20_amount,
                allowed: false,
                denial_reason: DENIAL_SELECTOR_NOT_ALLOWED,
                minted_at_ms: now,
            }
        };
    };

    // ERC20 amount check (only if amount present AND rule exists for token=to_evm)
    if (vector::length(&erc20_amount) == 32 && vector::length(&policy.erc20_rules) != 0) {
        let mut max_opt = find_erc20_rule_max(policy, &to_evm);
        if (option::is_some(&max_opt)) {
            let max = option::extract(&mut max_opt);
            if (!u256_be_lte(&erc20_amount, &max)) {
                return PolicyReceiptV2 {
                    id: object::new(ctx),
                    policy_object_id: object::id(policy),
                    policy_stable_id: copy_u8_vec(&policy.policy_id),
                    policy_version: copy_u8_vec(&policy.policy_version),
                    policy_version_id: latest,
                    policy_root: compute_policy_root_v2(policy),
                    evm_chain_id,
                    intent_hash,
                    to_evm,
                    evm_selector,
                    erc20_amount,
                    allowed: false,
                    denial_reason: DENIAL_ERC20_AMOUNT_EXCEEDS_MAX,
                    minted_at_ms: now,
                }
            }
        };
    };

    PolicyReceiptV2 {
        id: object::new(ctx),
        policy_object_id: object::id(policy),
        policy_stable_id: copy_u8_vec(&policy.policy_id),
        policy_version: copy_u8_vec(&policy.policy_version),
        policy_version_id: latest,
        policy_root: compute_policy_root_v2(policy),
        evm_chain_id,
        intent_hash,
        to_evm,
        evm_selector,
        erc20_amount,
        allowed: true,
        denial_reason: DENIAL_NONE,
        minted_at_ms: now,
    }
}


/// Create a new policy version.
public fun create_policy(
    policy_id: vector<u8>,
    policy_version: vector<u8>,
    allow_to_evm: vector<vector<u8>>,
    deny_to_evm: vector<vector<u8>>,
    expires_at_ms: u64,
    ctx: &mut TxContext
): Policy {
    Policy { id: object::new(ctx), policy_id, policy_version, allow_to_evm, deny_to_evm, expires_at_ms }
}

/// Create and immediately share a policy (recommended for CLI / setup flows).
/// Returns the Policy object id for later reference.
public fun create_and_share_policy(
    policy_id: vector<u8>,
    policy_version: vector<u8>,
    allow_to_evm: vector<vector<u8>>,
    deny_to_evm: vector<vector<u8>>,
    expires_at_ms: u64,
    ctx: &mut TxContext
): object::ID {
    let policy = create_policy(policy_id, policy_version, allow_to_evm, deny_to_evm, expires_at_ms, ctx);
    let id = object::id(&policy);
    transfer::share_object(policy);
    id
}

/// Mint a receipt for an EVM intent under this policy (hard gate).
///
/// `intent_hash` must be 32 bytes.
/// `to_evm` should be 20 bytes (zero address allowed if unknown).
public fun mint_receipt_evm(
    policy: &Policy,
    clock: &Clock,
    evm_chain_id: u64,
    intent_hash: vector<u8>,
    to_evm: vector<u8>,
    ctx: &mut TxContext
): PolicyReceipt {
    let now = clock.timestamp_ms();

    // Basic format checks
    let intent_ok = vector::length(&intent_hash) == 32;
    let to_ok = vector::length(&to_evm) == 20;
    if (!intent_ok || !to_ok) {
        return PolicyReceipt {
            id: object::new(ctx),
            policy_id: object::id(policy),
            policy_version: copy_u8_vec(&policy.policy_version),
            evm_chain_id,
            intent_hash,
            to_evm,
            allowed: false,
            denial_reason: DENIAL_BAD_FORMAT,
            minted_at_ms: now,
        }
    };

    // Expiry check
    if (policy.expires_at_ms != 0 && now > policy.expires_at_ms) {
        return PolicyReceipt {
            id: object::new(ctx),
            policy_id: object::id(policy),
            policy_version: copy_u8_vec(&policy.policy_version),
            evm_chain_id,
            intent_hash,
            to_evm,
            allowed: false,
            denial_reason: DENIAL_EXPIRED,
            minted_at_ms: now,
        }
    };

    // Denylist check (still enforced)
    if (contains_addr(&policy.deny_to_evm, &to_evm)) {
        return PolicyReceipt {
            id: object::new(ctx),
            policy_id: object::id(policy),
            policy_version: copy_u8_vec(&policy.policy_version),
            evm_chain_id,
            intent_hash,
            to_evm,
            allowed: false,
            denial_reason: DENIAL_DENYLIST,
            minted_at_ms: now,
        }
    };

    // Allowlist-only: always require membership.
    let allowlist_len = vector::length(&policy.allow_to_evm);
    if (allowlist_len == 0 || !contains_addr(&policy.allow_to_evm, &to_evm)) {
        return PolicyReceipt {
            id: object::new(ctx),
            policy_id: object::id(policy),
            policy_version: copy_u8_vec(&policy.policy_version),
            evm_chain_id,
            intent_hash,
            to_evm,
            allowed: false,
            denial_reason: DENIAL_NOT_IN_ALLOWLIST,
            minted_at_ms: now,
        }
    };

    PolicyReceipt {
        id: object::new(ctx),
        policy_id: object::id(policy),
        policy_version: copy_u8_vec(&policy.policy_version),
        evm_chain_id,
        intent_hash,
        to_evm,
        allowed: true,
        denial_reason: DENIAL_NONE,
        minted_at_ms: now,
    }
}

/// Mint a receipt and transfer it to the transaction sender.
/// This avoids `UnusedValueWithoutDrop` when calling from `sui client call`.
///
/// Returns the newly created receipt object id.
public fun mint_receipt_evm_to_sender(
    policy: &Policy,
    clock: &Clock,
    evm_chain_id: u64,
    intent_hash: vector<u8>,
    to_evm: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    let receipt = mint_receipt_evm(policy, clock, evm_chain_id, intent_hash, to_evm, ctx);
    let id = object::id(&receipt);
    transfer::transfer(receipt, tx_context::sender(ctx));
    id
}

/// Convenience: share a Policy object (so multiple actors can mint receipts from it).
public fun share_policy(policy: Policy) { transfer::share_object(policy); }

/// Convenience: transfer a receipt to a recipient (e.g., the user who requested signing).
public fun transfer_receipt(receipt: PolicyReceipt, recipient: address) { transfer::transfer(receipt, recipient); }

fun contains_addr(list: &vector<vector<u8>>, addr: &vector<u8>): bool {
    let mut i = 0;
    let n = vector::length(list);
    while (i < n) {
        if (u8_vec_equal(vector::borrow(list, i), addr)) return true;
        i = i + 1;
    };
    false
}

public fun u8_vec_equal(a: &vector<u8>, b: &vector<u8>): bool {
    let la = vector::length(a);
    if (la != vector::length(b)) return false;
    let mut i = 0;
    while (i < la) {
        if (*vector::borrow(a, i) != *vector::borrow(b, i)) return false;
        i = i + 1;
    };
    true
}

public fun copy_u8_vec(v: &vector<u8>): vector<u8> {
    let mut out = vector::empty<u8>();
    let mut i = 0;
    let n = vector::length(v);
    while (i < n) { vector::push_back(&mut out, *vector::borrow(v, i)); i = i + 1; };
    out
}

/// ---------------- Policy Registry (Phase 1) ----------------

const E_BAD_ROOT_LEN: u64 = 100;
const E_STABLE_ID_NOT_FOUND: u64 = 101;
const E_NO_VERSIONS: u64 = 102;
const E_BINDING_STABLE_ID_MISMATCH: u64 = 103;
const E_BINDING_GOVERNED: u64 = 104;
const E_GOVERNANCE_RECEIPT_MISMATCH: u64 = 105;
const E_VERSION_NOT_IN_REGISTRY: u64 = 106;
const E_BINDING_ALREADY_GOVERNED: u64 = 107;
const E_BINDING_NOT_GOVERNED: u64 = 108;

/// Governance enforcement modes.
const GOVERNANCE_MODE_DISABLED: u8 = 0;
const GOVERNANCE_MODE_RECEIPT_REQUIRED: u8 = 1;

/// Shared registry for policy series and version commitments.
public struct PolicyRegistry has key, store {
    id: UID,
    series: vector<PolicySeries>,
}

/// Stored inside `PolicyRegistry` (not a standalone object).
public struct PolicySeries has copy, drop, store {
    stable_id: vector<u8>,
    versions: vector<object::ID>, // PolicyVersion ids (shared objects)
}

/// Immutable version commitment.
public struct PolicyVersion has key, store {
    id: UID,
    stable_id: vector<u8>,
    version: vector<u8>,
    policy_root: vector<u8>, // 32 bytes
    created_at_ms: u64,
}

/// Immutable changelog entry for a version.
public struct PolicyChange has key, store {
    id: UID,
    policy_version_id: object::ID,
    note: vector<u8>,
    created_at_ms: u64,
}

/// Create and share a `PolicyRegistry` object.
public fun create_and_share_policy_registry(ctx: &mut TxContext): object::ID {
    let reg = PolicyRegistry { id: object::new(ctx), series: vector::empty<PolicySeries>() };
    let id = object::id(&reg);
    transfer::share_object(reg);
    id
}

/// Canonical bytes for a Policy (for commitments / roots).
public struct PolicyCanonicalV1 has copy, drop, store {
    policy_id: vector<u8>,
    policy_version: vector<u8>,
    allow_to_evm: vector<vector<u8>>,
    deny_to_evm: vector<vector<u8>>,
    expires_at_ms: u64,
}

public fun canonical_policy_bytes(policy: &Policy): vector<u8> {
    // Encode the policy fields in a canonical order.
    // NOTE: This is a deterministic commitment; callers that want an actual Merkle tree
    // can treat this as the leaf preimage for off-chain Merkleization.
    let canon = PolicyCanonicalV1 {
        policy_id: copy_u8_vec(&policy.policy_id),
        policy_version: copy_u8_vec(&policy.policy_version),
        allow_to_evm: copy_vec_vec_u8(&policy.allow_to_evm),
        deny_to_evm: copy_vec_vec_u8(&policy.deny_to_evm),
        expires_at_ms: policy.expires_at_ms,
    };
    bcs::to_bytes(&canon)
}

/// Compute a 32-byte commitment for the current policy contents.
public fun compute_policy_root(policy: &Policy): vector<u8> {
    let b = canonical_policy_bytes(policy);
    let h = hash::keccak256(&b);
    // Sui hash returns 32 bytes; assert anyway.
    assert!(vector::length(&h) == 32, E_BAD_ROOT_LEN);
    h
}

fun copy_vec_vec_u8(v: &vector<vector<u8>>): vector<vector<u8>> {
    let mut out = vector::empty<vector<u8>>();
    let mut i = 0;
    let n = vector::length(v);
    while (i < n) { vector::push_back(&mut out, copy_u8_vec(vector::borrow(v, i))); i = i + 1; };
    out
}

/// Register a new version commitment in the registry.
///
/// - Creates and shares a `PolicyVersion` object (immutable).
/// - Creates and shares a `PolicyChange` object (immutable).
/// - Updates the registry series list (append-only for versions).
///
/// Returns the PolicyVersion object id.
public fun register_policy_version(
    registry: &mut PolicyRegistry,
    clock: &Clock,
    stable_id: vector<u8>,
    version: vector<u8>,
    policy_root: vector<u8>,
    note: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    assert!(vector::length(&policy_root) == 32, E_BAD_ROOT_LEN);
    let now = clock.timestamp_ms();

    let pv = PolicyVersion {
        id: object::new(ctx),
        stable_id: copy_u8_vec(&stable_id),
        version: copy_u8_vec(&version),
        policy_root: copy_u8_vec(&policy_root),
        created_at_ms: now,
    };
    let pv_id = object::id(&pv);
    transfer::share_object(pv);

    let ch = PolicyChange {
        id: object::new(ctx),
        policy_version_id: pv_id,
        note,
        created_at_ms: now,
    };
    transfer::share_object(ch);

    // Find or create series.
    let mut i = 0;
    let n = vector::length(&registry.series);
    while (i < n) {
        let s = vector::borrow_mut(&mut registry.series, i);
        if (u8_vec_equal(&s.stable_id, &stable_id)) {
            vector::push_back(&mut s.versions, pv_id);
            return pv_id
        };
        i = i + 1;
    };
    // Create new series.
    let mut versions = vector::empty<object::ID>();
    vector::push_back(&mut versions, pv_id);
    vector::push_back(&mut registry.series, PolicySeries { stable_id, versions });
    pv_id
}

/// Convenience: register a PolicyVersion by reading the stable_id + version from a `Policy`
/// and computing `policy_root` on-chain.
///
/// This avoids having to reproduce canonical serialization/hash logic off-chain.
public fun register_policy_version_from_policy(
    registry: &mut PolicyRegistry,
    clock: &Clock,
    policy: &Policy,
    note: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    let stable_id = copy_u8_vec(&policy.policy_id);
    let version = copy_u8_vec(&policy.policy_version);
    let root = compute_policy_root(policy);
    register_policy_version(registry, clock, stable_id, version, root, note, ctx)
}

/// Convenience: register a PolicyVersion from a PolicyV2 object (computes policy_root_v2 on-chain).
public fun register_policy_version_from_policy_v2(
    registry: &mut PolicyRegistry,
    clock: &Clock,
    policy: &PolicyV2,
    note: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    let stable_id = copy_u8_vec(&policy.policy_id);
    let version = copy_u8_vec(&policy.policy_version);
    let root = compute_policy_root_v2(policy);
    register_policy_version(registry, clock, stable_id, version, root, note, ctx)
}

/// Best-effort: return the latest PolicyVersion id for a stable id.
public fun get_latest_policy_version_id(registry: &PolicyRegistry, stable_id: &vector<u8>): option::Option<object::ID> {
    let mut i = 0;
    let n = vector::length(&registry.series);
    while (i < n) {
        let s = vector::borrow(&registry.series, i);
        if (u8_vec_equal(&s.stable_id, stable_id)) {
            let m = vector::length(&s.versions);
            if (m == 0) return option::none<object::ID>();
            return option::some<object::ID>(*vector::borrow(&s.versions, m - 1))
        };
        i = i + 1;
    };
    option::none<object::ID>()
}

/// ---------------- Policy Binding (Phase 1) ----------------

public struct PolicyBinding has key, store {
    id: UID,
    /// Opaque dWallet identifier (we store bytes so callers can choose encoding).
    dwallet_id: vector<u8>,
    /// Stable policy id this binding follows.
    stable_id: vector<u8>,
    /// The currently affirmed version id.
    active_version_id: object::ID,
    /// Timestamp (ms) when last updated.
    updated_at_ms: u64,
}

/// Create and share a PolicyBinding for a dWallet to the *current* registry version.
/// Aborts if `stable_id` has no registered versions.
public fun create_and_share_policy_binding(
    registry: &PolicyRegistry,
    clock: &Clock,
    dwallet_id: vector<u8>,
    stable_id: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    let now = clock.timestamp_ms();
    let mut latest_opt = get_latest_policy_version_id(registry, &stable_id);
    assert!(option::is_some(&latest_opt), E_NO_VERSIONS);
    let latest = option::extract(&mut latest_opt);
    let binding = PolicyBinding {
        id: object::new(ctx),
        dwallet_id,
        stable_id,
        active_version_id: latest,
        updated_at_ms: now,
    };
    let id = object::id(&binding);
    transfer::share_object(binding);
    id
}

/// Reaffirm the binding to the latest registry version.
/// Returns the new active version id.
/// Aborts with E_BINDING_GOVERNED if the binding is under hard governance enforcement.
public fun reaffirm_policy_binding(
    binding: &mut PolicyBinding,
    registry: &PolicyRegistry,
    clock: &Clock
): object::ID {
    // Governance hard gate: if marker exists with mode=ReceiptRequired, block direct reaffirm.
    if (dynamic_field::exists_(&binding.id, GovernanceMarker {})) {
        let info = dynamic_field::borrow<GovernanceMarker, GovernanceInfo>(&binding.id, GovernanceMarker {});
        if (info.mode == GOVERNANCE_MODE_RECEIPT_REQUIRED) {
            abort E_BINDING_GOVERNED
        };
        // mode == DISABLED: fall through, allow normal reaffirm
    };

    let mut latest_opt = get_latest_policy_version_id(registry, &binding.stable_id);
    assert!(option::is_some(&latest_opt), E_NO_VERSIONS);
    let latest = option::extract(&mut latest_opt);
    // Stable id match is inherent; binding stores it. Keep a defensive check.
    assert!(vector::length(&binding.stable_id) > 0, E_BINDING_STABLE_ID_MISMATCH);
    binding.active_version_id = latest;
    binding.updated_at_ms = clock.timestamp_ms();
    latest
}

public fun binding_active_version_id(b: &PolicyBinding): object::ID { b.active_version_id }
public fun binding_stable_id_bytes(b: &PolicyBinding): vector<u8> { copy_u8_vec(&b.stable_id) }
public fun binding_dwallet_id_bytes(b: &PolicyBinding): vector<u8> { copy_u8_vec(&b.dwallet_id) }
public fun binding_updated_at_ms(b: &PolicyBinding): u64 { b.updated_at_ms }

/// ---------------- Governance Hard Gate ----------------
///
/// Dynamic-field marker on PolicyBinding for governance opt-in.
/// The policy engine dynamic field is the single source of truth
/// for whether a binding is governed.

/// Dynamic field key for the governance marker.
public struct GovernanceMarker has copy, drop, store {}

/// Dynamic field value storing governance configuration.
public struct GovernanceInfo has store, drop, copy {
    /// The governance object ID (from kairo_governance) controlling this binding.
    governance_id: object::ID,
    /// Enforcement mode: 0 = Disabled (soft), 1 = ReceiptRequired (hard).
    mode: u8,
}

/// Attach governance to a binding in Disabled mode (staged rollout).
/// Only the binding owner / admin should call this. No on-chain admin cap
/// is checked here because the binding is a shared object accessed via PTB
/// construction — operational safety is handled at the backend level.
public fun set_binding_governance(
    binding: &mut PolicyBinding,
    governance_id: object::ID,
    mode: u8,
) {
    assert!(
        !dynamic_field::exists_(&binding.id, GovernanceMarker {}),
        E_BINDING_ALREADY_GOVERNED
    );
    dynamic_field::add(
        &mut binding.id,
        GovernanceMarker {},
        GovernanceInfo { governance_id, mode },
    );
}

/// Flip governance mode from Disabled to ReceiptRequired (two-step activation).
public fun activate_binding_governance(
    binding: &mut PolicyBinding,
) {
    assert!(
        dynamic_field::exists_(&binding.id, GovernanceMarker {}),
        E_BINDING_NOT_GOVERNED
    );
    let info = dynamic_field::borrow_mut<GovernanceMarker, GovernanceInfo>(
        &mut binding.id, GovernanceMarker {}
    );
    info.mode = GOVERNANCE_MODE_RECEIPT_REQUIRED;
}

/// Remove governance from a binding entirely.
public fun remove_binding_governance(
    binding: &mut PolicyBinding,
) {
    assert!(
        dynamic_field::exists_(&binding.id, GovernanceMarker {}),
        E_BINDING_NOT_GOVERNED
    );
    let _info = dynamic_field::remove<GovernanceMarker, GovernanceInfo>(
        &mut binding.id, GovernanceMarker {}
    );
}

/// Read the governance info for a binding (returns option).
public fun get_binding_governance_info(binding: &PolicyBinding): option::Option<GovernanceInfo> {
    if (dynamic_field::exists_(&binding.id, GovernanceMarker {})) {
        let info = dynamic_field::borrow<GovernanceMarker, GovernanceInfo>(
            &binding.id, GovernanceMarker {}
        );
        option::some(*info)
    } else {
        option::none<GovernanceInfo>()
    }
}

public fun governance_info_id(info: &GovernanceInfo): object::ID { info.governance_id }
public fun governance_info_mode(info: &GovernanceInfo): u8 { info.mode }

/// Reaffirm a governed binding using a GovernanceReceipt from the governance package.
/// Validates that the receipt matches the binding's governance configuration,
/// consumes the receipt (single-use), and sets the binding to the approved version.
///
/// Mandatory check: target_version_id must exist in the registry for this stable_id.
public fun governed_reaffirm_policy_binding(
    binding: &mut PolicyBinding,
    registry: &PolicyRegistry,
    clock: &Clock,
    receipt: GovernanceReceipt,
): object::ID {
    // 1. Read the governance info from the binding.
    assert!(
        dynamic_field::exists_(&binding.id, GovernanceMarker {}),
        E_BINDING_NOT_GOVERNED
    );
    let info = dynamic_field::borrow<GovernanceMarker, GovernanceInfo>(
        &binding.id, GovernanceMarker {}
    );

    // 2. Consume receipt and extract fields.
    let expected_governance_id = info.governance_id;
    let (receipt_governance_id, receipt_binding_id, receipt_target_version_id, _receipt_proposal_id) =
        consume_governance_receipt(receipt);

    // 3. Validate receipt matches this binding's governance.
    assert!(receipt_governance_id == expected_governance_id, E_GOVERNANCE_RECEIPT_MISMATCH);

    // 4. Validate receipt is for this binding.
    assert!(receipt_binding_id == object::id(binding), E_GOVERNANCE_RECEIPT_MISMATCH);

    // 5. Mandatory: target_version_id must exist in registry for this stable_id.
    assert!(
        version_exists_in_registry(registry, &binding.stable_id, receipt_target_version_id),
        E_VERSION_NOT_IN_REGISTRY
    );

    // 6. Apply the approved version change.
    binding.active_version_id = receipt_target_version_id;
    binding.updated_at_ms = clock.timestamp_ms();
    receipt_target_version_id
}

/// Check if a specific version ID exists in the registry for a given stable_id.
fun version_exists_in_registry(
    registry: &PolicyRegistry,
    stable_id: &vector<u8>,
    version_id: object::ID,
): bool {
    let mut i = 0;
    let n = vector::length(&registry.series);
    while (i < n) {
        let s = vector::borrow(&registry.series, i);
        if (u8_vec_equal(&s.stable_id, stable_id)) {
            let mut j = 0;
            let m = vector::length(&s.versions);
            while (j < m) {
                if (*vector::borrow(&s.versions, j) == version_id) return true;
                j = j + 1;
            };
            return false
        };
        i = i + 1;
    };
    false
}

/// ---------------- Policy V3 + Receipt V3 (Multi-Chain Support) ----------------
///
/// V3 adds support for Bitcoin and Solana chains:
/// - Chain namespace (EVM=1, Bitcoin=2, Solana=3)
/// - Chain-agnostic destination rules
/// - Bitcoin-specific: script type rules, fee rate limits
/// - Solana-specific: program ID allowlists

/// Chain namespace constants
const NAMESPACE_EVM: u8 = 1;
const NAMESPACE_BITCOIN: u8 = 2;
const NAMESPACE_SOLANA: u8 = 3;

/// Bitcoin script type constants
const BTC_SCRIPT_P2PKH: u8 = 0;
const BTC_SCRIPT_P2WPKH: u8 = 1;
const BTC_SCRIPT_P2TR: u8 = 2;

/// V3 denial codes (extending V2)
const DENIAL_NAMESPACE_NOT_ALLOWED: u64 = 20;
const DENIAL_BTC_SCRIPT_TYPE_NOT_ALLOWED: u64 = 21;
const DENIAL_BTC_FEE_RATE_EXCEEDED: u64 = 22;
const DENIAL_SOL_PROGRAM_DENYLISTED: u64 = 23;
const DENIAL_SOL_PROGRAM_NOT_ALLOWED: u64 = 24;

/// Chain identifier for multi-chain policies.
public struct ChainIdV3 has copy, drop, store {
    namespace: u8,
    /// Chain-specific identifier:
    /// - EVM: chain ID as u64 encoded in 8 bytes
    /// - Bitcoin: "mainnet", "testnet", "signet" as bytes
    /// - Solana: "mainnet-beta", "devnet", "testnet" as bytes
    chain_id: vector<u8>,
}

/// Bitcoin-specific policy rules.
public struct BitcoinRulesV3 has copy, drop, store {
    /// Allowed script types (empty = allow all).
    allow_script_types: vector<u8>,
    /// Maximum fee rate in sat/vByte (0 = no limit).
    max_fee_rate_sat_vb: u64,
}

/// Solana-specific policy rules.
public struct SolanaRulesV3 has copy, drop, store {
    /// Allowed program IDs (32 bytes each). Empty = allow all (unless denylist hits).
    allow_program_ids: vector<vector<u8>>,
    /// Denied program IDs (32 bytes each).
    deny_program_ids: vector<vector<u8>>,
}

/// Multi-chain policy (V3).
public struct PolicyV3 has key, store {
    id: UID,
    /// Stable id grouping versions.
    policy_id: vector<u8>,
    /// Semantic version string bytes.
    policy_version: vector<u8>,
    /// Optional expiry (unix ms). 0 means no expiry.
    expires_at_ms: u64,

    /// Allowed chain namespaces (empty = allow all).
    allow_namespaces: vector<u8>,
    /// Allowed chain IDs (namespace + chain_id pairs).
    allow_chain_ids: vector<ChainIdV3>,

    /// Chain-agnostic destination allowlist.
    /// Format depends on namespace:
    /// - EVM: 20 bytes
    /// - Bitcoin: 25-62 bytes (base58/bech32 decoded)
    /// - Solana: 32 bytes
    allow_destinations: vector<vector<u8>>,
    /// Chain-agnostic destination denylist.
    deny_destinations: vector<vector<u8>>,

    /// EVM-specific rules (same as V2)
    evm_allow_selectors: vector<vector<u8>>,
    evm_deny_selectors: vector<vector<u8>>,
    erc20_rules: vector<Erc20Rule>,

    /// Bitcoin-specific rules
    btc_rules: BitcoinRulesV3,

    /// Solana-specific rules
    sol_rules: SolanaRulesV3,
}

/// Multi-chain policy receipt (V3).
public struct PolicyReceiptV3 has key, store {
    id: UID,
    /// Sui object id of the PolicyV3 object this receipt was minted from.
    policy_object_id: object::ID,
    /// Stable id bytes (copied from PolicyV3).
    policy_stable_id: vector<u8>,
    /// Policy version bytes (copied from PolicyV3).
    policy_version: vector<u8>,
    /// The PolicyVersion object id (from PolicyRegistry).
    policy_version_id: object::ID,
    /// 32-byte commitment to policy contents (keccak256 over canonical bytes).
    policy_root: vector<u8>,

    /// Chain namespace (1=EVM, 2=Bitcoin, 3=Solana).
    namespace: u8,
    /// Chain-specific identifier.
    chain_id: vector<u8>,
    /// 32-byte commitment to the signed intent.
    intent_hash: vector<u8>,
    /// Destination address (chain-native format).
    destination: vector<u8>,

    /// Chain-specific fields
    /// EVM: function selector (4 bytes)
    evm_selector: vector<u8>,
    /// EVM: ERC20 amount (32 bytes)
    erc20_amount: vector<u8>,
    /// Bitcoin: script type (1 byte)
    btc_script_type: u8,
    /// Bitcoin: fee rate in sat/vByte
    btc_fee_rate: u64,
    /// Solana: program IDs involved (list of 32-byte keys)
    sol_program_ids: vector<vector<u8>>,

    /// Whether the policy allowed the action.
    allowed: bool,
    /// Reason code for denial (0=none/allowed).
    denial_reason: u64,
    /// Timestamp (ms) when minted.
    minted_at_ms: u64,
}

/// Create a new PolicyV3.
public fun create_policy_v3(
    policy_id: vector<u8>,
    policy_version: vector<u8>,
    expires_at_ms: u64,
    allow_namespaces: vector<u8>,
    allow_chain_ids: vector<ChainIdV3>,
    allow_destinations: vector<vector<u8>>,
    deny_destinations: vector<vector<u8>>,
    evm_allow_selectors: vector<vector<u8>>,
    evm_deny_selectors: vector<vector<u8>>,
    erc20_rules: vector<Erc20Rule>,
    btc_rules: BitcoinRulesV3,
    sol_rules: SolanaRulesV3,
    ctx: &mut TxContext
): PolicyV3 {
    PolicyV3 {
        id: object::new(ctx),
        policy_id,
        policy_version,
        expires_at_ms,
        allow_namespaces,
        allow_chain_ids,
        allow_destinations,
        deny_destinations,
        evm_allow_selectors,
        evm_deny_selectors,
        erc20_rules,
        btc_rules,
        sol_rules,
    }
}

/// Create and share a PolicyV3.
public fun create_and_share_policy_v3(
    policy_id: vector<u8>,
    policy_version: vector<u8>,
    expires_at_ms: u64,
    allow_namespaces: vector<u8>,
    allow_chain_ids: vector<ChainIdV3>,
    allow_destinations: vector<vector<u8>>,
    deny_destinations: vector<vector<u8>>,
    evm_allow_selectors: vector<vector<u8>>,
    evm_deny_selectors: vector<vector<u8>>,
    erc20_rules: vector<Erc20Rule>,
    btc_rules: BitcoinRulesV3,
    sol_rules: SolanaRulesV3,
    ctx: &mut TxContext
): object::ID {
    let policy = create_policy_v3(
        policy_id, policy_version, expires_at_ms, allow_namespaces, allow_chain_ids,
        allow_destinations, deny_destinations, evm_allow_selectors, evm_deny_selectors,
        erc20_rules, btc_rules, sol_rules, ctx
    );
    let id = object::id(&policy);
    transfer::share_object(policy);
    id
}

/// Create default (empty) Bitcoin rules.
public fun default_btc_rules(): BitcoinRulesV3 {
    BitcoinRulesV3 {
        allow_script_types: vector::empty<u8>(),
        max_fee_rate_sat_vb: 0,
    }
}

/// Create default (empty) Solana rules.
public fun default_sol_rules(): SolanaRulesV3 {
    SolanaRulesV3 {
        allow_program_ids: vector::empty<vector<u8>>(),
        deny_program_ids: vector::empty<vector<u8>>(),
    }
}

/// Canonical bytes for PolicyV3 commitments.
public struct PolicyV3CanonicalV1 has copy, drop, store {
    policy_id: vector<u8>,
    policy_version: vector<u8>,
    expires_at_ms: u64,
    allow_namespaces: vector<u8>,
    allow_destinations: vector<vector<u8>>,
    deny_destinations: vector<vector<u8>>,
    evm_allow_selectors: vector<vector<u8>>,
    evm_deny_selectors: vector<vector<u8>>,
}

/// Compute policy root for V3.
public fun compute_policy_root_v3(policy: &PolicyV3): vector<u8> {
    let canon = PolicyV3CanonicalV1 {
        policy_id: copy_u8_vec(&policy.policy_id),
        policy_version: copy_u8_vec(&policy.policy_version),
        expires_at_ms: policy.expires_at_ms,
        allow_namespaces: copy_u8_vec(&policy.allow_namespaces),
        allow_destinations: copy_vec_vec_u8(&policy.allow_destinations),
        deny_destinations: copy_vec_vec_u8(&policy.deny_destinations),
        evm_allow_selectors: copy_vec_vec_u8(&policy.evm_allow_selectors),
        evm_deny_selectors: copy_vec_vec_u8(&policy.evm_deny_selectors),
    };
    let b = bcs::to_bytes(&canon);
    let h = hash::keccak256(&b);
    assert!(vector::length(&h) == 32, E_BAD_ROOT_LEN);
    h
}

/// Check if namespace is allowed.
fun is_namespace_allowed(policy: &PolicyV3, namespace: u8): bool {
    let n = vector::length(&policy.allow_namespaces);
    if (n == 0) return true; // Empty = allow all
    let mut i = 0;
    while (i < n) {
        if (*vector::borrow(&policy.allow_namespaces, i) == namespace) return true;
        i = i + 1;
    };
    false
}

/// Check if Bitcoin script type is allowed.
fun is_btc_script_type_allowed(policy: &PolicyV3, script_type: u8): bool {
    let n = vector::length(&policy.btc_rules.allow_script_types);
    if (n == 0) return true; // Empty = allow all
    let mut i = 0;
    while (i < n) {
        if (*vector::borrow(&policy.btc_rules.allow_script_types, i) == script_type) return true;
        i = i + 1;
    };
    false
}

/// Check if Solana program is allowed.
fun is_sol_program_allowed(policy: &PolicyV3, program_id: &vector<u8>): bool {
    // First check denylist
    if (contains_addr(&policy.sol_rules.deny_program_ids, program_id)) return false;
    // Then check allowlist (empty = allow all)
    let n = vector::length(&policy.sol_rules.allow_program_ids);
    if (n == 0) return true;
    contains_addr(&policy.sol_rules.allow_program_ids, program_id)
}

/// Mint a V3 receipt for a multi-chain intent.
public fun mint_receipt_v3(
    registry: &PolicyRegistry,
    policy: &PolicyV3,
    clock: &Clock,
    namespace: u8,
    chain_id: vector<u8>,
    intent_hash: vector<u8>,
    destination: vector<u8>,
    evm_selector: vector<u8>,
    erc20_amount: vector<u8>,
    btc_script_type: u8,
    btc_fee_rate: u64,
    sol_program_ids: vector<vector<u8>>,
    ctx: &mut TxContext
): PolicyReceiptV3 {
    let now = clock.timestamp_ms();

    // Get latest policy version from registry
    let mut latest_opt = get_latest_policy_version_id(registry, &policy.policy_id);
    if (!option::is_some(&latest_opt)) {
        return PolicyReceiptV3 {
            id: object::new(ctx),
            policy_object_id: object::id(policy),
            policy_stable_id: copy_u8_vec(&policy.policy_id),
            policy_version: copy_u8_vec(&policy.policy_version),
            policy_version_id: object::id(policy),
            policy_root: compute_policy_root_v3(policy),
            namespace,
            chain_id,
            intent_hash,
            destination,
            evm_selector,
            erc20_amount,
            btc_script_type,
            btc_fee_rate,
            sol_program_ids,
            allowed: false,
            denial_reason: DENIAL_NO_POLICY_VERSION,
            minted_at_ms: now,
        }
    };
    let latest = option::extract(&mut latest_opt);

    // Check namespace allowed
    if (!is_namespace_allowed(policy, namespace)) {
        return PolicyReceiptV3 {
            id: object::new(ctx),
            policy_object_id: object::id(policy),
            policy_stable_id: copy_u8_vec(&policy.policy_id),
            policy_version: copy_u8_vec(&policy.policy_version),
            policy_version_id: latest,
            policy_root: compute_policy_root_v3(policy),
            namespace,
            chain_id,
            intent_hash,
            destination,
            evm_selector,
            erc20_amount,
            btc_script_type,
            btc_fee_rate,
            sol_program_ids,
            allowed: false,
            denial_reason: DENIAL_NAMESPACE_NOT_ALLOWED,
            minted_at_ms: now,
        }
    };

    // Check expiry
    if (policy.expires_at_ms != 0 && now > policy.expires_at_ms) {
        return PolicyReceiptV3 {
            id: object::new(ctx),
            policy_object_id: object::id(policy),
            policy_stable_id: copy_u8_vec(&policy.policy_id),
            policy_version: copy_u8_vec(&policy.policy_version),
            policy_version_id: latest,
            policy_root: compute_policy_root_v3(policy),
            namespace,
            chain_id,
            intent_hash,
            destination,
            evm_selector,
            erc20_amount,
            btc_script_type,
            btc_fee_rate,
            sol_program_ids,
            allowed: false,
            denial_reason: DENIAL_EXPIRED,
            minted_at_ms: now,
        }
    };

    // Check destination denylist
    if (contains_addr(&policy.deny_destinations, &destination)) {
        return PolicyReceiptV3 {
            id: object::new(ctx),
            policy_object_id: object::id(policy),
            policy_stable_id: copy_u8_vec(&policy.policy_id),
            policy_version: copy_u8_vec(&policy.policy_version),
            policy_version_id: latest,
            policy_root: compute_policy_root_v3(policy),
            namespace,
            chain_id,
            intent_hash,
            destination,
            evm_selector,
            erc20_amount,
            btc_script_type,
            btc_fee_rate,
            sol_program_ids,
            allowed: false,
            denial_reason: DENIAL_DENYLIST,
            minted_at_ms: now,
        }
    };

    // Check destination allowlist
    let allow_len = vector::length(&policy.allow_destinations);
    if (allow_len > 0 && !contains_addr(&policy.allow_destinations, &destination)) {
        return PolicyReceiptV3 {
            id: object::new(ctx),
            policy_object_id: object::id(policy),
            policy_stable_id: copy_u8_vec(&policy.policy_id),
            policy_version: copy_u8_vec(&policy.policy_version),
            policy_version_id: latest,
            policy_root: compute_policy_root_v3(policy),
            namespace,
            chain_id,
            intent_hash,
            destination,
            evm_selector,
            erc20_amount,
            btc_script_type,
            btc_fee_rate,
            sol_program_ids,
            allowed: false,
            denial_reason: DENIAL_NOT_IN_ALLOWLIST,
            minted_at_ms: now,
        }
    };

    // Bitcoin-specific checks
    if (namespace == NAMESPACE_BITCOIN) {
        if (!is_btc_script_type_allowed(policy, btc_script_type)) {
            return PolicyReceiptV3 {
                id: object::new(ctx),
                policy_object_id: object::id(policy),
                policy_stable_id: copy_u8_vec(&policy.policy_id),
                policy_version: copy_u8_vec(&policy.policy_version),
                policy_version_id: latest,
                policy_root: compute_policy_root_v3(policy),
                namespace,
                chain_id,
                intent_hash,
                destination,
                evm_selector,
                erc20_amount,
                btc_script_type,
                btc_fee_rate,
                sol_program_ids,
                allowed: false,
                denial_reason: DENIAL_BTC_SCRIPT_TYPE_NOT_ALLOWED,
                minted_at_ms: now,
            }
        };
        if (policy.btc_rules.max_fee_rate_sat_vb > 0 && btc_fee_rate > policy.btc_rules.max_fee_rate_sat_vb) {
            return PolicyReceiptV3 {
                id: object::new(ctx),
                policy_object_id: object::id(policy),
                policy_stable_id: copy_u8_vec(&policy.policy_id),
                policy_version: copy_u8_vec(&policy.policy_version),
                policy_version_id: latest,
                policy_root: compute_policy_root_v3(policy),
                namespace,
                chain_id,
                intent_hash,
                destination,
                evm_selector,
                erc20_amount,
                btc_script_type,
                btc_fee_rate,
                sol_program_ids,
                allowed: false,
                denial_reason: DENIAL_BTC_FEE_RATE_EXCEEDED,
                minted_at_ms: now,
            }
        };
    };

    // Solana-specific checks
    if (namespace == NAMESPACE_SOLANA) {
        let mut i = 0;
        let n = vector::length(&sol_program_ids);
        while (i < n) {
            let prog = vector::borrow(&sol_program_ids, i);
            if (!is_sol_program_allowed(policy, prog)) {
                return PolicyReceiptV3 {
                    id: object::new(ctx),
                    policy_object_id: object::id(policy),
                    policy_stable_id: copy_u8_vec(&policy.policy_id),
                    policy_version: copy_u8_vec(&policy.policy_version),
                    policy_version_id: latest,
                    policy_root: compute_policy_root_v3(policy),
                    namespace,
                    chain_id,
                    intent_hash,
                    destination,
                    evm_selector,
                    erc20_amount,
                    btc_script_type,
                    btc_fee_rate,
                    sol_program_ids,
                    allowed: false,
                    denial_reason: DENIAL_SOL_PROGRAM_NOT_ALLOWED,
                    minted_at_ms: now,
                }
            };
            i = i + 1;
        };
    };

    // EVM-specific checks (selector)
    if (namespace == NAMESPACE_EVM && vector::length(&evm_selector) == 4) {
        if (contains_selector(&policy.evm_deny_selectors, &evm_selector)) {
            return PolicyReceiptV3 {
                id: object::new(ctx),
                policy_object_id: object::id(policy),
                policy_stable_id: copy_u8_vec(&policy.policy_id),
                policy_version: copy_u8_vec(&policy.policy_version),
                policy_version_id: latest,
                policy_root: compute_policy_root_v3(policy),
                namespace,
                chain_id,
                intent_hash,
                destination,
                evm_selector,
                erc20_amount,
                btc_script_type,
                btc_fee_rate,
                sol_program_ids,
                allowed: false,
                denial_reason: DENIAL_SELECTOR_DENYLIST,
                minted_at_ms: now,
            }
        };
        if (vector::length(&policy.evm_allow_selectors) > 0 && !contains_selector(&policy.evm_allow_selectors, &evm_selector)) {
            return PolicyReceiptV3 {
                id: object::new(ctx),
                policy_object_id: object::id(policy),
                policy_stable_id: copy_u8_vec(&policy.policy_id),
                policy_version: copy_u8_vec(&policy.policy_version),
                policy_version_id: latest,
                policy_root: compute_policy_root_v3(policy),
                namespace,
                chain_id,
                intent_hash,
                destination,
                evm_selector,
                erc20_amount,
                btc_script_type,
                btc_fee_rate,
                sol_program_ids,
                allowed: false,
                denial_reason: DENIAL_SELECTOR_NOT_ALLOWED,
                minted_at_ms: now,
            }
        };
    };

    // All checks passed
    PolicyReceiptV3 {
        id: object::new(ctx),
        policy_object_id: object::id(policy),
        policy_stable_id: copy_u8_vec(&policy.policy_id),
        policy_version: copy_u8_vec(&policy.policy_version),
        policy_version_id: latest,
        policy_root: compute_policy_root_v3(policy),
        namespace,
        chain_id,
        intent_hash,
        destination,
        evm_selector,
        erc20_amount,
        btc_script_type,
        btc_fee_rate,
        sol_program_ids,
        allowed: true,
        denial_reason: DENIAL_NONE,
        minted_at_ms: now,
    }
}

/// Mint V3 receipt and transfer to sender.
public fun mint_receipt_v3_to_sender(
    registry: &PolicyRegistry,
    policy: &PolicyV3,
    clock: &Clock,
    namespace: u8,
    chain_id: vector<u8>,
    intent_hash: vector<u8>,
    destination: vector<u8>,
    evm_selector: vector<u8>,
    erc20_amount: vector<u8>,
    btc_script_type: u8,
    btc_fee_rate: u64,
    sol_program_ids: vector<vector<u8>>,
    ctx: &mut TxContext
): object::ID {
    let receipt = mint_receipt_v3(
        registry, policy, clock, namespace, chain_id, intent_hash, destination,
        evm_selector, erc20_amount, btc_script_type, btc_fee_rate, sol_program_ids, ctx
    );
    let id = object::id(&receipt);
    transfer::transfer(receipt, tx_context::sender(ctx));
    id
}

/// V3 receipt accessors
public fun receipt_v3_is_allowed(r: &PolicyReceiptV3): bool { r.allowed }
public fun receipt_v3_namespace(r: &PolicyReceiptV3): u8 { r.namespace }
public fun receipt_v3_chain_id_bytes(r: &PolicyReceiptV3): vector<u8> { copy_u8_vec(&r.chain_id) }
public fun receipt_v3_policy_object_id(r: &PolicyReceiptV3): object::ID { r.policy_object_id }
public fun receipt_v3_policy_stable_id_bytes(r: &PolicyReceiptV3): vector<u8> { copy_u8_vec(&r.policy_stable_id) }
public fun receipt_v3_policy_version_bytes(r: &PolicyReceiptV3): vector<u8> { copy_u8_vec(&r.policy_version) }
public fun receipt_v3_policy_version_id(r: &PolicyReceiptV3): object::ID { r.policy_version_id }
public fun receipt_v3_policy_root_bytes(r: &PolicyReceiptV3): vector<u8> { copy_u8_vec(&r.policy_root) }
public fun receipt_v3_intent_hash_bytes(r: &PolicyReceiptV3): vector<u8> { copy_u8_vec(&r.intent_hash) }
public fun receipt_v3_destination_bytes(r: &PolicyReceiptV3): vector<u8> { copy_u8_vec(&r.destination) }
public fun receipt_v3_denial_reason(r: &PolicyReceiptV3): u64 { r.denial_reason }
public fun receipt_v3_minted_at_ms(r: &PolicyReceiptV3): u64 { r.minted_at_ms }

/// Consume (delete) a PolicyReceiptV3 and return its object ID.
/// This is used for one-time authorization - the receipt cannot be reused.
public fun consume_receipt_v3(receipt: PolicyReceiptV3): object::ID {
    let receipt_id = object::id(&receipt);
    let PolicyReceiptV3 {
        id: receipt_uid,
        policy_object_id: _,
        policy_stable_id: _,
        policy_version: _,
        policy_version_id: _,
        policy_root: _,
        namespace: _,
        chain_id: _,
        intent_hash: _,
        destination: _,
        evm_selector: _,
        erc20_amount: _,
        btc_script_type: _,
        btc_fee_rate: _,
        sol_program_ids: _,
        allowed: _,
        denial_reason: _,
        minted_at_ms: _,
    } = receipt;
    object::delete(receipt_uid);
    receipt_id
}

/// Register a PolicyVersion from a PolicyV3 object.
public fun register_policy_version_from_policy_v3(
    registry: &mut PolicyRegistry,
    clock: &Clock,
    policy: &PolicyV3,
    note: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    let stable_id = copy_u8_vec(&policy.policy_id);
    let version = copy_u8_vec(&policy.policy_version);
    let root = compute_policy_root_v3(policy);
    register_policy_version(registry, clock, stable_id, version, root, note, ctx)
}

// ============================================================================
// PolicyV4: Extensible Generic Rules Engine
// ============================================================================
//
// V4 replaces per-chain dedicated fields with a generic `rules` vector.
// New rule types can be added via constant + checking code without struct changes.

use kairo_policy_engine::policy_governance::{
    GovernanceReceiptV2,
    consume_governance_receipt_v2,
};

/// Rule type constants
const RULE_MAX_NATIVE_VALUE: u8 = 1;
const RULE_EVM_SELECTOR_ALLOW: u8 = 2;
const RULE_EVM_SELECTOR_DENY: u8 = 3;
const RULE_ERC20_MAX_AMOUNT: u8 = 4;
const RULE_BTC_SCRIPT_TYPES: u8 = 5;
const RULE_BTC_MAX_FEE_RATE: u8 = 6;
const RULE_SOL_PROGRAM_ALLOW: u8 = 7;
const RULE_SOL_PROGRAM_DENY: u8 = 8;
const RULE_TIME_WINDOW: u8 = 9;
const RULE_PERIOD_LIMIT: u8 = 10;
const RULE_RATE_LIMIT: u8 = 11;

/// V4 denial codes
const DENIAL_NATIVE_VALUE_EXCEEDED: u64 = 30;
const DENIAL_TIME_WINDOW_BLOCKED: u64 = 31;
const DENIAL_PERIOD_LIMIT_EXCEEDED: u64 = 32;
const DENIAL_RATE_LIMIT_EXCEEDED: u64 = 33;

/// Period type constants (used in RULE_PERIOD_LIMIT params)
const PERIOD_DAILY: u8 = 0;
const PERIOD_WEEKLY: u8 = 1;
const PERIOD_MONTHLY: u8 = 2;
const PERIOD_ANNUAL: u8 = 3;

/// Milliseconds per period (approximate for month/year)
const MS_PER_DAY: u64 = 86_400_000;
const MS_PER_WEEK: u64 = 604_800_000;
const MS_PER_MONTH: u64 = 2_592_000_000;   // 30 days
const MS_PER_YEAR: u64 = 31_536_000_000;    // 365 days

/// Governance V2 error codes (for governed_reaffirm_v2)
const E_BINDING_GOVERNED_V2: u64 = 120;
const E_GOVERNANCE_V2_RECEIPT_MISMATCH: u64 = 121;
const E_BINDING_ALREADY_GOVERNED_V2: u64 = 122;
const E_BINDING_NOT_GOVERNED_V2: u64 = 123;

// ---- V4 structs ----

public struct GenericRule has copy, drop, store {
    rule_type: u8,
    namespace: u8,
    params: vector<u8>,
}

public struct PolicyV4 has key, store {
    id: UID,
    policy_id: vector<u8>,
    policy_version: vector<u8>,
    expires_at_ms: u64,
    allow_namespaces: vector<u8>,
    allow_chain_ids: vector<ChainIdV3>,
    allow_destinations: vector<vector<u8>>,
    deny_destinations: vector<vector<u8>>,
    rules: vector<GenericRule>,
}

public struct PolicyReceiptV4 has key, store {
    id: UID,
    policy_object_id: object::ID,
    policy_stable_id: vector<u8>,
    policy_version: vector<u8>,
    policy_version_id: object::ID,
    policy_root: vector<u8>,
    namespace: u8,
    chain_id: vector<u8>,
    intent_hash: vector<u8>,
    destination: vector<u8>,
    native_value: vector<u8>,
    context_data: vector<u8>,
    allowed: bool,
    denial_reason: u64,
    minted_at_ms: u64,
}

// ---- SpendingLedger (stateful rules, dynamic field on PolicyBinding) ----

public struct SpendingLedgerKey has copy, drop, store {}

public struct SpendingLedger has store {
    period_totals: vector<PeriodTotal>,
    rate_window_entries: vector<RateEntry>,
}

public struct PeriodTotal has copy, drop, store {
    period_type: u8,
    window_start_ms: u64,
    cumulative_value: vector<u8>,
}

public struct RateEntry has copy, drop, store {
    window_start_ms: u64,
    count: u64,
}

// ---- V4 Governance marker (in-package governance V2) ----

public struct GovernanceMarkerV2 has copy, drop, store {}

public struct GovernanceInfoV2 has store, drop, copy {
    governance_id: object::ID,
    mode: u8,
}

// ---- V4 canonical bytes ----

public struct PolicyV4CanonicalV1 has copy, drop, store {
    policy_id: vector<u8>,
    policy_version: vector<u8>,
    expires_at_ms: u64,
    allow_namespaces: vector<u8>,
    allow_destinations: vector<vector<u8>>,
    deny_destinations: vector<vector<u8>>,
    rules: vector<GenericRule>,
}

// ---- V4 constructor helpers ----

public fun create_generic_rule(rule_type: u8, namespace: u8, params: vector<u8>): GenericRule {
    GenericRule { rule_type, namespace, params }
}

public fun create_policy_v4(
    policy_id: vector<u8>,
    policy_version: vector<u8>,
    expires_at_ms: u64,
    allow_namespaces: vector<u8>,
    allow_chain_ids: vector<ChainIdV3>,
    allow_destinations: vector<vector<u8>>,
    deny_destinations: vector<vector<u8>>,
    rules: vector<GenericRule>,
    ctx: &mut TxContext,
): PolicyV4 {
    PolicyV4 {
        id: object::new(ctx),
        policy_id,
        policy_version,
        expires_at_ms,
        allow_namespaces,
        allow_chain_ids,
        allow_destinations,
        deny_destinations,
        rules,
    }
}

public fun create_and_share_policy_v4(
    policy_id: vector<u8>,
    policy_version: vector<u8>,
    expires_at_ms: u64,
    allow_namespaces: vector<u8>,
    allow_chain_ids: vector<ChainIdV3>,
    allow_destinations: vector<vector<u8>>,
    deny_destinations: vector<vector<u8>>,
    rules: vector<GenericRule>,
    ctx: &mut TxContext,
): object::ID {
    let policy = create_policy_v4(
        policy_id, policy_version, expires_at_ms, allow_namespaces,
        allow_chain_ids, allow_destinations, deny_destinations, rules, ctx,
    );
    let id = object::id(&policy);
    transfer::share_object(policy);
    id
}

public fun compute_policy_root_v4(policy: &PolicyV4): vector<u8> {
    let canon = PolicyV4CanonicalV1 {
        policy_id: copy_u8_vec(&policy.policy_id),
        policy_version: copy_u8_vec(&policy.policy_version),
        expires_at_ms: policy.expires_at_ms,
        allow_namespaces: copy_u8_vec(&policy.allow_namespaces),
        allow_destinations: copy_vec_vec_u8(&policy.allow_destinations),
        deny_destinations: copy_vec_vec_u8(&policy.deny_destinations),
        rules: copy_generic_rules(&policy.rules),
    };
    let b = bcs::to_bytes(&canon);
    let h = hash::keccak256(&b);
    assert!(vector::length(&h) == 32, E_BAD_ROOT_LEN);
    h
}

fun copy_generic_rules(v: &vector<GenericRule>): vector<GenericRule> {
    let mut out = vector::empty<GenericRule>();
    let mut i = 0;
    let n = vector::length(v);
    while (i < n) {
        let r = vector::borrow(v, i);
        vector::push_back(&mut out, GenericRule {
            rule_type: r.rule_type,
            namespace: r.namespace,
            params: copy_u8_vec(&r.params),
        });
        i = i + 1;
    };
    out
}

public fun register_policy_version_from_policy_v4(
    registry: &mut PolicyRegistry,
    clock: &Clock,
    policy: &PolicyV4,
    note: vector<u8>,
    ctx: &mut TxContext,
): object::ID {
    let stable_id = copy_u8_vec(&policy.policy_id);
    let version = copy_u8_vec(&policy.policy_version);
    let root = compute_policy_root_v4(policy);
    register_policy_version(registry, clock, stable_id, version, root, note, ctx)
}

// ============================================================================
// mint_receipt_v4 – generic rule evaluation
// ============================================================================

/// Mint a V4 receipt. Takes `&mut PolicyBinding` so stateful rules
/// (period limit, rate limit) can read/write the SpendingLedger.
public fun mint_receipt_v4(
    registry: &PolicyRegistry,
    policy: &PolicyV4,
    binding: &mut PolicyBinding,
    clock: &Clock,
    namespace: u8,
    chain_id: vector<u8>,
    intent_hash: vector<u8>,
    destination: vector<u8>,
    native_value: vector<u8>,
    context_data: vector<u8>,
    ctx: &mut TxContext,
): PolicyReceiptV4 {
    let now = clock.timestamp_ms();

    let mut latest_opt = get_latest_policy_version_id(registry, &policy.policy_id);
    if (!option::is_some(&latest_opt)) {
        return make_receipt_v4_denied(
            policy, object::id(policy), now, namespace, chain_id,
            intent_hash, destination, native_value, context_data,
            DENIAL_NO_POLICY_VERSION, ctx,
        )
    };
    let latest = option::extract(&mut latest_opt);

    // Expiry check
    if (policy.expires_at_ms != 0 && now > policy.expires_at_ms) {
        return make_receipt_v4_denied(
            policy, latest, now, namespace, chain_id,
            intent_hash, destination, native_value, context_data,
            DENIAL_EXPIRED, ctx,
        )
    };

    // Namespace check
    if (!is_namespace_allowed_v4(policy, namespace)) {
        return make_receipt_v4_denied(
            policy, latest, now, namespace, chain_id,
            intent_hash, destination, native_value, context_data,
            DENIAL_NAMESPACE_NOT_ALLOWED, ctx,
        )
    };

    // Destination denylist
    if (vector::length(&destination) > 0 && contains_addr(&policy.deny_destinations, &destination)) {
        return make_receipt_v4_denied(
            policy, latest, now, namespace, chain_id,
            intent_hash, destination, native_value, context_data,
            DENIAL_DENYLIST, ctx,
        )
    };

    // Destination allowlist
    let allow_len = vector::length(&policy.allow_destinations);
    if (allow_len > 0 && !contains_addr(&policy.allow_destinations, &destination)) {
        return make_receipt_v4_denied(
            policy, latest, now, namespace, chain_id,
            intent_hash, destination, native_value, context_data,
            DENIAL_NOT_IN_ALLOWLIST, ctx,
        )
    };

    // Evaluate generic rules
    let mut i = 0;
    let n = vector::length(&policy.rules);
    while (i < n) {
        let rule = vector::borrow(&policy.rules, i);
        // Skip rules scoped to a different namespace
        if (rule.namespace != 0 && rule.namespace != namespace) {
            i = i + 1;
            continue
        };

        let denial = evaluate_rule(rule, &native_value, &context_data, namespace, binding, now);
        if (denial != DENIAL_NONE) {
            return make_receipt_v4_denied(
                policy, latest, now, namespace, chain_id,
                intent_hash, destination, native_value, context_data,
                denial, ctx,
            )
        };
        i = i + 1;
    };

    // All checks passed — update stateful ledger entries
    commit_stateful_rules(policy, &native_value, namespace, binding, now);

    PolicyReceiptV4 {
        id: object::new(ctx),
        policy_object_id: object::id(policy),
        policy_stable_id: copy_u8_vec(&policy.policy_id),
        policy_version: copy_u8_vec(&policy.policy_version),
        policy_version_id: latest,
        policy_root: compute_policy_root_v4(policy),
        namespace,
        chain_id,
        intent_hash,
        destination,
        native_value,
        context_data,
        allowed: true,
        denial_reason: DENIAL_NONE,
        minted_at_ms: now,
    }
}

public fun mint_receipt_v4_to_sender(
    registry: &PolicyRegistry,
    policy: &PolicyV4,
    binding: &mut PolicyBinding,
    clock: &Clock,
    namespace: u8,
    chain_id: vector<u8>,
    intent_hash: vector<u8>,
    destination: vector<u8>,
    native_value: vector<u8>,
    context_data: vector<u8>,
    ctx: &mut TxContext,
): object::ID {
    let receipt = mint_receipt_v4(
        registry, policy, binding, clock, namespace, chain_id,
        intent_hash, destination, native_value, context_data, ctx,
    );
    let id = object::id(&receipt);
    transfer::transfer(receipt, tx_context::sender(ctx));
    id
}

// ---- V4 rule evaluation helpers ----

fun evaluate_rule(
    rule: &GenericRule,
    native_value: &vector<u8>,
    context_data: &vector<u8>,
    namespace: u8,
    binding: &PolicyBinding,
    now: u64,
): u64 {
    if (rule.rule_type == RULE_MAX_NATIVE_VALUE) {
        if (vector::length(native_value) == 32 && vector::length(&rule.params) >= 32) {
            let max_val = slice_bytes(&rule.params, 0, 32);
            if (!u256_be_lte(native_value, &max_val)) {
                return DENIAL_NATIVE_VALUE_EXCEEDED
            };
        };
    } else if (rule.rule_type == RULE_EVM_SELECTOR_ALLOW) {
        if (namespace == NAMESPACE_EVM && vector::length(context_data) >= 4) {
            let selector = slice_bytes(context_data, 0, 4);
            if (!contains_chunk(&rule.params, &selector, 4)) {
                return DENIAL_SELECTOR_NOT_ALLOWED
            };
        };
    } else if (rule.rule_type == RULE_EVM_SELECTOR_DENY) {
        if (namespace == NAMESPACE_EVM && vector::length(context_data) >= 4) {
            let selector = slice_bytes(context_data, 0, 4);
            if (contains_chunk(&rule.params, &selector, 4)) {
                return DENIAL_SELECTOR_DENYLIST
            };
        };
    } else if (rule.rule_type == RULE_ERC20_MAX_AMOUNT) {
        if (namespace == NAMESPACE_EVM && vector::length(&rule.params) >= 52 && vector::length(context_data) >= 36) {
            let rule_token = slice_bytes(&rule.params, 0, 20);
            let rule_max = slice_bytes(&rule.params, 20, 52);
            let ctx_token = slice_bytes(context_data, 4, 24);
            let ctx_amount = slice_bytes(context_data, 4, 36);
            if (u8_vec_equal(&rule_token, &ctx_token) && !u256_be_lte(&ctx_amount, &rule_max)) {
                return DENIAL_ERC20_AMOUNT_EXCEEDS_MAX
            };
        };
    } else if (rule.rule_type == RULE_BTC_SCRIPT_TYPES) {
        if (namespace == NAMESPACE_BITCOIN && vector::length(context_data) >= 1) {
            let script_type = *vector::borrow(context_data, 0);
            if (!contains_u8(&rule.params, script_type)) {
                return DENIAL_BTC_SCRIPT_TYPE_NOT_ALLOWED
            };
        };
    } else if (rule.rule_type == RULE_BTC_MAX_FEE_RATE) {
        if (namespace == NAMESPACE_BITCOIN && vector::length(context_data) >= 9 && vector::length(&rule.params) >= 8) {
            let fee_rate = read_u64_be(context_data, 1);
            let max_fee = read_u64_be(&rule.params, 0);
            if (max_fee > 0 && fee_rate > max_fee) {
                return DENIAL_BTC_FEE_RATE_EXCEEDED
            };
        };
    } else if (rule.rule_type == RULE_SOL_PROGRAM_ALLOW) {
        if (namespace == NAMESPACE_SOLANA && vector::length(context_data) >= 32) {
            let prog = slice_bytes(context_data, 0, 32);
            if (!contains_chunk(&rule.params, &prog, 32)) {
                return DENIAL_SOL_PROGRAM_NOT_ALLOWED
            };
        };
    } else if (rule.rule_type == RULE_SOL_PROGRAM_DENY) {
        if (namespace == NAMESPACE_SOLANA && vector::length(context_data) >= 32) {
            let prog = slice_bytes(context_data, 0, 32);
            if (contains_chunk(&rule.params, &prog, 32)) {
                return DENIAL_SOL_PROGRAM_DENYLISTED
            };
        };
    } else if (rule.rule_type == RULE_TIME_WINDOW) {
        if (vector::length(&rule.params) >= 3) {
            let start_hour = (*vector::borrow(&rule.params, 0) as u64);
            let end_hour = (*vector::borrow(&rule.params, 1) as u64);
            let day_mask = *vector::borrow(&rule.params, 2);
            let hour_of_day = (now / 3_600_000) % 24;
            let day_of_week = (now / MS_PER_DAY) % 7;
            let day_bit = 1u8 << (day_of_week as u8);
            if ((day_mask & day_bit) == 0) {
                return DENIAL_TIME_WINDOW_BLOCKED
            };
            if (start_hour <= end_hour) {
                if (hour_of_day < start_hour || hour_of_day >= end_hour) {
                    return DENIAL_TIME_WINDOW_BLOCKED
                };
            } else {
                if (hour_of_day < start_hour && hour_of_day >= end_hour) {
                    return DENIAL_TIME_WINDOW_BLOCKED
                };
            };
        };
    } else if (rule.rule_type == RULE_PERIOD_LIMIT) {
        if (vector::length(&rule.params) >= 33 && vector::length(native_value) == 32) {
            let period_type = *vector::borrow(&rule.params, 0);
            let max_cumulative = slice_bytes(&rule.params, 1, 33);
            let (current_total, _in_window) = read_period_total(binding, period_type, now);
            let sum = u256_be_add(&current_total, native_value);
            if (!u256_be_lte(&sum, &max_cumulative)) {
                return DENIAL_PERIOD_LIMIT_EXCEEDED
            };
        };
    } else if (rule.rule_type == RULE_RATE_LIMIT) {
        if (vector::length(&rule.params) >= 12) {
            let max_count = read_u32_be(&rule.params, 0);
            let window_ms = read_u64_be(&rule.params, 4);
            let current_count = read_rate_count(binding, window_ms, now);
            if (current_count >= (max_count as u64)) {
                return DENIAL_RATE_LIMIT_EXCEEDED
            };
        };
    };
    // Unknown rule types are skipped (forward-compatible)
    DENIAL_NONE
}

/// After all rules pass, update the SpendingLedger for stateful rules.
fun commit_stateful_rules(
    policy: &PolicyV4,
    native_value: &vector<u8>,
    namespace: u8,
    binding: &mut PolicyBinding,
    now: u64,
) {
    let mut i = 0;
    let n = vector::length(&policy.rules);
    while (i < n) {
        let rule = vector::borrow(&policy.rules, i);
        if (rule.namespace != 0 && rule.namespace != namespace) {
            i = i + 1;
            continue
        };
        if (rule.rule_type == RULE_PERIOD_LIMIT && vector::length(&rule.params) >= 33 && vector::length(native_value) == 32) {
            let period_type = *vector::borrow(&rule.params, 0);
            update_period_total(binding, period_type, native_value, now);
        } else if (rule.rule_type == RULE_RATE_LIMIT && vector::length(&rule.params) >= 12) {
            let window_ms = read_u64_be(&rule.params, 4);
            increment_rate_count(binding, window_ms, now);
        };
        i = i + 1;
    };
}

// ---- SpendingLedger helpers ----

fun ensure_ledger(binding: &mut PolicyBinding) {
    if (!dynamic_field::exists_(&binding.id, SpendingLedgerKey {})) {
        dynamic_field::add(
            &mut binding.id,
            SpendingLedgerKey {},
            SpendingLedger {
                period_totals: vector::empty<PeriodTotal>(),
                rate_window_entries: vector::empty<RateEntry>(),
            },
        );
    };
}

fun period_window_start(period_type: u8, now: u64): u64 {
    let period_ms = if (period_type == PERIOD_DAILY) { MS_PER_DAY }
        else if (period_type == PERIOD_WEEKLY) { MS_PER_WEEK }
        else if (period_type == PERIOD_MONTHLY) { MS_PER_MONTH }
        else { MS_PER_YEAR };
    (now / period_ms) * period_ms
}

fun read_period_total(binding: &PolicyBinding, period_type: u8, now: u64): (vector<u8>, bool) {
    let zero = zero_32();
    if (!dynamic_field::exists_(&binding.id, SpendingLedgerKey {})) {
        return (zero, false)
    };
    let ledger = dynamic_field::borrow<SpendingLedgerKey, SpendingLedger>(&binding.id, SpendingLedgerKey {});
    let window_start = period_window_start(period_type, now);
    let mut i = 0;
    let n = vector::length(&ledger.period_totals);
    while (i < n) {
        let pt = vector::borrow(&ledger.period_totals, i);
        if (pt.period_type == period_type) {
            if (pt.window_start_ms == window_start) {
                return (copy_u8_vec(&pt.cumulative_value), true)
            };
            return (zero, false)
        };
        i = i + 1;
    };
    (zero, false)
}

fun update_period_total(binding: &mut PolicyBinding, period_type: u8, value: &vector<u8>, now: u64) {
    ensure_ledger(binding);
    let window_start = period_window_start(period_type, now);
    let ledger = dynamic_field::borrow_mut<SpendingLedgerKey, SpendingLedger>(&mut binding.id, SpendingLedgerKey {});
    let mut i = 0;
    let n = vector::length(&ledger.period_totals);
    while (i < n) {
        let pt = vector::borrow_mut(&mut ledger.period_totals, i);
        if (pt.period_type == period_type) {
            if (pt.window_start_ms != window_start) {
                pt.window_start_ms = window_start;
                pt.cumulative_value = zero_32();
            };
            pt.cumulative_value = u256_be_add(&pt.cumulative_value, value);
            return
        };
        i = i + 1;
    };
    vector::push_back(&mut ledger.period_totals, PeriodTotal {
        period_type,
        window_start_ms: window_start,
        cumulative_value: copy_u8_vec(value),
    });
}

fun read_rate_count(binding: &PolicyBinding, window_ms: u64, now: u64): u64 {
    if (!dynamic_field::exists_(&binding.id, SpendingLedgerKey {})) {
        return 0
    };
    let ledger = dynamic_field::borrow<SpendingLedgerKey, SpendingLedger>(&binding.id, SpendingLedgerKey {});
    let window_start = if (window_ms > 0) { (now / window_ms) * window_ms } else { 0 };
    let mut i = 0;
    let n = vector::length(&ledger.rate_window_entries);
    while (i < n) {
        let re = vector::borrow(&ledger.rate_window_entries, i);
        if (re.window_start_ms == window_start) {
            return re.count
        };
        i = i + 1;
    };
    0
}

fun increment_rate_count(binding: &mut PolicyBinding, window_ms: u64, now: u64) {
    ensure_ledger(binding);
    let window_start = if (window_ms > 0) { (now / window_ms) * window_ms } else { 0 };
    let ledger = dynamic_field::borrow_mut<SpendingLedgerKey, SpendingLedger>(&mut binding.id, SpendingLedgerKey {});
    let mut i = 0;
    let n = vector::length(&ledger.rate_window_entries);
    while (i < n) {
        let re = vector::borrow_mut(&mut ledger.rate_window_entries, i);
        if (re.window_start_ms == window_start) {
            re.count = re.count + 1;
            return
        };
        i = i + 1;
    };
    vector::push_back(&mut ledger.rate_window_entries, RateEntry {
        window_start_ms: window_start,
        count: 1,
    });
}

// ---- V4 byte-manipulation helpers ----

fun zero_32(): vector<u8> {
    let mut v = vector::empty<u8>();
    let mut i = 0;
    while (i < 32) { vector::push_back(&mut v, 0u8); i = i + 1; };
    v
}

fun slice_bytes(v: &vector<u8>, start: u64, end: u64): vector<u8> {
    let mut out = vector::empty<u8>();
    let mut i = start;
    while (i < end && i < vector::length(v)) {
        vector::push_back(&mut out, *vector::borrow(v, i));
        i = i + 1;
    };
    out
}

fun contains_chunk(haystack: &vector<u8>, needle: &vector<u8>, chunk_size: u64): bool {
    let h_len = vector::length(haystack);
    let n_len = vector::length(needle);
    if (n_len != chunk_size || h_len < chunk_size) return false;
    let mut offset = 0;
    while (offset + chunk_size <= h_len) {
        let chunk = slice_bytes(haystack, offset, offset + chunk_size);
        if (u8_vec_equal(&chunk, needle)) return true;
        offset = offset + chunk_size;
    };
    false
}

fun contains_u8(v: &vector<u8>, val: u8): bool {
    let mut i = 0;
    let n = vector::length(v);
    while (i < n) {
        if (*vector::borrow(v, i) == val) return true;
        i = i + 1;
    };
    false
}

fun read_u64_be(v: &vector<u8>, offset: u64): u64 {
    let mut result: u64 = 0;
    let mut i = 0;
    while (i < 8) {
        result = (result << 8) | (*vector::borrow(v, offset + i) as u64);
        i = i + 1;
    };
    result
}

fun read_u32_be(v: &vector<u8>, offset: u64): u32 {
    let mut result: u32 = 0;
    let mut i = 0;
    while (i < 4) {
        result = (result << 8) | (*vector::borrow(v, offset + i) as u32);
        i = i + 1;
    };
    result
}

/// Big-endian 256-bit addition (no overflow check — wraps).
fun u256_be_add(a: &vector<u8>, b: &vector<u8>): vector<u8> {
    let mut result = vector::empty<u8>();
    let mut i = 0;
    while (i < 32) { vector::push_back(&mut result, 0u8); i = i + 1; };

    let mut carry: u64 = 0;
    let mut idx: u64 = 31;
    loop {
        let sum = (*vector::borrow(a, idx) as u64) + (*vector::borrow(b, idx) as u64) + carry;
        *vector::borrow_mut(&mut result, idx) = ((sum & 0xFF) as u8);
        carry = sum >> 8;
        if (idx == 0) break;
        idx = idx - 1;
    };
    result
}

fun is_namespace_allowed_v4(policy: &PolicyV4, namespace: u8): bool {
    let n = vector::length(&policy.allow_namespaces);
    if (n == 0) return true;
    let mut i = 0;
    while (i < n) {
        if (*vector::borrow(&policy.allow_namespaces, i) == namespace) return true;
        i = i + 1;
    };
    false
}

fun make_receipt_v4_denied(
    policy: &PolicyV4,
    version_id: object::ID,
    now: u64,
    namespace: u8,
    chain_id: vector<u8>,
    intent_hash: vector<u8>,
    destination: vector<u8>,
    native_value: vector<u8>,
    context_data: vector<u8>,
    denial_reason: u64,
    ctx: &mut TxContext,
): PolicyReceiptV4 {
    PolicyReceiptV4 {
        id: object::new(ctx),
        policy_object_id: object::id(policy),
        policy_stable_id: copy_u8_vec(&policy.policy_id),
        policy_version: copy_u8_vec(&policy.policy_version),
        policy_version_id: version_id,
        policy_root: compute_policy_root_v4(policy),
        namespace,
        chain_id,
        intent_hash,
        destination,
        native_value,
        context_data,
        allowed: false,
        denial_reason,
        minted_at_ms: now,
    }
}

// ---- V4 receipt consumption + accessors ----

public fun consume_receipt_v4(receipt: PolicyReceiptV4): object::ID {
    let receipt_id = object::id(&receipt);
    let PolicyReceiptV4 {
        id: receipt_uid,
        policy_object_id: _,
        policy_stable_id: _,
        policy_version: _,
        policy_version_id: _,
        policy_root: _,
        namespace: _,
        chain_id: _,
        intent_hash: _,
        destination: _,
        native_value: _,
        context_data: _,
        allowed: _,
        denial_reason: _,
        minted_at_ms: _,
    } = receipt;
    object::delete(receipt_uid);
    receipt_id
}

public fun receipt_v4_is_allowed(r: &PolicyReceiptV4): bool { r.allowed }
public fun receipt_v4_namespace(r: &PolicyReceiptV4): u8 { r.namespace }
public fun receipt_v4_chain_id_bytes(r: &PolicyReceiptV4): vector<u8> { copy_u8_vec(&r.chain_id) }
public fun receipt_v4_policy_object_id(r: &PolicyReceiptV4): object::ID { r.policy_object_id }
public fun receipt_v4_policy_stable_id_bytes(r: &PolicyReceiptV4): vector<u8> { copy_u8_vec(&r.policy_stable_id) }
public fun receipt_v4_policy_version_bytes(r: &PolicyReceiptV4): vector<u8> { copy_u8_vec(&r.policy_version) }
public fun receipt_v4_policy_version_id(r: &PolicyReceiptV4): object::ID { r.policy_version_id }
public fun receipt_v4_policy_root_bytes(r: &PolicyReceiptV4): vector<u8> { copy_u8_vec(&r.policy_root) }
public fun receipt_v4_intent_hash_bytes(r: &PolicyReceiptV4): vector<u8> { copy_u8_vec(&r.intent_hash) }
public fun receipt_v4_destination_bytes(r: &PolicyReceiptV4): vector<u8> { copy_u8_vec(&r.destination) }
public fun receipt_v4_native_value_bytes(r: &PolicyReceiptV4): vector<u8> { copy_u8_vec(&r.native_value) }
public fun receipt_v4_context_data_bytes(r: &PolicyReceiptV4): vector<u8> { copy_u8_vec(&r.context_data) }
public fun receipt_v4_denial_reason(r: &PolicyReceiptV4): u64 { r.denial_reason }
public fun receipt_v4_minted_at_ms(r: &PolicyReceiptV4): u64 { r.minted_at_ms }

// ============================================================================
// Governance V2 marker – dynamic field on PolicyBinding (in-package)
// ============================================================================

public fun set_binding_governance_v2(
    binding: &mut PolicyBinding,
    governance_id: object::ID,
    mode: u8,
) {
    assert!(
        !dynamic_field::exists_(&binding.id, GovernanceMarkerV2 {}),
        E_BINDING_ALREADY_GOVERNED_V2
    );
    dynamic_field::add(
        &mut binding.id,
        GovernanceMarkerV2 {},
        GovernanceInfoV2 { governance_id, mode },
    );
}

public fun activate_binding_governance_v2(
    binding: &mut PolicyBinding,
) {
    assert!(
        dynamic_field::exists_(&binding.id, GovernanceMarkerV2 {}),
        E_BINDING_NOT_GOVERNED_V2
    );
    let info = dynamic_field::borrow_mut<GovernanceMarkerV2, GovernanceInfoV2>(
        &mut binding.id, GovernanceMarkerV2 {}
    );
    info.mode = GOVERNANCE_MODE_RECEIPT_REQUIRED;
}

public fun remove_binding_governance_v2(
    binding: &mut PolicyBinding,
) {
    assert!(
        dynamic_field::exists_(&binding.id, GovernanceMarkerV2 {}),
        E_BINDING_NOT_GOVERNED_V2
    );
    let _info = dynamic_field::remove<GovernanceMarkerV2, GovernanceInfoV2>(
        &mut binding.id, GovernanceMarkerV2 {}
    );
}

public fun get_binding_governance_info_v2(binding: &PolicyBinding): option::Option<GovernanceInfoV2> {
    if (dynamic_field::exists_(&binding.id, GovernanceMarkerV2 {})) {
        let info = dynamic_field::borrow<GovernanceMarkerV2, GovernanceInfoV2>(
            &binding.id, GovernanceMarkerV2 {}
        );
        option::some(*info)
    } else {
        option::none<GovernanceInfoV2>()
    }
}

public fun governance_info_v2_id(info: &GovernanceInfoV2): object::ID { info.governance_id }
public fun governance_info_v2_mode(info: &GovernanceInfoV2): u8 { info.mode }

/// Reaffirm a governed binding using a GovernanceReceiptV2 from the in-package module.
public fun governed_reaffirm_policy_binding_v2(
    binding: &mut PolicyBinding,
    registry: &PolicyRegistry,
    clock: &Clock,
    receipt: GovernanceReceiptV2,
): object::ID {
    assert!(
        dynamic_field::exists_(&binding.id, GovernanceMarkerV2 {}),
        E_BINDING_NOT_GOVERNED_V2
    );
    let info = dynamic_field::borrow<GovernanceMarkerV2, GovernanceInfoV2>(
        &binding.id, GovernanceMarkerV2 {}
    );

    let expected_governance_id = info.governance_id;
    let (receipt_governance_id, receipt_binding_id, receipt_target_version_id, _receipt_proposal_id) =
        consume_governance_receipt_v2(receipt);

    assert!(receipt_governance_id == expected_governance_id, E_GOVERNANCE_V2_RECEIPT_MISMATCH);
    assert!(receipt_binding_id == object::id(binding), E_GOVERNANCE_V2_RECEIPT_MISMATCH);
    assert!(
        version_exists_in_registry(registry, &binding.stable_id, receipt_target_version_id),
        E_VERSION_NOT_IN_REGISTRY
    );

    binding.active_version_id = receipt_target_version_id;
    binding.updated_at_ms = clock.timestamp_ms();
    receipt_target_version_id
}

// ---- V4 exported rule-type constants ----

public fun rule_max_native_value(): u8 { RULE_MAX_NATIVE_VALUE }
public fun rule_evm_selector_allow(): u8 { RULE_EVM_SELECTOR_ALLOW }
public fun rule_evm_selector_deny(): u8 { RULE_EVM_SELECTOR_DENY }
public fun rule_erc20_max_amount(): u8 { RULE_ERC20_MAX_AMOUNT }
public fun rule_btc_script_types(): u8 { RULE_BTC_SCRIPT_TYPES }
public fun rule_btc_max_fee_rate(): u8 { RULE_BTC_MAX_FEE_RATE }
public fun rule_sol_program_allow(): u8 { RULE_SOL_PROGRAM_ALLOW }
public fun rule_sol_program_deny(): u8 { RULE_SOL_PROGRAM_DENY }
public fun rule_time_window(): u8 { RULE_TIME_WINDOW }
public fun rule_period_limit(): u8 { RULE_PERIOD_LIMIT }
public fun rule_rate_limit(): u8 { RULE_RATE_LIMIT }

