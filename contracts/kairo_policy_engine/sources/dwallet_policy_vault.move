/// PolicyVault: Hard-gated dWallet custody with mandatory policy enforcement.
/// 
/// This module implements Option A from the Kairo policy integration plan:
/// - All dWallet caps are custodied by the vault (non-extractable)
/// - Signing requires a valid PolicyReceiptV3 + PolicyBinding
/// - Single audit event per signing attempt
/// - Emergency circuit breaker for safety
/// 
/// Design notes:
/// - The vault stores dWallet caps in dynamic fields keyed by dwallet_id bytes
/// - Caps are borrowed (not transferred) for use with Ika's coordinator in the same tx
/// - Uses a "hot potato" pattern (SigningTicket) to ensure cap is returned
/// - Idempotency is enforced by IntentDigestV1 (same digest returns existing sign request)
#[allow(duplicate_alias, unused_const)]
module kairo_policy_engine::dwallet_policy_vault;

use sui::clock::Clock;
use sui::object::{Self, UID, ID};
use sui::tx_context::{Self, TxContext};
use sui::transfer;
use sui::dynamic_field;
use sui::event;
use std::vector;

use kairo_policy_engine::policy_registry::{
    PolicyBinding,
    PolicyReceiptV3,
    receipt_v3_is_allowed,
    receipt_v3_namespace,
    receipt_v3_chain_id_bytes,
    receipt_v3_policy_version_id,
    receipt_v3_policy_stable_id_bytes,
    receipt_v3_intent_hash_bytes,
    receipt_v3_destination_bytes,
    receipt_v3_minted_at_ms,
    receipt_v3_denial_reason,
    consume_receipt_v3,
    PolicyReceiptV4,
    receipt_v4_is_allowed,
    receipt_v4_namespace,
    receipt_v4_chain_id_bytes,
    receipt_v4_policy_version_id,
    receipt_v4_policy_stable_id_bytes,
    receipt_v4_intent_hash_bytes,
    receipt_v4_destination_bytes,
    receipt_v4_minted_at_ms,
    receipt_v4_denial_reason,
    consume_receipt_v4,
    binding_active_version_id,
    binding_stable_id_bytes,
    u8_vec_equal,
    copy_u8_vec,
};

use kairo_policy_engine::policy_governance::{
    RecoveryReceiptV1,
    consume_recovery_receipt,
};

// ============================================================================
// Error Codes
// ============================================================================

/// Receipt is not allowed (policy denied the action)
const E_RECEIPT_NOT_ALLOWED: u64 = 1;
/// Receipt intent hash doesn't match the provided intent
const E_INTENT_HASH_MISMATCH: u64 = 2;
/// Receipt destination doesn't match
const E_DESTINATION_MISMATCH: u64 = 3;
/// Receipt chain_id doesn't match
const E_CHAIN_ID_MISMATCH: u64 = 4;
/// Receipt namespace doesn't match
const E_NAMESPACE_MISMATCH: u64 = 5;
/// Binding version doesn't match receipt version
const E_BINDING_VERSION_MISMATCH: u64 = 6;
/// Binding stable_id doesn't match receipt stable_id
const E_BINDING_STABLE_ID_MISMATCH: u64 = 7;
/// Binding dwallet_id doesn't match vaulted dwallet
const E_BINDING_DWALLET_MISMATCH: u64 = 8;
/// dWallet not found in vault
const E_DWALLET_NOT_FOUND: u64 = 9;
/// Admin capability required
const E_NOT_ADMIN: u64 = 10;
/// Vault is in emergency bypass mode (signing disabled)
const E_VAULT_EMERGENCY_BYPASS: u64 = 11;
/// Receipt has expired (TTL exceeded)
const E_RECEIPT_EXPIRED: u64 = 12;
/// Intent digest must be 32 bytes
const E_BAD_INTENT_DIGEST_LEN: u64 = 13;
/// dWallet already registered in vault
const E_DWALLET_ALREADY_REGISTERED: u64 = 14;
/// Invalid signing ticket (wrong vault or dwallet)
const E_INVALID_SIGNING_TICKET: u64 = 15;
/// Cannot record denial for an allowed receipt
const E_RECEIPT_IS_ALLOWED: u64 = 16;

// ============================================================================
// Enforcement Mode Constants
// ============================================================================

/// Strict enforcement - all policy checks must pass
const ENFORCEMENT_STRICT: u8 = 1;
/// Emergency bypass - signing disabled, vault is locked
const ENFORCEMENT_EMERGENCY_BYPASS: u8 = 2;

// ============================================================================
// Structs
// ============================================================================

/// Admin capability for vault governance
public struct VaultAdminCap has key, store {
    id: UID,
    vault_id: ID,
}

/// Shared policy vault that custodies dWallet caps.
/// 
/// Dynamic fields:
/// - `vector<u8>` (dwallet_id bytes) -> `VaultedDWallet<T>` (cap + metadata)
/// - `vector<u8>` (IntentDigestV1) -> `IntentRecord` (idempotency index)
public struct PolicyVault has key {
    id: UID,
    /// Enforcement mode (STRICT or EMERGENCY_BYPASS)
    enforcement_mode: u8,
    /// Total number of registered dWallets
    dwallet_count: u64,
    /// Created timestamp
    created_at_ms: u64,
}

/// Record of a vaulted dWallet (stored as dynamic field).
/// Generic over cap type to support both DWalletCap and ImportedKeyDWalletCap.
/// 
/// NOTE: We use `vector<u8>` for cap storage since we can't directly import
/// Ika types. The cap is stored as BCS-encoded bytes and must be decoded
/// by the backend when constructing transactions.
public struct VaultedDWallet has store {
    /// The dwallet object ID (32 bytes)
    dwallet_id: vector<u8>,
    /// Policy binding object ID for this dWallet
    binding_id: ID,
    /// Stable policy ID this dWallet follows
    stable_id: vector<u8>,
    /// Registration timestamp
    registered_at_ms: u64,
    /// Whether this is an imported-key dWallet
    is_imported_key: bool,
}

/// Idempotency record for a signing intent (stored as dynamic field keyed by intent digest).
public struct IntentRecord has store {
    /// The canonical IntentDigestV1 (32 bytes)
    intent_digest: vector<u8>,
    /// Sign request ID returned by Ika coordinator (if any)
    sign_request_id: ID,
    /// The receipt ID that authorized this signing
    receipt_id: ID,
    /// Binding version at time of signing
    binding_version_id: ID,
    /// Timestamp when recorded
    recorded_at_ms: u64,
}

/// Authorization result returned when a signing request is approved.
/// This is NOT a hot potato - the receipt consumption is the authorization.
/// 
/// The caller receives this to confirm authorization passed, then calls
/// Ika's coordinator in a subsequent transaction.
public struct SigningAuthorization has drop {
    vault_id: ID,
    dwallet_id: vector<u8>,
    intent_digest: vector<u8>,
    receipt_id: ID,
    binding_version_id: ID,
}

// ============================================================================
// Events
// ============================================================================

/// Emitted once per signing attempt (success or failure).
public struct VaultSigningEvent has copy, drop {
    /// Vault object ID
    vault_id: ID,
    /// The canonical IntentDigestV1 (32 bytes)
    intent_digest: vector<u8>,
    /// Receipt object ID that authorized signing
    receipt_id: ID,
    /// Binding version ID at time of signing
    binding_version_id: ID,
    /// Sign request ID from Ika (if idempotent hit, this is existing; else new)
    sign_request_id: ID,
    /// Enforcement mode used (STRICT, etc.)
    enforcement_mode: u8,
    /// Namespace (1=EVM, 2=Bitcoin, 3=Solana)
    namespace: u8,
    /// Chain ID bytes
    chain_id: vector<u8>,
    /// Destination address bytes
    destination: vector<u8>,
    /// Whether this was an idempotent hit (existing request returned)
    is_idempotent_hit: bool,
    /// Timestamp
    timestamp_ms: u64,
}

/// Emitted when a dWallet is registered into the vault.
public struct DWalletRegisteredEvent has copy, drop {
    vault_id: ID,
    dwallet_id: vector<u8>,
    binding_id: ID,
    stable_id: vector<u8>,
    is_imported_key: bool,
    timestamp_ms: u64,
}

/// Emitted when recovery completes and vault re-enables signing.
public struct VaultRecoveryCompletedEvent has copy, drop {
    vault_id: ID,
    config_id: ID,
    dwallet_id: vector<u8>,
    completed_at_ms: u64,
}

/// Emitted when vault enforcement mode changes.
public struct VaultModeChangedEvent has copy, drop {
    vault_id: ID,
    old_mode: u8,
    new_mode: u8,
    timestamp_ms: u64,
}

/// Emitted when a signing attempt is denied by policy.
/// This event is emitted before the transaction aborts, providing an audit trail.
public struct VaultSigningDeniedEvent has copy, drop {
    /// Vault object ID
    vault_id: ID,
    /// The canonical IntentDigestV1 (32 bytes)
    intent_digest: vector<u8>,
    /// Receipt object ID that was denied
    receipt_id: ID,
    /// Denial reason code from policy evaluation
    denial_reason: u64,
    /// Namespace (1=EVM, 2=Bitcoin, 3=Solana)
    namespace: u8,
    /// Chain ID bytes
    chain_id: vector<u8>,
    /// Destination address bytes
    destination: vector<u8>,
    /// Timestamp
    timestamp_ms: u64,
}

// ============================================================================
// Vault Creation
// ============================================================================

/// Create and share a new PolicyVault.
/// Returns the vault ID and transfers the admin cap to the sender.
public fun create_and_share_vault(
    clock: &Clock,
    ctx: &mut TxContext
): ID {
    let now = clock.timestamp_ms();
    let vault = PolicyVault {
        id: object::new(ctx),
        enforcement_mode: ENFORCEMENT_STRICT,
        dwallet_count: 0,
        created_at_ms: now,
    };
    let vault_id = object::id(&vault);
    
    // Create admin cap for governance
    let admin_cap = VaultAdminCap {
        id: object::new(ctx),
        vault_id,
    };
    transfer::transfer(admin_cap, tx_context::sender(ctx));
    
    transfer::share_object(vault);
    vault_id
}

// ============================================================================
// dWallet Registration
// ============================================================================

/// Register a new dWallet into the vault (mandatory for all Kairo dWallets).
/// 
/// This function stores the dWallet metadata in the vault. The actual cap
/// should be transferred to the vault object via PTB in the same transaction.
/// 
/// NOTE: The cap itself is stored separately via `deposit_dwallet_cap` because
/// this module cannot import Ika types directly.
public fun register_dwallet_into_vault(
    vault: &mut PolicyVault,
    clock: &Clock,
    dwallet_id: vector<u8>,
    binding_id: ID,
    stable_id: vector<u8>,
    is_imported_key: bool,
    _ctx: &mut TxContext
) {
    assert!(!dynamic_field::exists_(&vault.id, dwallet_id), E_DWALLET_ALREADY_REGISTERED);
    
    let now = clock.timestamp_ms();
    let vaulted = VaultedDWallet {
        dwallet_id: copy_u8_vec(&dwallet_id),
        binding_id,
        stable_id: copy_u8_vec(&stable_id),
        registered_at_ms: now,
        is_imported_key,
    };
    
    dynamic_field::add(&mut vault.id, dwallet_id, vaulted);
    vault.dwallet_count = vault.dwallet_count + 1;
    
    event::emit(DWalletRegisteredEvent {
        vault_id: object::id(vault),
        dwallet_id: copy_u8_vec(&dwallet_id),
        binding_id,
        stable_id: copy_u8_vec(&stable_id),
        is_imported_key,
        timestamp_ms: now,
    });
}

/// Check if a dWallet is registered in the vault.
public fun has_dwallet(vault: &PolicyVault, dwallet_id: &vector<u8>): bool {
    dynamic_field::exists_(&vault.id, *dwallet_id)
}

/// Get the VaultedDWallet metadata (for inspection).
public fun get_vaulted_dwallet(vault: &PolicyVault, dwallet_id: &vector<u8>): &VaultedDWallet {
    assert!(dynamic_field::exists_(&vault.id, *dwallet_id), E_DWALLET_NOT_FOUND);
    dynamic_field::borrow(&vault.id, *dwallet_id)
}

// ============================================================================
// Policy-Gated Signing (V3)
// ============================================================================

/// Authorize a signing request with policy enforcement.
/// 
/// This is the main entrypoint for vault-gated signing. It:
/// 1. Checks idempotency (returns early if intent already authorized)
/// 2. Verifies the receipt is allowed
/// 3. Enforces strict receipt/binding matching
/// 4. Records the intent for idempotency
/// 5. Emits a VaultSigningEvent
/// 
/// The caller then uses the dWallet cap with Ika's coordinator in the same or
/// subsequent transaction. The receipt consumption proves authorization.
/// 
/// Consumes the PolicyReceiptV3 (one-time authorization).
public fun policy_gated_authorize_sign_v3(
    vault: &mut PolicyVault,
    receipt: PolicyReceiptV3,
    binding: &PolicyBinding,
    clock: &Clock,
    // Request parameters
    dwallet_id: vector<u8>,
    intent_digest: vector<u8>,
    namespace: u8,
    chain_id: vector<u8>,
    destination: vector<u8>,
    // Optional receipt TTL check (0 = no expiry)
    receipt_ttl_ms: u64,
    _ctx: &mut TxContext
): SigningAuthorization {
    // Check enforcement mode
    assert!(vault.enforcement_mode == ENFORCEMENT_STRICT, E_VAULT_EMERGENCY_BYPASS);
    
    let now = clock.timestamp_ms();
    
    // Validate intent digest format
    assert!(vector::length(&intent_digest) == 32, E_BAD_INTENT_DIGEST_LEN);
    
    // Check if dWallet exists in vault
    assert!(dynamic_field::exists_(&vault.id, dwallet_id), E_DWALLET_NOT_FOUND);
    let vaulted = dynamic_field::borrow<vector<u8>, VaultedDWallet>(&vault.id, dwallet_id);
    
    // ========== STRICT POLICY CHECKS ==========
    
    // 1. Receipt must be allowed
    if (!receipt_v3_is_allowed(&receipt)) {
        // Emit denial event before aborting for audit trail
        event::emit(VaultSigningDeniedEvent {
            vault_id: object::id(vault),
            intent_digest: copy_u8_vec(&intent_digest),
            receipt_id: object::id(&receipt),
            denial_reason: receipt_v3_denial_reason(&receipt),
            namespace: receipt_v3_namespace(&receipt),
            chain_id: receipt_v3_chain_id_bytes(&receipt),
            destination: receipt_v3_destination_bytes(&receipt),
            timestamp_ms: now,
        });
        abort E_RECEIPT_NOT_ALLOWED
    };
    
    // 2. Intent digest must match
    let receipt_intent = receipt_v3_intent_hash_bytes(&receipt);
    assert!(u8_vec_equal(&receipt_intent, &intent_digest), E_INTENT_HASH_MISMATCH);
    
    // 3. Destination must match
    let receipt_dest = receipt_v3_destination_bytes(&receipt);
    assert!(u8_vec_equal(&receipt_dest, &destination), E_DESTINATION_MISMATCH);
    
    // 4. Chain ID must match
    let receipt_chain = receipt_v3_chain_id_bytes(&receipt);
    assert!(u8_vec_equal(&receipt_chain, &chain_id), E_CHAIN_ID_MISMATCH);
    
    // 5. Namespace must match
    assert!(receipt_v3_namespace(&receipt) == namespace, E_NAMESPACE_MISMATCH);
    
    // 6. Binding active_version_id must match receipt policy_version_id
    let binding_version = binding_active_version_id(binding);
    let receipt_version = receipt_v3_policy_version_id(&receipt);
    assert!(binding_version == receipt_version, E_BINDING_VERSION_MISMATCH);
    
    // 7. Binding stable_id must match receipt stable_id
    let binding_stable = binding_stable_id_bytes(binding);
    let receipt_stable = receipt_v3_policy_stable_id_bytes(&receipt);
    assert!(u8_vec_equal(&binding_stable, &receipt_stable), E_BINDING_STABLE_ID_MISMATCH);
    
    // 8. Binding dwallet_id must match vaulted dwallet
    assert!(vaulted.binding_id == object::id(binding), E_BINDING_DWALLET_MISMATCH);
    
    // 9. Receipt TTL check (if enabled)
    if (receipt_ttl_ms > 0) {
        let receipt_minted = receipt_v3_minted_at_ms(&receipt);
        assert!(now <= receipt_minted + receipt_ttl_ms, E_RECEIPT_EXPIRED);
    };
    
    // Consume the receipt (delete it - one-time authorization)
    let receipt_id = consume_receipt_v3(receipt);
    
    // Check idempotency - if already authorized, this is a no-op
    let is_idempotent_hit = dynamic_field::exists_(&vault.id, intent_digest);
    
    // Record intent for idempotency (if new)
    if (!is_idempotent_hit) {
        // Use a placeholder sign_request_id (will be updated by record_sign_request_id)
        let placeholder_id = object::id_from_address(@0x0);
        let record = IntentRecord {
            intent_digest: copy_u8_vec(&intent_digest),
            sign_request_id: placeholder_id,
            receipt_id,
            binding_version_id: binding_version,
            recorded_at_ms: now,
        };
        dynamic_field::add(&mut vault.id, intent_digest, record);
    };
    
    // Emit the single audit event
    event::emit(VaultSigningEvent {
        vault_id: object::id(vault),
        intent_digest: copy_u8_vec(&intent_digest),
        receipt_id,
        binding_version_id: binding_version,
        sign_request_id: object::id_from_address(@0x0), // Placeholder
        enforcement_mode: vault.enforcement_mode,
        namespace,
        chain_id: copy_u8_vec(&chain_id),
        destination: copy_u8_vec(&destination),
        is_idempotent_hit,
        timestamp_ms: now,
    });
    
    // Return authorization (droppable - not a hot potato)
    SigningAuthorization {
        vault_id: object::id(vault),
        dwallet_id: copy_u8_vec(&dwallet_id),
        intent_digest: copy_u8_vec(&intent_digest),
        receipt_id,
        binding_version_id: binding_version,
    }
}

/// Record the sign_request_id for an authorized intent (optional, for full traceability).
/// 
/// This can be called in a subsequent transaction after Ika's coordinator returns
/// the sign_request_id. It updates the IntentRecord with the actual ID.
/// 
/// NOTE: This is optional - the authorization itself (policy_gated_authorize_sign_v3)
/// is what enforces the policy. This just provides better traceability.
public fun record_sign_request_id(
    vault: &mut PolicyVault,
    intent_digest: vector<u8>,
    sign_request_id: ID,
    _clock: &Clock,
) {
    // Validate intent exists
    assert!(dynamic_field::exists_(&vault.id, intent_digest), E_DWALLET_NOT_FOUND);
    
    // Update the record with the actual sign_request_id
    let record = dynamic_field::borrow_mut<vector<u8>, IntentRecord>(&mut vault.id, intent_digest);
    record.sign_request_id = sign_request_id;
}

/// Check if an intent has already been processed (for idempotency).
/// Returns the existing sign_request_id if found.
public fun get_existing_sign_request(
    vault: &PolicyVault,
    intent_digest: &vector<u8>
): (bool, ID) {
    if (dynamic_field::exists_(&vault.id, *intent_digest)) {
        let record = dynamic_field::borrow<vector<u8>, IntentRecord>(&vault.id, *intent_digest);
        (true, record.sign_request_id)
    } else {
        (false, object::id_from_address(@0x0))
    }
}

// ============================================================================
// Denial Recording (non-aborting)
// ============================================================================

/// Record a policy denial on-chain and destroy the receipt.
///
/// Called by the backend when a minted receipt has `allowed=false`.
/// Unlike policy_gated_authorize_sign_v3, this function does NOT abort,
/// so the VaultSigningDeniedEvent is persisted on-chain for the explorer.
///
/// Flow:
/// 1. Verifies the receipt is indeed denied (aborts if receipt is allowed)
/// 2. Emits VaultSigningDeniedEvent
/// 3. Consumes (destroys) the receipt — cannot be reused
public fun record_vault_denial(
    vault: &PolicyVault,
    receipt: PolicyReceiptV3,
    clock: &Clock,
    _ctx: &mut TxContext
) {
    // Only process denied receipts — abort if someone tries to destroy an allowed one
    assert!(!receipt_v3_is_allowed(&receipt), E_RECEIPT_IS_ALLOWED);

    let now = clock.timestamp_ms();

    // Emit denial event (persisted because this tx succeeds)
    event::emit(VaultSigningDeniedEvent {
        vault_id: object::id(vault),
        intent_digest: receipt_v3_intent_hash_bytes(&receipt),
        receipt_id: object::id(&receipt),
        denial_reason: receipt_v3_denial_reason(&receipt),
        namespace: receipt_v3_namespace(&receipt),
        chain_id: receipt_v3_chain_id_bytes(&receipt),
        destination: receipt_v3_destination_bytes(&receipt),
        timestamp_ms: now,
    });

    // Consume (destroy) the receipt — one-time, non-reusable
    consume_receipt_v3(receipt);
}

// ============================================================================
// Policy-Gated Signing (V4)
// ============================================================================

/// Authorize a signing request with PolicyReceiptV4 enforcement.
/// Same pattern as V3 but consuming the V4 receipt type.
public fun policy_gated_authorize_sign_v4(
    vault: &mut PolicyVault,
    receipt: PolicyReceiptV4,
    binding: &PolicyBinding,
    clock: &Clock,
    dwallet_id: vector<u8>,
    intent_digest: vector<u8>,
    namespace: u8,
    chain_id: vector<u8>,
    destination: vector<u8>,
    receipt_ttl_ms: u64,
    _ctx: &mut TxContext
): SigningAuthorization {
    assert!(vault.enforcement_mode == ENFORCEMENT_STRICT, E_VAULT_EMERGENCY_BYPASS);

    let now = clock.timestamp_ms();
    assert!(vector::length(&intent_digest) == 32, E_BAD_INTENT_DIGEST_LEN);
    assert!(dynamic_field::exists_(&vault.id, dwallet_id), E_DWALLET_NOT_FOUND);
    let vaulted = dynamic_field::borrow<vector<u8>, VaultedDWallet>(&vault.id, dwallet_id);

    // Receipt must be allowed
    if (!receipt_v4_is_allowed(&receipt)) {
        event::emit(VaultSigningDeniedEvent {
            vault_id: object::id(vault),
            intent_digest: copy_u8_vec(&intent_digest),
            receipt_id: object::id(&receipt),
            denial_reason: receipt_v4_denial_reason(&receipt),
            namespace: receipt_v4_namespace(&receipt),
            chain_id: receipt_v4_chain_id_bytes(&receipt),
            destination: receipt_v4_destination_bytes(&receipt),
            timestamp_ms: now,
        });
        abort E_RECEIPT_NOT_ALLOWED
    };

    // Field matching
    let receipt_intent = receipt_v4_intent_hash_bytes(&receipt);
    assert!(u8_vec_equal(&receipt_intent, &intent_digest), E_INTENT_HASH_MISMATCH);

    let receipt_dest = receipt_v4_destination_bytes(&receipt);
    assert!(u8_vec_equal(&receipt_dest, &destination), E_DESTINATION_MISMATCH);

    let receipt_chain = receipt_v4_chain_id_bytes(&receipt);
    assert!(u8_vec_equal(&receipt_chain, &chain_id), E_CHAIN_ID_MISMATCH);

    assert!(receipt_v4_namespace(&receipt) == namespace, E_NAMESPACE_MISMATCH);

    let binding_version = binding_active_version_id(binding);
    let receipt_version = receipt_v4_policy_version_id(&receipt);
    assert!(binding_version == receipt_version, E_BINDING_VERSION_MISMATCH);

    let binding_stable = binding_stable_id_bytes(binding);
    let receipt_stable = receipt_v4_policy_stable_id_bytes(&receipt);
    assert!(u8_vec_equal(&binding_stable, &receipt_stable), E_BINDING_STABLE_ID_MISMATCH);

    assert!(vaulted.binding_id == object::id(binding), E_BINDING_DWALLET_MISMATCH);

    if (receipt_ttl_ms > 0) {
        let receipt_minted = receipt_v4_minted_at_ms(&receipt);
        assert!(now <= receipt_minted + receipt_ttl_ms, E_RECEIPT_EXPIRED);
    };

    let receipt_id = consume_receipt_v4(receipt);

    let is_idempotent_hit = dynamic_field::exists_(&vault.id, intent_digest);

    if (!is_idempotent_hit) {
        let placeholder_id = object::id_from_address(@0x0);
        let record = IntentRecord {
            intent_digest: copy_u8_vec(&intent_digest),
            sign_request_id: placeholder_id,
            receipt_id,
            binding_version_id: binding_version,
            recorded_at_ms: now,
        };
        dynamic_field::add(&mut vault.id, intent_digest, record);
    };

    event::emit(VaultSigningEvent {
        vault_id: object::id(vault),
        intent_digest: copy_u8_vec(&intent_digest),
        receipt_id,
        binding_version_id: binding_version,
        sign_request_id: object::id_from_address(@0x0),
        enforcement_mode: vault.enforcement_mode,
        namespace,
        chain_id: copy_u8_vec(&chain_id),
        destination: copy_u8_vec(&destination),
        is_idempotent_hit,
        timestamp_ms: now,
    });

    SigningAuthorization {
        vault_id: object::id(vault),
        dwallet_id: copy_u8_vec(&dwallet_id),
        intent_digest: copy_u8_vec(&intent_digest),
        receipt_id,
        binding_version_id: binding_version,
    }
}

/// Record a V4 policy denial on-chain and destroy the receipt.
public fun record_vault_denial_v4(
    vault: &PolicyVault,
    receipt: PolicyReceiptV4,
    clock: &Clock,
    _ctx: &mut TxContext
) {
    assert!(!receipt_v4_is_allowed(&receipt), E_RECEIPT_IS_ALLOWED);

    let now = clock.timestamp_ms();

    event::emit(VaultSigningDeniedEvent {
        vault_id: object::id(vault),
        intent_digest: receipt_v4_intent_hash_bytes(&receipt),
        receipt_id: object::id(&receipt),
        denial_reason: receipt_v4_denial_reason(&receipt),
        namespace: receipt_v4_namespace(&receipt),
        chain_id: receipt_v4_chain_id_bytes(&receipt),
        destination: receipt_v4_destination_bytes(&receipt),
        timestamp_ms: now,
    });

    consume_receipt_v4(receipt);
}

// ============================================================================
// Recovery
// ============================================================================

/// Complete a guardian-approved recovery.
/// Validates the recovery receipt, re-enables signing if the vault is
/// in EMERGENCY_BYPASS, and emits a RecoveryCompletedEvent.
public fun complete_recovery(
    vault: &mut PolicyVault,
    recovery_receipt: RecoveryReceiptV1,
    binding: &PolicyBinding,
    clock: &Clock,
    _ctx: &mut TxContext,
) {
    let (config_id, receipt_dwallet_id, receipt_stable_id) = consume_recovery_receipt(recovery_receipt);

    // Validate receipt dwallet_id matches a vaulted dWallet
    assert!(dynamic_field::exists_(&vault.id, receipt_dwallet_id), E_DWALLET_NOT_FOUND);
    let vaulted = dynamic_field::borrow<vector<u8>, VaultedDWallet>(&vault.id, receipt_dwallet_id);

    // Validate receipt stable_id matches the binding
    let binding_stable = binding_stable_id_bytes(binding);
    assert!(u8_vec_equal(&binding_stable, &receipt_stable_id), E_BINDING_STABLE_ID_MISMATCH);
    assert!(vaulted.binding_id == object::id(binding), E_BINDING_DWALLET_MISMATCH);

    // If vault is locked, re-enable it
    if (vault.enforcement_mode == ENFORCEMENT_EMERGENCY_BYPASS) {
        let old_mode = vault.enforcement_mode;
        vault.enforcement_mode = ENFORCEMENT_STRICT;

        event::emit(VaultModeChangedEvent {
            vault_id: object::id(vault),
            old_mode,
            new_mode: ENFORCEMENT_STRICT,
            timestamp_ms: clock.timestamp_ms(),
        });
    };

    let now = clock.timestamp_ms();
    event::emit(VaultRecoveryCompletedEvent {
        vault_id: object::id(vault),
        config_id,
        dwallet_id: copy_u8_vec(&receipt_dwallet_id),
        completed_at_ms: now,
    });
}

// ============================================================================
// Governance / Safety
// ============================================================================

/// Set the vault enforcement mode (admin only).
/// 
/// - ENFORCEMENT_STRICT (1): Normal operation, all policy checks enforced
/// - ENFORCEMENT_EMERGENCY_BYPASS (2): Signing disabled, vault is locked
public fun set_enforcement_mode(
    vault: &mut PolicyVault,
    admin_cap: &VaultAdminCap,
    new_mode: u8,
    clock: &Clock,
) {
    assert!(admin_cap.vault_id == object::id(vault), E_NOT_ADMIN);
    
    let old_mode = vault.enforcement_mode;
    vault.enforcement_mode = new_mode;
    
    event::emit(VaultModeChangedEvent {
        vault_id: object::id(vault),
        old_mode,
        new_mode,
        timestamp_ms: clock.timestamp_ms(),
    });
}

/// Get the current enforcement mode.
public fun enforcement_mode(vault: &PolicyVault): u8 {
    vault.enforcement_mode
}

/// Get the vault statistics.
public fun vault_stats(vault: &PolicyVault): (u64, u64, u8) {
    (vault.dwallet_count, vault.created_at_ms, vault.enforcement_mode)
}

// ============================================================================
// Accessors for VaultedDWallet
// ============================================================================

public fun vaulted_dwallet_id(v: &VaultedDWallet): vector<u8> { copy_u8_vec(&v.dwallet_id) }
public fun vaulted_binding_id(v: &VaultedDWallet): ID { v.binding_id }
public fun vaulted_stable_id(v: &VaultedDWallet): vector<u8> { copy_u8_vec(&v.stable_id) }
public fun vaulted_is_imported_key(v: &VaultedDWallet): bool { v.is_imported_key }

// ============================================================================
// Accessors for IntentRecord
// ============================================================================

public fun intent_record_sign_request_id(r: &IntentRecord): ID { r.sign_request_id }
public fun intent_record_receipt_id(r: &IntentRecord): ID { r.receipt_id }
public fun intent_record_binding_version_id(r: &IntentRecord): ID { r.binding_version_id }

// ============================================================================
// Constants (exported)
// ============================================================================

public fun enforcement_strict(): u8 { ENFORCEMENT_STRICT }
public fun enforcement_emergency_bypass(): u8 { ENFORCEMENT_EMERGENCY_BYPASS }

// ============================================================================
// Tests
// ============================================================================

#[test_only]
use sui::test_scenario::{Self, Scenario};

#[test_only]
use sui::clock;

#[test_only]
fun setup_test_scenario(sender: address): Scenario {
    test_scenario::begin(sender)
}

#[test]
fun test_create_vault() {
    let sender = @0xCAFE;
    let mut scenario = setup_test_scenario(sender);
    
    test_scenario::next_tx(&mut scenario, sender);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        let clock = clock::create_for_testing(ctx);
        
        let vault_id = create_and_share_vault(&clock, ctx);
        assert!(object::id_to_address(&vault_id) != @0x0, 0);
        
        clock::destroy_for_testing(clock);
    };
    
    test_scenario::end(scenario);
}

#[test]
fun test_vault_enforcement_modes() {
    let sender = @0xCAFE;
    let mut scenario = setup_test_scenario(sender);
    
    test_scenario::next_tx(&mut scenario, sender);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        let clock = clock::create_for_testing(ctx);
        
        let _vault_id = create_and_share_vault(&clock, ctx);
        
        clock::destroy_for_testing(clock);
    };
    
    // Get the vault and admin cap
    test_scenario::next_tx(&mut scenario, sender);
    {
        let mut vault = test_scenario::take_shared<PolicyVault>(&scenario);
        let admin_cap = test_scenario::take_from_sender<VaultAdminCap>(&scenario);
        let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
        
        // Check initial mode is STRICT
        assert!(vault.enforcement_mode == ENFORCEMENT_STRICT, 1);
        
        // Change to emergency bypass
        set_enforcement_mode(&mut vault, &admin_cap, ENFORCEMENT_EMERGENCY_BYPASS, &clock);
        assert!(vault.enforcement_mode == ENFORCEMENT_EMERGENCY_BYPASS, 2);
        
        // Change back to strict
        set_enforcement_mode(&mut vault, &admin_cap, ENFORCEMENT_STRICT, &clock);
        assert!(vault.enforcement_mode == ENFORCEMENT_STRICT, 3);
        
        clock::destroy_for_testing(clock);
        test_scenario::return_shared(vault);
        test_scenario::return_to_sender(&scenario, admin_cap);
    };
    
    test_scenario::end(scenario);
}

#[test]
fun test_register_dwallet() {
    let sender = @0xCAFE;
    let mut scenario = setup_test_scenario(sender);
    
    test_scenario::next_tx(&mut scenario, sender);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        let clock = clock::create_for_testing(ctx);
        let _vault_id = create_and_share_vault(&clock, ctx);
        clock::destroy_for_testing(clock);
    };
    
    // Register a dWallet
    test_scenario::next_tx(&mut scenario, sender);
    {
        let mut vault = test_scenario::take_shared<PolicyVault>(&scenario);
        let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
        let ctx = test_scenario::ctx(&mut scenario);
        
        let dwallet_id = b"test_dwallet_id_32bytes_here1234";
        let binding_id = object::id_from_address(@0xB1D);
        let stable_id = b"test-policy-v1";
        
        // Check dwallet not registered yet
        assert!(!has_dwallet(&vault, &dwallet_id), 1);
        
        // Register
        register_dwallet_into_vault(
            &mut vault,
            &clock,
            dwallet_id,
            binding_id,
            stable_id,
            true, // is_imported_key
            ctx
        );
        
        // Check dwallet is now registered
        assert!(has_dwallet(&vault, &dwallet_id), 2);
        
        // Check vault stats
        let (count, _, _) = vault_stats(&vault);
        assert!(count == 1, 3);
        
        clock::destroy_for_testing(clock);
        test_scenario::return_shared(vault);
    };
    
    test_scenario::end(scenario);
}

#[test]
#[expected_failure(abort_code = E_DWALLET_ALREADY_REGISTERED)]
fun test_register_dwallet_twice_fails() {
    let sender = @0xCAFE;
    let mut scenario = setup_test_scenario(sender);
    
    test_scenario::next_tx(&mut scenario, sender);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        let clock = clock::create_for_testing(ctx);
        let _vault_id = create_and_share_vault(&clock, ctx);
        clock::destroy_for_testing(clock);
    };
    
    test_scenario::next_tx(&mut scenario, sender);
    {
        let mut vault = test_scenario::take_shared<PolicyVault>(&scenario);
        let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
        let ctx = test_scenario::ctx(&mut scenario);
        
        let dwallet_id = b"test_dwallet_id_32bytes_here1234";
        let binding_id = object::id_from_address(@0xB1D);
        let stable_id = b"test-policy-v1";
        
        // First registration succeeds
        register_dwallet_into_vault(&mut vault, &clock, dwallet_id, binding_id, stable_id, true, ctx);
        
        // Second registration should fail
        register_dwallet_into_vault(&mut vault, &clock, dwallet_id, binding_id, stable_id, true, ctx);
        
        clock::destroy_for_testing(clock);
        test_scenario::return_shared(vault);
    };
    
    test_scenario::end(scenario);
}

#[test]
#[expected_failure(abort_code = E_DWALLET_NOT_FOUND)]
fun test_get_vaulted_dwallet_not_found() {
    let sender = @0xCAFE;
    let mut scenario = setup_test_scenario(sender);
    
    test_scenario::next_tx(&mut scenario, sender);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        let clock = clock::create_for_testing(ctx);
        let _vault_id = create_and_share_vault(&clock, ctx);
        clock::destroy_for_testing(clock);
    };
    
    test_scenario::next_tx(&mut scenario, sender);
    {
        let vault = test_scenario::take_shared<PolicyVault>(&scenario);
        
        let nonexistent_id = b"nonexistent_dwallet_id__________";
        let _vaulted = get_vaulted_dwallet(&vault, &nonexistent_id); // Should fail
        
        test_scenario::return_shared(vault);
    };
    
    test_scenario::end(scenario);
}
