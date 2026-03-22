#[allow(duplicate_alias, unused_const, unused_field)]
module kairo_policy_engine::custody_ledger;

use sui::clock::Clock;
use sui::hash;
use sui::object::{Self, UID};
use sui::tx_context::TxContext;
use sui::transfer;
use std::bcs;
use std::vector;

use kairo_policy_engine::policy_registry::{
    PolicyReceipt,
    PolicyReceiptV2,
    PolicyReceiptV3,
    PolicyReceiptV4,
    receipt_intent_hash_bytes,
    receipt_is_allowed,
    receipt_policy_object_id,
    receipt_policy_version_bytes,
    receipt_v2_intent_hash_bytes,
    receipt_v2_policy_object_id,
    receipt_v2_policy_version_bytes,
    receipt_v3_intent_hash_bytes,
    receipt_v3_policy_object_id,
    receipt_v3_policy_version_bytes,
    receipt_v4_intent_hash_bytes,
    receipt_v4_policy_object_id,
    receipt_v4_policy_version_bytes,
    u8_vec_equal,
    copy_u8_vec,
};

/// Asset-centric chain-of-custody ledger (v0 + v2 hashing).
///
/// Design goals:
/// - One shared `CustodyChain` per asset identity.
/// - Append-only, hash-linked `CustodyEvent` objects.
/// - Every Kairo-governed event is bound to a `PolicyReceipt` (hard gate artifact).
///
/// Notes:
/// - v0 accepts `event_hash` as input (off-chain computed).
/// - v2 computes `event_hash` on-chain using keccak256 over a canonical BCS encoding.

/// Asset namespace (v0)
const NAMESPACE_EVM: u8 = 1;
const NAMESPACE_BITCOIN: u8 = 2;
const NAMESPACE_SOLANA: u8 = 3;

/// Asset kind (v0)
const KIND_EVM_ERC20_LOT: u8 = 1;
const KIND_EVM_ERC721: u8 = 2;
const KIND_EVM_ERC1155: u8 = 3;
const KIND_BTC_UTXO: u8 = 4;

/// Event kind (v0)
const EVENT_MINT: u8 = 1;
const EVENT_TRANSFER: u8 = 2;
const EVENT_BURN: u8 = 3;
const EVENT_LOCK: u8 = 4;
const EVENT_UNLOCK: u8 = 5;
const EVENT_POLICY_CHECKPOINT: u8 = 6;

/// Format errors
const E_BAD_HASH_LEN: u64 = 1;
const E_BAD_INTENT_LEN: u64 = 2;
const E_BAD_TO_LEN: u64 = 3;
const E_BAD_TXHASH_LEN: u64 = 4;
const E_PREV_HASH_MISMATCH: u64 = 6;
const E_RECEIPT_NOT_ALLOWED: u64 = 7;
const E_RECEIPT_INTENT_MISMATCH: u64 = 8;

/// Event hash computation errors (v2)
const E_HASH_MISMATCH: u64 = 9;

/// Canonical asset identity. `id` is opaque bytes interpreted by the chosen `namespace+kind`.
public struct AssetId has copy, drop, store {
    namespace: u8,
    chain_id: u64,
    kind: u8,
    id: vector<u8>,
}

/// Shared per-asset chain head.
public struct CustodyChain has key, store {
    id: UID,
    asset: AssetId,
    /// Hash of the latest event in the chain (32 bytes). Empty chain uses 32 bytes of 0.
    head_hash: vector<u8>,
    /// Number of events appended.
    length: u64,
}

/// Immutable event object. Events are append-only and hash-linked via `prev_hash`.
public struct CustodyEvent has key, store {
    id: UID,
    /// The `CustodyChain` this event belongs to.
    chain_id: object::ID,
    /// Event sequence number within the chain (0-based).
    seq: u64,
    /// Event kind.
    kind: u8,
    /// Timestamp (ms) recorded on Sui.
    recorded_at_ms: u64,
    /// Hash link (32 bytes).
    prev_hash: vector<u8>,
    /// This event hash (32 bytes), computed over a canonical encoding of the event fields.
    event_hash: vector<u8>,
    /// Chain where the action occurred (namespace + chain_id).
    src_namespace: u8,
    src_chain_id: u64,
    /// Optional transaction hash on the source chain (recommended 32 bytes).
    src_tx_hash: vector<u8>,
    /// Optional "to" destination for account-based chains (e.g., EVM address = 20 bytes).
    to_addr: vector<u8>,
    /// Policy binding: receipt that authorized this event (hard gate).
    policy_object_id: object::ID,
    policy_version: vector<u8>,
    intent_hash: vector<u8>,
    receipt_object_id: object::ID,
    /// Free-form bytes for app-specific data.
    payload: vector<u8>,
}

/// Canonical event encoding for hash computation (v2).
public struct EventV2Canonical has copy, drop, store {
    chain_id: object::ID,
    seq: u64,
    kind: u8,
    recorded_at_ms: u64,
    prev_hash: vector<u8>,
    src_namespace: u8,
    src_chain_id: u64,
    src_tx_hash: vector<u8>,
    to_addr: vector<u8>,
    policy_object_id: object::ID,
    policy_version: vector<u8>,
    intent_hash: vector<u8>,
    receipt_object_id: object::ID,
    payload: vector<u8>,
}

/// Create a new shared custody chain for an asset.
/// `head_hash` initializes to 32 zero bytes.
public fun create_and_share_chain(asset: AssetId, ctx: &mut TxContext): object::ID {
    let mut head = vector::empty<u8>();
    let mut i = 0;
    while (i < 32) {
        vector::push_back(&mut head, 0);
        i = i + 1;
    };

    let chain = CustodyChain { id: object::new(ctx), asset, head_hash: head, length: 0 };
    let id = object::id(&chain);
    transfer::share_object(chain);
    id
}

/// Convenience: create+share a chain without having to BCS-encode `AssetId` from the caller.
public fun create_and_share_chain_from_parts(
    namespace: u8,
    chain_id: u64,
    kind: u8,
    id: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    create_and_share_chain(AssetId { namespace, chain_id, kind, id }, ctx)
}

/// Append a custody event to a chain using a `PolicyReceipt` as the authorization proof (v0).
///
/// - `intent_hash` MUST equal `receipt.intent_hash`.
/// - `receipt.allowed` MUST be true.
/// - `prev_hash` MUST match the chain head.
/// - `event_hash` MUST be 32 bytes.
///
/// Returns the new event object id.
public fun append_event_with_receipt(
    chain: &mut CustodyChain,
    receipt: &PolicyReceipt,
    clock: &Clock,
    kind: u8,
    src_namespace: u8,
    src_chain_id: u64,
    src_tx_hash: vector<u8>,
    to_addr: vector<u8>,
    intent_hash: vector<u8>,
    prev_hash: vector<u8>,
    event_hash: vector<u8>,
    payload: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    assert!(vector::length(&event_hash) == 32, E_BAD_HASH_LEN);
    assert!(vector::length(&prev_hash) == 32, E_BAD_HASH_LEN);
    assert!(vector::length(&intent_hash) == 32, E_BAD_INTENT_LEN);

    if (vector::length(&to_addr) != 0) {
        assert!(vector::length(&to_addr) == 20, E_BAD_TO_LEN);
    };
    if (vector::length(&src_tx_hash) != 0) {
        assert!(vector::length(&src_tx_hash) == 32, E_BAD_TXHASH_LEN);
    };

    assert!(receipt_is_allowed(receipt), E_RECEIPT_NOT_ALLOWED);
    assert!(
        u8_vec_equal(&receipt_intent_hash_bytes(receipt), &intent_hash),
        E_RECEIPT_INTENT_MISMATCH
    );

    // Enforce hash chain linkage.
    assert!(u8_vec_equal(&chain.head_hash, &prev_hash), E_PREV_HASH_MISMATCH);

    let now = clock.timestamp_ms();
    let seq = chain.length;
    let event = CustodyEvent {
        id: object::new(ctx),
        chain_id: object::id(chain),
        seq,
        kind,
        recorded_at_ms: now,
        prev_hash,
        event_hash: copy_u8_vec(&event_hash),
        src_namespace,
        src_chain_id,
        src_tx_hash,
        to_addr,
        policy_object_id: receipt_policy_object_id(receipt),
        policy_version: receipt_policy_version_bytes(receipt),
        intent_hash,
        receipt_object_id: object::id(receipt),
        payload,
    };

    let event_id = object::id(&event);
    transfer::share_object(event);

    chain.head_hash = copy_u8_vec(&event_hash);
    chain.length = seq + 1;

    event_id
}

/// Append an event even if the receipt is denied (v0). Useful for logging blocked attempts.
public fun append_event_with_receipt_any(
    chain: &mut CustodyChain,
    receipt: &PolicyReceipt,
    clock: &Clock,
    kind: u8,
    src_namespace: u8,
    src_chain_id: u64,
    src_tx_hash: vector<u8>,
    to_addr: vector<u8>,
    intent_hash: vector<u8>,
    prev_hash: vector<u8>,
    event_hash: vector<u8>,
    payload: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    assert!(vector::length(&event_hash) == 32, E_BAD_HASH_LEN);
    assert!(vector::length(&prev_hash) == 32, E_BAD_HASH_LEN);
    assert!(vector::length(&intent_hash) == 32, E_BAD_INTENT_LEN);

    if (vector::length(&to_addr) != 0) {
        assert!(vector::length(&to_addr) == 20, E_BAD_TO_LEN);
    };
    if (vector::length(&src_tx_hash) != 0) {
        assert!(vector::length(&src_tx_hash) == 32, E_BAD_TXHASH_LEN);
    };

    assert!(
        u8_vec_equal(&receipt_intent_hash_bytes(receipt), &intent_hash),
        E_RECEIPT_INTENT_MISMATCH
    );

    // Enforce hash chain linkage.
    assert!(u8_vec_equal(&chain.head_hash, &prev_hash), E_PREV_HASH_MISMATCH);

    let now = clock.timestamp_ms();
    let seq = chain.length;
    let event = CustodyEvent {
        id: object::new(ctx),
        chain_id: object::id(chain),
        seq,
        kind,
        recorded_at_ms: now,
        prev_hash,
        event_hash: copy_u8_vec(&event_hash),
        src_namespace,
        src_chain_id,
        src_tx_hash,
        to_addr,
        policy_object_id: receipt_policy_object_id(receipt),
        policy_version: receipt_policy_version_bytes(receipt),
        intent_hash,
        receipt_object_id: object::id(receipt),
        payload,
    };

    let event_id = object::id(&event);
    transfer::share_object(event);

    chain.head_hash = copy_u8_vec(&event_hash);
    chain.length = seq + 1;

    event_id
}

/// Append a custody event and compute `event_hash` on-chain (v2).
public fun append_event_with_receipt_v2(
    chain: &mut CustodyChain,
    receipt: &PolicyReceipt,
    clock: &Clock,
    kind: u8,
    src_namespace: u8,
    src_chain_id: u64,
    src_tx_hash: vector<u8>,
    to_addr: vector<u8>,
    intent_hash: vector<u8>,
    prev_hash: vector<u8>,
    payload: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    assert!(vector::length(&prev_hash) == 32, E_BAD_HASH_LEN);
    assert!(vector::length(&intent_hash) == 32, E_BAD_INTENT_LEN);

    if (vector::length(&to_addr) != 0) {
        assert!(vector::length(&to_addr) == 20, E_BAD_TO_LEN);
    };
    if (vector::length(&src_tx_hash) != 0) {
        assert!(vector::length(&src_tx_hash) == 32, E_BAD_TXHASH_LEN);
    };

    assert!(receipt_is_allowed(receipt), E_RECEIPT_NOT_ALLOWED);
    assert!(
        u8_vec_equal(&receipt_intent_hash_bytes(receipt), &intent_hash),
        E_RECEIPT_INTENT_MISMATCH
    );
    assert!(u8_vec_equal(&chain.head_hash, &prev_hash), E_PREV_HASH_MISMATCH);

    let now = clock.timestamp_ms();
    let seq = chain.length;

    let canon = EventV2Canonical {
        chain_id: object::id(chain),
        seq,
        kind,
        recorded_at_ms: now,
        prev_hash: copy_u8_vec(&prev_hash),
        src_namespace,
        src_chain_id,
        src_tx_hash: copy_u8_vec(&src_tx_hash),
        to_addr: copy_u8_vec(&to_addr),
        policy_object_id: receipt_policy_object_id(receipt),
        policy_version: receipt_policy_version_bytes(receipt),
        intent_hash: copy_u8_vec(&intent_hash),
        receipt_object_id: object::id(receipt),
        payload: copy_u8_vec(&payload),
    };
    let canon_bytes = bcs::to_bytes(&canon);
    let event_hash = hash::keccak256(&canon_bytes);
    assert!(vector::length(&event_hash) == 32, E_HASH_MISMATCH);

    let event = CustodyEvent {
        id: object::new(ctx),
        chain_id: object::id(chain),
        seq,
        kind,
        recorded_at_ms: now,
        prev_hash,
        event_hash: copy_u8_vec(&event_hash),
        src_namespace,
        src_chain_id,
        src_tx_hash,
        to_addr,
        policy_object_id: receipt_policy_object_id(receipt),
        policy_version: receipt_policy_version_bytes(receipt),
        intent_hash,
        receipt_object_id: object::id(receipt),
        payload,
    };

    let event_id = object::id(&event);
    transfer::share_object(event);

    chain.head_hash = copy_u8_vec(&event_hash);
    chain.length = seq + 1;

    event_id
}

/// Append a custody event (even if denied) and compute `event_hash` on-chain (v2).
public fun append_event_with_receipt_any_v2(
    chain: &mut CustodyChain,
    receipt: &PolicyReceipt,
    clock: &Clock,
    kind: u8,
    src_namespace: u8,
    src_chain_id: u64,
    src_tx_hash: vector<u8>,
    to_addr: vector<u8>,
    intent_hash: vector<u8>,
    prev_hash: vector<u8>,
    payload: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    assert!(vector::length(&prev_hash) == 32, E_BAD_HASH_LEN);
    assert!(vector::length(&intent_hash) == 32, E_BAD_INTENT_LEN);

    if (vector::length(&to_addr) != 0) {
        assert!(vector::length(&to_addr) == 20, E_BAD_TO_LEN);
    };
    if (vector::length(&src_tx_hash) != 0) {
        assert!(vector::length(&src_tx_hash) == 32, E_BAD_TXHASH_LEN);
    };

    assert!(
        u8_vec_equal(&receipt_intent_hash_bytes(receipt), &intent_hash),
        E_RECEIPT_INTENT_MISMATCH
    );
    assert!(u8_vec_equal(&chain.head_hash, &prev_hash), E_PREV_HASH_MISMATCH);

    let now = clock.timestamp_ms();
    let seq = chain.length;

    let canon = EventV2Canonical {
        chain_id: object::id(chain),
        seq,
        kind,
        recorded_at_ms: now,
        prev_hash: copy_u8_vec(&prev_hash),
        src_namespace,
        src_chain_id,
        src_tx_hash: copy_u8_vec(&src_tx_hash),
        to_addr: copy_u8_vec(&to_addr),
        policy_object_id: receipt_policy_object_id(receipt),
        policy_version: receipt_policy_version_bytes(receipt),
        intent_hash: copy_u8_vec(&intent_hash),
        receipt_object_id: object::id(receipt),
        payload: copy_u8_vec(&payload),
    };
    let canon_bytes = bcs::to_bytes(&canon);
    let event_hash = hash::keccak256(&canon_bytes);
    assert!(vector::length(&event_hash) == 32, E_HASH_MISMATCH);

    let event = CustodyEvent {
        id: object::new(ctx),
        chain_id: object::id(chain),
        seq,
        kind,
        recorded_at_ms: now,
        prev_hash,
        event_hash: copy_u8_vec(&event_hash),
        src_namespace,
        src_chain_id,
        src_tx_hash,
        to_addr,
        policy_object_id: receipt_policy_object_id(receipt),
        policy_version: receipt_policy_version_bytes(receipt),
        intent_hash,
        receipt_object_id: object::id(receipt),
        payload,
    };

    let event_id = object::id(&event);
    transfer::share_object(event);

    chain.head_hash = copy_u8_vec(&event_hash);
    chain.length = seq + 1;

    event_id
}

/// Append a custody event (even if denied) using a V2 receipt and compute `event_hash` on-chain (v3).
public fun append_event_with_receipt_any_v3(
    chain: &mut CustodyChain,
    receipt: &PolicyReceiptV2,
    clock: &Clock,
    kind: u8,
    src_namespace: u8,
    src_chain_id: u64,
    src_tx_hash: vector<u8>,
    to_addr: vector<u8>,
    intent_hash: vector<u8>,
    prev_hash: vector<u8>,
    payload: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    assert!(vector::length(&prev_hash) == 32, E_BAD_HASH_LEN);
    assert!(vector::length(&intent_hash) == 32, E_BAD_INTENT_LEN);

    if (vector::length(&to_addr) != 0) {
        assert!(vector::length(&to_addr) == 20, E_BAD_TO_LEN);
    };
    if (vector::length(&src_tx_hash) != 0) {
        assert!(vector::length(&src_tx_hash) == 32, E_BAD_TXHASH_LEN);
    };

    assert!(
        u8_vec_equal(&receipt_v2_intent_hash_bytes(receipt), &intent_hash),
        E_RECEIPT_INTENT_MISMATCH
    );
    assert!(u8_vec_equal(&chain.head_hash, &prev_hash), E_PREV_HASH_MISMATCH);

    let now = clock.timestamp_ms();
    let seq = chain.length;

    let canon = EventV2Canonical {
        chain_id: object::id(chain),
        seq,
        kind,
        recorded_at_ms: now,
        prev_hash: copy_u8_vec(&prev_hash),
        src_namespace,
        src_chain_id,
        src_tx_hash: copy_u8_vec(&src_tx_hash),
        to_addr: copy_u8_vec(&to_addr),
        policy_object_id: receipt_v2_policy_object_id(receipt),
        policy_version: receipt_v2_policy_version_bytes(receipt),
        intent_hash: copy_u8_vec(&intent_hash),
        receipt_object_id: object::id(receipt),
        payload: copy_u8_vec(&payload),
    };
    let canon_bytes = bcs::to_bytes(&canon);
    let event_hash = hash::keccak256(&canon_bytes);
    assert!(vector::length(&event_hash) == 32, E_HASH_MISMATCH);

    let event = CustodyEvent {
        id: object::new(ctx),
        chain_id: object::id(chain),
        seq,
        kind,
        recorded_at_ms: now,
        prev_hash,
        event_hash: copy_u8_vec(&event_hash),
        src_namespace,
        src_chain_id,
        src_tx_hash,
        to_addr,
        policy_object_id: receipt_v2_policy_object_id(receipt),
        policy_version: receipt_v2_policy_version_bytes(receipt),
        intent_hash,
        receipt_object_id: object::id(receipt),
        payload,
    };

    let event_id = object::id(&event);
    transfer::share_object(event);

    chain.head_hash = copy_u8_vec(&event_hash);
    chain.length = seq + 1;

    event_id
}

/// Append a custody event using a V3 (multi-chain) receipt and compute `event_hash` on-chain.
public fun append_event_with_receipt_v3(
    chain: &mut CustodyChain,
    receipt: &PolicyReceiptV3,
    clock: &Clock,
    kind: u8,
    src_namespace: u8,
    src_chain_id: u64,
    src_tx_hash: vector<u8>,
    to_addr: vector<u8>,
    intent_hash: vector<u8>,
    prev_hash: vector<u8>,
    payload: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    assert!(vector::length(&prev_hash) == 32, E_BAD_HASH_LEN);
    assert!(vector::length(&intent_hash) == 32, E_BAD_INTENT_LEN);

    // V3 supports variable-length addresses:
    // - Bitcoin: up to 62 bytes (bech32m)
    // - Solana: 32 bytes
    // - EVM: 20 bytes
    if (vector::length(&to_addr) != 0) {
        let len = vector::length(&to_addr);
        assert!(len <= 64, E_BAD_TO_LEN);
    };
    if (vector::length(&src_tx_hash) != 0) {
        let len = vector::length(&src_tx_hash);
        assert!(len <= 64, E_BAD_TXHASH_LEN);
    };

    assert!(
        u8_vec_equal(&receipt_v3_intent_hash_bytes(receipt), &intent_hash),
        E_RECEIPT_INTENT_MISMATCH
    );
    assert!(u8_vec_equal(&chain.head_hash, &prev_hash), E_PREV_HASH_MISMATCH);

    let now = clock.timestamp_ms();
    let seq = chain.length;

    let canon = EventV2Canonical {
        chain_id: object::id(chain),
        seq,
        kind,
        recorded_at_ms: now,
        prev_hash: copy_u8_vec(&prev_hash),
        src_namespace,
        src_chain_id,
        src_tx_hash: copy_u8_vec(&src_tx_hash),
        to_addr: copy_u8_vec(&to_addr),
        policy_object_id: receipt_v3_policy_object_id(receipt),
        policy_version: receipt_v3_policy_version_bytes(receipt),
        intent_hash: copy_u8_vec(&intent_hash),
        receipt_object_id: object::id(receipt),
        payload: copy_u8_vec(&payload),
    };
    let canon_bytes = bcs::to_bytes(&canon);
    let event_hash = hash::keccak256(&canon_bytes);
    assert!(vector::length(&event_hash) == 32, E_HASH_MISMATCH);

    let event = CustodyEvent {
        id: object::new(ctx),
        chain_id: object::id(chain),
        seq,
        kind,
        recorded_at_ms: now,
        prev_hash,
        event_hash: copy_u8_vec(&event_hash),
        src_namespace,
        src_chain_id,
        src_tx_hash,
        to_addr,
        policy_object_id: receipt_v3_policy_object_id(receipt),
        policy_version: receipt_v3_policy_version_bytes(receipt),
        intent_hash,
        receipt_object_id: object::id(receipt),
        payload,
    };

    let event_id = object::id(&event);
    transfer::share_object(event);

    chain.head_hash = copy_u8_vec(&event_hash);
    chain.length = seq + 1;

    event_id
}

/// Append a custody event using a V4 (generic-rules) receipt and compute `event_hash` on-chain.
public fun append_event_with_receipt_v4(
    chain: &mut CustodyChain,
    receipt: &PolicyReceiptV4,
    clock: &Clock,
    kind: u8,
    src_namespace: u8,
    src_chain_id: u64,
    src_tx_hash: vector<u8>,
    to_addr: vector<u8>,
    intent_hash: vector<u8>,
    prev_hash: vector<u8>,
    payload: vector<u8>,
    ctx: &mut TxContext
): object::ID {
    assert!(vector::length(&prev_hash) == 32, E_BAD_HASH_LEN);
    assert!(vector::length(&intent_hash) == 32, E_BAD_INTENT_LEN);

    if (vector::length(&to_addr) != 0) {
        let len = vector::length(&to_addr);
        assert!(len <= 64, E_BAD_TO_LEN);
    };
    if (vector::length(&src_tx_hash) != 0) {
        let len = vector::length(&src_tx_hash);
        assert!(len <= 64, E_BAD_TXHASH_LEN);
    };

    assert!(
        u8_vec_equal(&receipt_v4_intent_hash_bytes(receipt), &intent_hash),
        E_RECEIPT_INTENT_MISMATCH
    );
    assert!(u8_vec_equal(&chain.head_hash, &prev_hash), E_PREV_HASH_MISMATCH);

    let now = clock.timestamp_ms();
    let seq = chain.length;

    let canon = EventV2Canonical {
        chain_id: object::id(chain),
        seq,
        kind,
        recorded_at_ms: now,
        prev_hash: copy_u8_vec(&prev_hash),
        src_namespace,
        src_chain_id,
        src_tx_hash: copy_u8_vec(&src_tx_hash),
        to_addr: copy_u8_vec(&to_addr),
        policy_object_id: receipt_v4_policy_object_id(receipt),
        policy_version: receipt_v4_policy_version_bytes(receipt),
        intent_hash: copy_u8_vec(&intent_hash),
        receipt_object_id: object::id(receipt),
        payload: copy_u8_vec(&payload),
    };
    let canon_bytes = bcs::to_bytes(&canon);
    let event_hash = hash::keccak256(&canon_bytes);
    assert!(vector::length(&event_hash) == 32, E_HASH_MISMATCH);

    let event = CustodyEvent {
        id: object::new(ctx),
        chain_id: object::id(chain),
        seq,
        kind,
        recorded_at_ms: now,
        prev_hash,
        event_hash: copy_u8_vec(&event_hash),
        src_namespace,
        src_chain_id,
        src_tx_hash,
        to_addr,
        policy_object_id: receipt_v4_policy_object_id(receipt),
        policy_version: receipt_v4_policy_version_bytes(receipt),
        intent_hash,
        receipt_object_id: object::id(receipt),
        payload,
    };

    let event_id = object::id(&event);
    transfer::share_object(event);

    chain.head_hash = copy_u8_vec(&event_hash);
    chain.length = seq + 1;

    event_id
}

