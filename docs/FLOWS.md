# Flows

This document describes the key operational flows in Kairo with detailed sequence diagrams.

---

## 1. Vault-Gated Signing Flow (Option A)

This is the primary flow for all signing operations. The PolicyVault is the mandatory gate—there is no legacy signing path.

### Overview

**Vault-Gated Signing Overview:**

```
dApp Request → Extension Approval → Mint Receipt → Vault Authorization → MPC Signing → Custody Append → Broadcast → Return tx_hash
```

### Detailed Sequence

**Detailed Vault-Gated Signing Flow:**

```
1. dApp → Extension: eth_sendTransaction(tx)
   └─ Extension intercepts via EIP-1193 provider

2. Extension → Extension: Compute intent_hash = keccak256(unsignedTx)
   └─ Parse transaction, load policy from storage

3. Extension → User: Show approval popup
   └─ User reviews transaction details
   └─ User authenticates with passkey
   └─ Extension decrypts user share locally
   └─ Extension computes userSignMessage

4. Extension → Sui: mint_receipt_v4(policy, intent_hash, destination, ...)
   └─ Sui → Extension: PolicyReceiptV4 { id: receipt_id, allowed: true }

5. Extension → Backend: POST /api/sign/evm
   └─ Includes: receipt_id, intent, userSignMessage, vaultParams

6. Backend → Sui: Fetch receipt object
   └─ Backend validates receipt fields match request
   └─ Backend checks binding version alignment

7. Backend → Sui: policy_gated_authorize_sign_v4
   └─ Vault performs 9 validation checks:
     • enforcement_mode == STRICT
     • intent_digest length == 32 bytes
     • dWallet exists in vault
     • receipt.allowed == true
     • intent_hash matches
     • destination matches
     • chain_id matches
     • namespace matches
     • binding version matches
   └─ Vault consumes receipt (deletes object)
   └─ Vault records IntentRecord for idempotency
   └─ Sui → Backend: SigningAuthorization

8. Backend → Ika: requestImportedKeySign(userSignMessage, presign)
   └─ Ika performs threshold signing (user + network shares)
   └─ Ika → Backend: signature (r, s, v)

9. Backend → Sui: append_event_with_receipt_v4
   └─ Sui appends hash-chained CustodyEvent
   └─ Sui → Backend: CustodyEvent { id, event_hash }

10. Backend → Target Chain: Broadcast signed transaction
    └─ Target Chain → Backend: tx_hash

11. Backend → Extension: { tx_hash, receipt_id, custody_event_id }
    └─ Extension → dApp: tx_hash
```

### Vault Authorization Checks

The vault performs these checks in `policy_gated_authorize_sign_v4`:

| Check | Error Code | Description |
|-------|------------|-------------|
| Enforcement mode | `E_VAULT_EMERGENCY_BYPASS` | Must be STRICT mode |
| Intent digest length | `E_BAD_INTENT_DIGEST_LEN` | Must be 32 bytes |
| dWallet registered | `E_DWALLET_NOT_FOUND` | Must be in vault |
| Receipt allowed | `E_RECEIPT_NOT_ALLOWED` | Must be `allowed=true` |
| Intent hash match | `E_INTENT_HASH_MISMATCH` | Receipt vs request |
| Destination match | `E_DESTINATION_MISMATCH` | Receipt vs request |
| Chain ID match | `E_CHAIN_ID_MISMATCH` | Receipt vs request |
| Namespace match | `E_NAMESPACE_MISMATCH` | Receipt vs request |
| Binding version match | `E_BINDING_VERSION_MISMATCH` | Receipt vs binding |
| Binding stable ID match | `E_BINDING_STABLE_ID_MISMATCH` | Receipt vs binding |
| Binding dWallet match | `E_BINDING_DWALLET_MISMATCH` | Binding vs vault |
| Receipt TTL (optional) | `E_RECEIPT_EXPIRED` | If TTL specified |

---

## 2. dWallet Provisioning Flow

This flow covers the complete onboarding process from key creation to vault registration.

### Overview

```mermaid
flowchart TB
    A[Create Passkey] --> B[Import/Generate Key]
    B --> C[Encrypt User Share]
    C --> D[Create dWallet via Ika]
    D --> E[Create Policy]
    E --> F[Register in PolicyRegistry]
    F --> G[Create PolicyBinding]
    G --> H[Register in PolicyVault]
    H --> I[Ready to Sign]
```

### Detailed Sequence

```mermaid
sequenceDiagram
    participant User
    participant Ext as Extension
    participant Backend
    participant Ika as Ika Coordinator
    participant Sui

    %% Step 1: Passkey setup
    User->>Ext: Open setup page
    Ext->>Ext: Check for existing passkey
    User->>Ext: Click "Create Passkey"
    Ext->>User: WebAuthn prompt
    User->>Ext: Authenticate (FaceID/TouchID/PIN)
    Ext->>Ext: Store credential ID
    Note over Ext: Passkey enables PRF-based<br/>key derivation for encryption

    %% Step 2: Key import
    User->>Ext: Enter private key (hex or WIF)
    Ext->>Ext: Validate key format
    Ext->>Ext: Derive public key and address
    
    %% Step 3: Encrypt share
    Ext->>Ext: Request PRF output from passkey
    Ext->>Ext: Derive encryption key
    Ext->>Ext: Encrypt private key
    Ext->>Ext: Store encrypted blob locally
    Note over Ext: Key never leaves browser unencrypted

    %% Step 4: Create dWallet
    Ext->>Backend: POST /api/dkg/create-imported
    Backend->>Ika: createDKGSession(imported=true)
    Ika-->>Backend: session_id
    
    Backend->>Sui: Create dWallet + cap objects
    Sui-->>Backend: dwallet_id, dwallet_cap_id

    Backend->>Ika: Finalize DKG
    Ika-->>Backend: encrypted_user_secret_share_id
    
    Backend-->>Ext: { dwallet_id, dwallet_cap_id, encrypted_share_id }

    %% Step 5: Create policy
    User->>Ext: Configure policy rules
    Note over Ext: Destinations, selectors,<br/>amount limits, etc.
    
    Ext->>Backend: POST /api/policy/create-v3
    Backend->>Sui: create_and_share_policy_v4
    Sui-->>Backend: policy_id
    Backend-->>Ext: policy_id

    %% Step 6: Register in registry
    Ext->>Backend: POST /api/policy/register-version
    Backend->>Sui: register_policy_version_from_policy_v3
    Sui-->>Backend: policy_version_id
    Backend-->>Ext: policy_version_id

    %% Step 7: Create binding
    Ext->>Backend: POST /api/policy/create-binding
    Backend->>Sui: create_and_share_policy_binding
    Sui-->>Backend: binding_id
    Backend-->>Ext: binding_id

    %% Step 8: Register in vault
    Ext->>Backend: POST /api/vault/register-dwallet
    Backend->>Sui: register_dwallet_into_vault
    Note over Sui: Emits DWalletRegisteredEvent
    Sui-->>Backend: success
    Backend-->>Ext: { vault_registered: true }

    %% Complete
    Ext->>Ext: Update wallet state to BOUND_AND_READY
    Ext->>User: "Wallet ready for signing"
```

### Wallet State Transitions

```mermaid
stateDiagram-v2
    [*] --> CREATED: dWallet created
    CREATED --> BOUND_AND_READY: Binding + Vault registration
    BOUND_AND_READY --> SIGNING: Sign request approved
    SIGNING --> BOUND_AND_READY: Signature complete
    
    note right of CREATED
        dWallet exists but cannot sign.
        Missing binding or vault registration.
    end note
    
    note right of BOUND_AND_READY
        Both PolicyBinding and vault
        registration exist. Ready to sign.
    end note
```

---

## 3. Recovery Flow

Recovery involves regaining access to signing capabilities after losing access to the original device or passkey.

### Current Implementation

The current code implements passkey-based recovery:

```mermaid
flowchart TB
    subgraph Current["Current (Implemented)"]
        A1[New Device] --> A2[Create New Passkey]
        A2 --> A3[Re-import Private Key]
        A3 --> A4[Re-encrypt with New Passkey]
        A4 --> A5[Restore from Stored dWallet IDs]
    end
    
    subgraph Planned["Implemented"]
        B1[Social Recovery] --> B2[Threshold Approvals]
        B2 --> B3[Timelock Period]
        B3 --> B4[Vault Re-authorization]
        
        C1[Walrus+Seal Backup] --> C2[Decrypt Share]
        C2 --> C4[Vault Re-authorization]
    end
```

### Detailed Recovery Sequence (Current)

```mermaid
sequenceDiagram
    participant User
    participant NewDevice as New Device/Browser
    participant Ext as Extension
    participant Sui

    User->>NewDevice: Install extension
    NewDevice->>Ext: Open setup page

    %% Create new passkey
    User->>Ext: Create new passkey
    Ext->>User: WebAuthn registration
    User->>Ext: Authenticate

    %% Re-import key
    Note over User: User must have backup<br/>of original private key
    User->>Ext: Enter private key
    Ext->>Ext: Encrypt with new passkey

    %% Restore wallet metadata
    User->>Ext: Enter known object IDs
    Note over Ext: dWallet ID, binding ID,<br/>policy ID, etc.
    
    Ext->>Sui: Fetch and verify objects exist
    Sui-->>Ext: Object data

    Ext->>Ext: Store wallet configuration
    Ext->>User: Recovery complete
```

### Planned Recovery Flow (TBD)

```mermaid
sequenceDiagram
    participant User
    participant Ext as Extension
    participant Sui
    participant Vault as PolicyVault
    participant Guardians as Recovery Guardians

    %% Initiate recovery
    User->>Ext: Initiate recovery
    Ext->>Sui: Create RecoveryIntent
    
    %% Gather approvals
    Ext->>Guardians: Request recovery approval
    Note over Guardians: Social recovery:<br/>trusted contacts, other wallets
    
    loop Until threshold met
        Guardians->>Sui: Sign recovery approval
    end

    %% Timelock
    Note over Sui: Timelock period starts<br/>(e.g., 7 days)
    
    %% Complete recovery
    Sui->>Sui: Timelock expires
    User->>Ext: Complete recovery
    Ext->>Sui: Mint RecoveryReceipt
    
    %% Re-authorize vault
    Ext->>Vault: complete_recovery
    Vault->>Vault: Re-enable signing for dWallet
    
    Ext->>User: Recovery complete
```

---

## 4. Chain of Custody Flow

Every signing operation creates an immutable custody event, forming a verifiable audit trail.

### Hash Chain Progression

```mermaid
flowchart LR
    subgraph Chain["CustodyChain"]
        Head["head_hash"]
    end

    subgraph Events["CustodyEvents"]
        E0["Event 0<br/>prev: 0x000...<br/>hash: H0"]
        E1["Event 1<br/>prev: H0<br/>hash: H1"]
        E2["Event 2<br/>prev: H1<br/>hash: H2"]
        E3["Event 3<br/>prev: H2<br/>hash: H3"]
    end

    E0 --> E1 --> E2 --> E3
    E3 -.->|"Updates"| Head
```

### Custody Append Sequence

```mermaid
sequenceDiagram
    participant Backend
    participant Sui
    participant Chain as CustodyChain
    participant Event as CustodyEvent

    Backend->>Sui: append_event_with_receipt_v4
    
    Sui->>Chain: Read head_hash
    Chain-->>Sui: prev_hash (current head)
    
    Sui->>Sui: Build EventV2Canonical struct
    Note over Sui: Includes: chain_id, seq, kind,<br/>prev_hash, intent_hash, receipt_id, etc.
    
    Sui->>Sui: Serialize to BCS
    Sui->>Sui: event_hash = keccak256(bcs_bytes)
    
    Sui->>Event: Create CustodyEvent
    Note over Event: Immutable object with<br/>all fields + computed hash
    
    Sui->>Chain: Update head_hash = event_hash
    Sui->>Chain: Increment length
    
    Sui-->>Backend: event_id
```

### Event Kind Constants

| Kind | Value | Description |
|------|-------|-------------|
| `EVENT_MINT` | 1 | Asset minted/created |
| `EVENT_TRANSFER` | 2 | Asset transferred |
| `EVENT_BURN` | 3 | Asset burned/destroyed |
| `EVENT_LOCK` | 4 | Asset locked |
| `EVENT_UNLOCK` | 5 | Asset unlocked |
| `EVENT_POLICY_CHECKPOINT` | 6 | Policy affirmation |

### Custody Verification

```mermaid
flowchart TB
    A[Get CustodyEvent by ID] --> B[Extract all fields]
    B --> C[Build EventV2Canonical]
    C --> D[Serialize to BCS]
    D --> E[Compute keccak256]
    E --> F{Hash matches<br/>event_hash?}
    F -->|Yes| G[Valid Event]
    F -->|No| H[Tampered/Invalid]
    
    G --> I[Check prev_hash linkage]
    I --> J{Links to<br/>previous event?}
    J -->|Yes| K[Valid Chain]
    J -->|No| L[Broken Chain]
```

---

## 5. Policy Update Flow

When a policy is updated, users must reaffirm their binding before signing can continue.

```mermaid
sequenceDiagram
    participant Publisher
    participant Sui
    participant Registry as PolicyRegistry
    participant Binding as PolicyBinding
    participant User
    participant Ext as Extension

    %% Publisher updates policy
    Publisher->>Sui: create_and_share_policy_v4 (new version)
    Sui-->>Publisher: new_policy_id

    Publisher->>Sui: register_policy_version
    Sui->>Registry: Add new PolicyVersion
    Note over Registry: Latest version updated<br/>for this stable_id

    %% User attempts to sign
    User->>Ext: Send transaction
    Ext->>Sui: Fetch binding.active_version_id
    Ext->>Sui: Fetch registry latest version
    
    Ext->>Ext: Compare versions
    Note over Ext: Binding version != Latest version

    Ext->>User: "Policy updated. Review and reaffirm?"
    
    %% Show changes
    Ext->>Sui: Fetch old PolicyVersion
    Ext->>Sui: Fetch new PolicyVersion
    Ext->>User: Display policy diff

    %% User reaffirms
    User->>Ext: Approve update
    Ext->>Sui: reaffirm_policy_binding
    Sui->>Binding: Update active_version_id
    
    %% Now signing can proceed
    Ext->>User: "Ready to sign"
```

---

## Flow Summary Table

| Flow | Trigger | Key Steps | Artifacts Created |
|------|---------|-----------|-------------------|
| **Signing** | dApp transaction | Mint receipt → Vault auth → MPC sign → Custody | Receipt (consumed), IntentRecord, CustodyEvent |
| **Provisioning** | User onboarding | Passkey → dWallet → Policy → Binding → Vault | dWallet, Policy, Binding, VaultedDWallet |
| **Recovery** | Device loss | New passkey → Re-import → Restore | New encrypted share |
| **Custody** | Every signing | Append hash-linked event | CustodyEvent |
| **Policy Update** | Publisher action | Register version → User reaffirms | PolicyVersion, updated Binding |
