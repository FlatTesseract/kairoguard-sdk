# `kairo_policy_engine` (Sui Move) — Testnet workflow

This package implements a minimal **hard-gate** policy engine for Kairo:

- A `Policy` object defines simple constraints (v0: allow/deny destination).
- A `PolicyReceipt` object is minted on Sui and is intended to be **required before EVM signing**.

## Build / publish (testnet)

Prereq: install Sui CLI (see Sui docs: `https://docs.sui.io/`).

In a terminal:

```bash
cd sui/kairo_policy_engine
sui client active-address
sui client publish --gas-budget 200000000
```

Record the published **packageId** from the output (you’ll use it in `buildMintEvmReceiptTx` and CLI calls).

If you later run `sui client upgrade`, Sui will produce a **new PackageID** (the “upgraded package”),
and you should use that newest PackageID going forward.

### Fresh publish (new wallet / new package)

If you see an error like:

- `Modules must all have 0x0 as their addresses. Violated by module ...`

it usually means the package is being built with a previously published address (often due to `Published.toml`).

Use the helper script (Windows):

```powershell
cd sui/kairo_policy_engine
.\publish-fresh.ps1
```

This temporarily moves `Published.toml` aside, cleans build artifacts, and publishes a brand-new package.

## Important: CLI minting helper

When calling from `sui client call`, prefer:

- `mint_receipt_evm_to_sender(...)` (mints a receipt and transfers it to the transaction sender)

because `mint_receipt_evm(...)` returns a `PolicyReceipt` object and can fail with
`UnusedValueWithoutDrop` in CLI-constructed transactions if the return value isn’t transferred.

## Verify a receipt (CLI)

To inspect a minted receipt:

```bash
sui client object <RECEIPT_OBJECT_ID> --json
```

Look for:

- `fields.allowed: true`
- `fields.evm_chain_id` matches your target chain
- `fields.to_evm` equals the allowlisted destination (20 bytes)
- `fields.intent_hash` matches your EVM intent (32 bytes)

## Create a policy object (testnet)

The simplest way is via `sui client call` to create+share a `Policy` in one transaction.

Example: create policy v`1.0.0`, **allowlist-only**, allow exactly one EVM destination, no expiry:

```bash
sui client call \
  --package <PACKAGE_ID> \
  --module policy_registry \
  --function create_and_share_policy \
  --args \
    "kairo-policy-demo" \
    "1.0.0" \
    "[[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]]" \
    "[]" \
    0 \
  --gas-budget 50000000
```

Notes:

- In v0, `allow_to_evm` and `deny_to_evm` are `vector<vector<u8>>` where each address is **20 bytes**.
- In **allowlist-only**, an empty `allow_to_evm` means **deny all**.
- In a real build we’ll add a proper admin/governance model for who can create/upgrade policies.


