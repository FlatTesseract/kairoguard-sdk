import { SuiClient } from "@mysten/sui/client";
import type { Hex } from "./types.js";

/**
 * Minimal "hard gate" receipt verification helper.
 *
 * We verify:
 * - receipt object exists
 * - receipt.allowed === true
 * - receipt fields match the expected commitment (policyId, policyVersion, chainId, intent hash, optional destination)
 *
 * The exact object type + field names are defined in the Move package under `sui/kairo_policy_engine`.
 */
export async function fetchAndValidatePolicyReceipt(params: {
  suiRpcUrl: string;
  receiptObjectId: string;
  expected: {
    // Policy object id on Sui.
    policyId: string;
    policyVersion: string;
    evmChainId: number;
    intentHash: Hex;
    toEvm?: Hex;
    // Optional PolicyReceiptV2 extras (for stronger audit proofs).
    policyStableId?: string;
    policyRoot?: Hex; // 32 bytes
    policyVersionId?: string; // 0x...
    evmSelector?: Hex; // 4 bytes
    erc20Amount?: Hex; // 32 bytes
  };
}): Promise<void> {
  const suiClient = new SuiClient({ url: params.suiRpcUrl });

  const obj = await suiClient.getObject({
    id: params.receiptObjectId,
    options: { showContent: true, showType: true },
  });
  if (!obj.data) throw new Error("Receipt object not found");

  const content: any = (obj.data as any).content;
  const typeStr: string = String((obj.data as any).type ?? "");
  if (!content || content.dataType !== "moveObject") {
    throw new Error("Receipt object has no Move content");
  }

  const fields: any = content.fields ?? {};

  // PolicyReceiptV2
  if (typeStr.endsWith("::policy_registry::PolicyReceiptV2")) {
    const allowed = Boolean(fields["allowed"]);
    if (!allowed) {
      const denial = fields["denial_reason"];
      const denialReason = typeof denial === "bigint" ? denial.toString() : String(denial ?? "");
      throw new Error(`Receipt is denied (denial_reason=${denialReason})`);
    }

    const policyObjectId = String(fields["policy_object_id"] ?? "");
    const policyVersion = bytesFieldToUtf8(fields["policy_version"]);
    const stableId = bytesFieldToUtf8(fields["policy_stable_id"]);
    const policyRoot = normalizeBytesFieldToHex(fields["policy_root"]);
    const policyVersionId = String(fields["policy_version_id"] ?? "");

    const evmChainId = Number(String(fields["evm_chain_id"] ?? ""));
    const intentHash = normalizeBytesFieldToHex(fields["intent_hash"]);
    const toEvm = normalizeBytesFieldToHex(fields["to_evm"]);
    const selector = normalizeBytesFieldToHex(fields["evm_selector"]);
    const amount = normalizeBytesFieldToHex(fields["erc20_amount"]);

    if (!policyObjectId || !policyVersion || !Number.isFinite(evmChainId) || !intentHash || !toEvm) {
      throw new Error("ReceiptV2 missing required fields");
    }
    if (!policyRoot || coerceBytes(fields["policy_root"])?.length !== 32) {
      throw new Error("ReceiptV2 policy_root missing/invalid (expected 32 bytes)");
    }
    if (!policyVersionId.startsWith("0x")) {
      throw new Error("ReceiptV2 policy_version_id missing/invalid");
    }
    if (selector && coerceBytes(fields["evm_selector"])?.length !== 4) {
      throw new Error("ReceiptV2 evm_selector invalid (expected 4 bytes or empty)");
    }
    if (amount && coerceBytes(fields["erc20_amount"])?.length !== 32) {
      throw new Error("ReceiptV2 erc20_amount invalid (expected 32 bytes or empty)");
    }

    if (policyObjectId.toLowerCase() !== params.expected.policyId.toLowerCase()) {
      throw new Error("ReceiptV2 policy_object_id mismatch");
    }
    if (policyVersion !== params.expected.policyVersion) {
      throw new Error("ReceiptV2 policy_version mismatch");
    }
    if (evmChainId !== params.expected.evmChainId) {
      throw new Error("ReceiptV2 evm_chain_id mismatch");
    }
    if (intentHash.toLowerCase() !== params.expected.intentHash.toLowerCase()) {
      throw new Error("ReceiptV2 intent_hash mismatch");
    }
    if (params.expected.toEvm && toEvm.toLowerCase() !== params.expected.toEvm.toLowerCase()) {
      throw new Error("ReceiptV2 destination mismatch");
    }

    // Optional stronger checks (if caller provides expectations)
    if (params.expected.policyStableId && stableId && stableId !== params.expected.policyStableId) {
      throw new Error("ReceiptV2 policy_stable_id mismatch");
    }
    if (params.expected.policyRoot && policyRoot.toLowerCase() !== params.expected.policyRoot.toLowerCase()) {
      throw new Error("ReceiptV2 policy_root mismatch");
    }
    if (
      params.expected.policyVersionId &&
      policyVersionId.toLowerCase() !== params.expected.policyVersionId.toLowerCase()
    ) {
      throw new Error("ReceiptV2 policy_version_id mismatch");
    }
    if (params.expected.evmSelector && (!selector || selector.toLowerCase() !== params.expected.evmSelector.toLowerCase())) {
      throw new Error("ReceiptV2 evm_selector mismatch");
    }
    if (params.expected.erc20Amount && (!amount || amount.toLowerCase() !== params.expected.erc20Amount.toLowerCase())) {
      throw new Error("ReceiptV2 erc20_amount mismatch");
    }
    return;
  }

  // Legacy PolicyReceipt (MVP)
  const policyId = String(fields["policy_id"] ?? "");
  const policyVersion = bytesFieldToUtf8(fields["policy_version"]);
  const evmChainId = Number(String(fields["evm_chain_id"] ?? ""));
  const allowed = Boolean(fields["allowed"]);

  if (!allowed) {
    const denial = fields["denial_reason"];
    const denialReason = typeof denial === "bigint" ? denial.toString() : String(denial ?? "");
    throw new Error(`Receipt is denied (denial_reason=${denialReason})`);
  }

  const intentHash = normalizeBytesFieldToHex(fields["intent_hash"]);
  if (!intentHash) throw new Error("Receipt intent_hash missing/invalid");

  if (!policyId || !policyVersion || !Number.isFinite(evmChainId)) {
    throw new Error("Receipt missing required fields");
  }

  if (policyId.toLowerCase() !== params.expected.policyId.toLowerCase()) {
    throw new Error("Receipt policy_id mismatch");
  }
  if (policyVersion !== params.expected.policyVersion) {
    throw new Error("Receipt policy_version mismatch");
  }
  if (evmChainId !== params.expected.evmChainId) {
    throw new Error("Receipt evm_chain_id mismatch");
  }
  if (intentHash.toLowerCase() !== params.expected.intentHash.toLowerCase()) {
    throw new Error("Receipt intent_hash mismatch");
  }

  const expectedTo = params.expected.toEvm;
  if (expectedTo) {
    const receiptTo = normalizeBytesFieldToHex(fields["to_evm"]);
    if (!receiptTo) throw new Error("Receipt to_evm missing/invalid");
    if (receiptTo.toLowerCase() !== expectedTo.toLowerCase()) {
      throw new Error("Receipt destination mismatch");
    }
  }
}

function normalizeBytesFieldToHex(v: unknown): Hex | null {
  const bytes = coerceBytes(v);
  if (!bytes) return null;
  return `0x${bytesToHex(bytes)}` as Hex;
}

function bytesFieldToUtf8(v: unknown): string {
  const bytes = coerceBytes(v);
  if (!bytes) return "";
  return new TextDecoder().decode(bytes);
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function coerceBytes(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v) && v.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) {
    return Uint8Array.from(v as number[]);
  }
  if (typeof v === "string") {
    if (/^0x[0-9a-fA-F]*$/.test(v)) {
      const raw = v.slice(2);
      if (raw.length % 2 !== 0) return null;
      const out = new Uint8Array(raw.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
      return out;
    }
    return base64ToBytes(v);
  }
  if (v && typeof v === "object") {
    const o: any = v;
    if (typeof o.bytes === "string") return coerceBytes(o.bytes);
    if (typeof o.data === "string") return coerceBytes(o.data);
    if (typeof o.value === "string") return coerceBytes(o.value);
  }
  return null;
}

function base64ToBytes(s: string): Uint8Array | null {
  // Node
  try {
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
    if (typeof Buffer !== "undefined") {
      const buf = Buffer.from(s, "base64");
      if (buf.length === 0 && s.length > 0) return null;
      return Uint8Array.from(buf);
    }
  } catch {
    // ignore
  }
  // Browser
  try {
    const atobFn = (globalThis as any).atob;
    if (typeof atobFn !== "function") return null;
    const bin = atobFn(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

