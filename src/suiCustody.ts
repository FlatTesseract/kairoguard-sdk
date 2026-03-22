import { SuiClient } from "@mysten/sui/client";
import { bcs } from "@mysten/sui/bcs";
import { keccak256, toBytes, type Hex as ViemHex } from "viem";

type Hex = `0x${string}`;

const VecU8 = bcs.vector(bcs.u8());

// Matches `kairo_policy_engine::custody_ledger::EventV2Canonical`
const EventV2CanonicalBcs = bcs.struct("EventV2Canonical", {
  chain_id: bcs.Address,
  seq: bcs.u64(),
  kind: bcs.u8(),
  recorded_at_ms: bcs.u64(),
  prev_hash: VecU8,
  src_namespace: bcs.u8(),
  src_chain_id: bcs.u64(),
  src_tx_hash: VecU8,
  to_addr: VecU8,
  policy_object_id: bcs.Address,
  policy_version: VecU8,
  intent_hash: VecU8,
  receipt_object_id: bcs.Address,
  payload: VecU8,
});

/**
 * Verify a custody event hash by recomputing the canonical BCS encoding (v2/v3 hashing).
 *
 * Note: This does NOT discover events. You must provide a specific `CustodyEvent` object id.
 */
export async function fetchAndVerifyCustodyEvent(args: {
  suiRpcUrl: string;
  custodyEventObjectId: string;
}): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const client = new SuiClient({ url: args.suiRpcUrl });
    const obj = await client.getObject({
      id: args.custodyEventObjectId,
      options: { showType: true, showContent: true },
    });
    if (!obj.data) throw new Error("CustodyEvent object not found");
    const typeStr = String((obj.data as any).type ?? "");
    if (!typeStr.endsWith("::custody_ledger::CustodyEvent")) {
      throw new Error(`Object is not a CustodyEvent (type=${typeStr})`);
    }
    const content: any = (obj.data as any).content;
    if (!content || content.dataType !== "moveObject") {
      throw new Error("CustodyEvent object has no Move content");
    }
    const f: any = content.fields ?? {};

    const chainId = String(f["chain_id"] ?? "").trim();
    const receiptId = String(f["receipt_object_id"] ?? "").trim();
    const policyObjectId = String(f["policy_object_id"] ?? "").trim();
    if (!chainId.startsWith("0x") || !receiptId.startsWith("0x") || !policyObjectId.startsWith("0x")) {
      throw new Error("CustodyEvent missing required object id fields");
    }

    const seq = toBigInt(f["seq"]);
    const kind = toNumberU8(f["kind"]);
    const recordedAt = toBigInt(f["recorded_at_ms"]);
    const prevHash = coerceBytes(f["prev_hash"]);
    const srcNs = toNumberU8(f["src_namespace"]);
    const srcChainId = toBigInt(f["src_chain_id"]);
    const srcTxHash = coerceBytes(f["src_tx_hash"]) ?? new Uint8Array();
    const toAddr = coerceBytes(f["to_addr"]) ?? new Uint8Array();
    const policyVersion = coerceBytes(f["policy_version"]) ?? new Uint8Array();
    const intentHash = coerceBytes(f["intent_hash"]);
    const payload = coerceBytes(f["payload"]) ?? new Uint8Array();
    const eventHashOnChain = coerceBytes(f["event_hash"]);

    if (
      seq == null ||
      kind == null ||
      recordedAt == null ||
      srcNs == null ||
      srcChainId == null ||
      !prevHash ||
      !intentHash ||
      !eventHashOnChain
    ) {
      throw new Error("CustodyEvent missing required scalar/hash fields");
    }
    if (prevHash.length !== 32) throw new Error("prev_hash must be 32 bytes");
    if (intentHash.length !== 32) throw new Error("intent_hash must be 32 bytes");
    if (eventHashOnChain.length !== 32) throw new Error("event_hash must be 32 bytes");

    const canonBytes = EventV2CanonicalBcs.serialize({
      chain_id: chainId,
      seq,
      kind,
      recorded_at_ms: recordedAt,
      prev_hash: Array.from(prevHash),
      src_namespace: srcNs,
      src_chain_id: srcChainId,
      src_tx_hash: Array.from(srcTxHash),
      to_addr: Array.from(toAddr),
      policy_object_id: policyObjectId,
      policy_version: Array.from(policyVersion),
      intent_hash: Array.from(intentHash),
      receipt_object_id: receiptId,
      payload: Array.from(payload),
    }).toBytes();

    const computed = toBytes(keccak256(canonBytes) as ViemHex);
    if (!bytesEq(computed, eventHashOnChain)) {
      throw new Error(
        `CustodyEvent hash mismatch (computed=${toHex(computed)}, onchain=${toHex(eventHashOnChain)})`
      );
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

function toBigInt(v: any): bigint | null {
  if (v == null) return null;
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isFinite(v)) return BigInt(v);
  if (typeof v === "string") {
    const s = v.trim();
    if (!s) return null;
    if (s.startsWith("0x") || s.startsWith("0X")) return BigInt(s);
    if (/^\\d+$/.test(s)) return BigInt(s);
  }
  return null;
}

function toNumberU8(v: any): number | null {
  if (v == null) return null;
  const n = typeof v === "number" ? v : Number(String(v));
  if (!Number.isFinite(n)) return null;
  const i = Math.floor(n);
  if (i < 0 || i > 255) return null;
  return i;
}

function coerceBytes(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v) && v.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) {
    return Uint8Array.from(v as number[]);
  }
  if (typeof v === "string") {
    const s = v.trim();
    if (!s) return null;
    if (/^0x[0-9a-fA-F]*$/.test(s)) {
      try {
        return toBytes(s as any);
      } catch {
        return null;
      }
    }
    // base64
    try {
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
      if (typeof Buffer !== "undefined") return Uint8Array.from(Buffer.from(s, "base64"));
    } catch {
      return null;
    }
  }
  if (v && typeof v === "object") {
    const o: any = v;
    if (o.bytes != null) return coerceBytes(o.bytes);
    if (o.data != null) return coerceBytes(o.data);
    if (o.value != null) return coerceBytes(o.value);
  }
  return null;
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function toHex(bytes: Uint8Array): Hex {
  return `0x${Buffer.from(bytes).toString("hex")}` as Hex;
}

