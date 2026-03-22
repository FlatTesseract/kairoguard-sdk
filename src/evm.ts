/**
 * Minimal EVM JSON-RPC helpers using raw fetch (no ethers/viem runtime dependency).
 */

interface JsonRpcSuccess<T> {
  jsonrpc: "2.0";
  id: number;
  result: T;
}

interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

interface JsonRpcFailure {
  jsonrpc: "2.0";
  id: number;
  error: JsonRpcError;
}

type JsonRpcResponse<T> = JsonRpcSuccess<T> | JsonRpcFailure;

export interface EstimateGasParams {
  from?: string;
  to?: string;
  value?: string;
  data?: string;
  gas?: string;
  gasPrice?: string;
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
  nonce?: string;
}

let rpcRequestId = 0;

function parseHexQuantity(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) {
    throw new Error(`Invalid ${field} response: expected hex quantity`);
  }
  return BigInt(value);
}

async function rpcCall<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const id = ++rpcRequestId;
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method,
      params,
    }),
  });

  const payload = await response.json() as JsonRpcResponse<T>;

  if (!response.ok) {
    const errorMessage =
      "error" in payload
        ? payload.error.message
        : `HTTP ${response.status}`;
    throw new Error(`EVM RPC error (${method}): ${errorMessage}`);
  }

  if ("error" in payload) {
    throw new Error(`EVM RPC error (${method}): ${payload.error.message}`);
  }

  return payload.result;
}

export async function broadcastEvm(signedTx: string, rpcUrl: string): Promise<string> {
  return rpcCall<string>(rpcUrl, "eth_sendRawTransaction", [signedTx]);
}

export async function getBalance(address: string, rpcUrl: string): Promise<bigint> {
  const result = await rpcCall<string>(rpcUrl, "eth_getBalance", [address, "latest"]);
  return parseHexQuantity(result, "eth_getBalance");
}

export async function estimateGas(txParams: EstimateGasParams, rpcUrl: string): Promise<bigint> {
  const result = await rpcCall<string>(rpcUrl, "eth_estimateGas", [txParams]);
  return parseHexQuantity(result, "eth_estimateGas");
}

export async function getTransactionCount(address: string, rpcUrl: string): Promise<bigint> {
  const result = await rpcCall<string>(rpcUrl, "eth_getTransactionCount", [address, "pending"]);
  return parseHexQuantity(result, "eth_getTransactionCount");
}

export async function getGasPrice(rpcUrl: string): Promise<bigint> {
  const result = await rpcCall<string>(rpcUrl, "eth_gasPrice", []);
  return parseHexQuantity(result, "eth_gasPrice");
}
