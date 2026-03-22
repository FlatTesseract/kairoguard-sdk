export interface PolicyTemplatePreset {
  id: "tpl-1" | "tpl-2" | "tpl-3";
  label: string;
  singleTxUsd: number;
  dailyLimitUsd: number;
}

export const POLICY_TEMPLATE_PRESETS: Record<PolicyTemplatePreset["id"], PolicyTemplatePreset> = {
  "tpl-1": {
    id: "tpl-1",
    label: "Conservative ($200/tx, $1k/day)",
    singleTxUsd: 200,
    dailyLimitUsd: 1_000,
  },
  "tpl-2": {
    id: "tpl-2",
    label: "Standard ($2k/tx, $10k/day)",
    singleTxUsd: 2_000,
    dailyLimitUsd: 10_000,
  },
  "tpl-3": {
    id: "tpl-3",
    label: "High-limit ($10k/tx, $50k/day)",
    singleTxUsd: 10_000,
    dailyLimitUsd: 50_000,
  },
};

function stripHexPrefix(value: string): string {
  return value.startsWith("0x") ? value.slice(2) : value;
}

function encodeU256(value: number | string | bigint): string {
  const big = typeof value === "bigint" ? value : BigInt(value);
  return `0x${big.toString(16).padStart(64, "0")}`;
}

function encodeMaxNativeRule(maxNativeBaseUnits: bigint): string {
  return encodeU256(maxNativeBaseUnits);
}

function encodeDailyPeriodLimitRule(maxDailyBaseUnits: bigint): string {
  const periodTypeDaily = 1;
  return `0x${periodTypeDaily.toString(16).padStart(2, "0")}${stripHexPrefix(
    encodeU256(maxDailyBaseUnits),
  )}`;
}

export function buildPolicyTemplatePayload(templateId: string): {
  template: PolicyTemplatePreset;
  allowNamespaces: number[];
  rules: Array<{ ruleType: number; namespace?: number; params: string }>;
} {
  const template =
    POLICY_TEMPLATE_PRESETS[templateId as PolicyTemplatePreset["id"]] ?? POLICY_TEMPLATE_PRESETS["tpl-2"];
  const maxNativeBaseUnits = BigInt(Math.round(template.singleTxUsd * 1_000_000));
  const dailyLimitBaseUnits = BigInt(Math.round(template.dailyLimitUsd * 1_000_000));

  return {
    template,
    // Default to EVM namespace so newly onboarded users can sign EVM txs immediately.
    allowNamespaces: [1],
    rules: [
      {
        ruleType: 1,
        namespace: 0,
        params: encodeMaxNativeRule(maxNativeBaseUnits),
      },
      {
        ruleType: 10,
        namespace: 0,
        params: encodeDailyPeriodLimitRule(dailyLimitBaseUnits),
      },
    ],
  };
}
