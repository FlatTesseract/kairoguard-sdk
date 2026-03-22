#!/usr/bin/env node
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { verifyAuditBundle } from "./auditBundle.js";
import { BackendClient, DEFAULT_BACKEND_URL } from "./backend.js";
import { KairoClient } from "./client.js";
import { POLICY_TEMPLATE_PRESETS, buildPolicyTemplatePayload } from "./policy-templates.js";
import { SKILL_MD, API_REFERENCE_MD, SDK_REFERENCE_MD } from "./skill-templates.js";

const CONFIG_DIR = join(homedir(), ".kairo");
const CONFIG_PATH = join(CONFIG_DIR, "config.json");

// ── Config helpers ──────────────────────────────────────────────────────────

interface KairoConfig {
  apiKey: string;
  backendUrl?: string;
}

function loadConfig(): KairoConfig | null {
  if (!existsSync(CONFIG_PATH)) return null;
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as KairoConfig;
  } catch {
    return null;
  }
}

function requireConfig(): KairoConfig {
  const cfg = loadConfig();
  if (!cfg) {
    console.error("No Kairo config found. Run: npx @kairo/sdk init <YOUR_KEY>");
    process.exit(1);
  }
  return cfg;
}

function getClient(apiKeyOverride?: string, backendUrlOverride?: string): BackendClient {
  const cfg = requireConfig();
  const key = apiKeyOverride ?? cfg.apiKey;
  const backendUrl = backendUrlOverride ?? cfg.backendUrl ?? DEFAULT_BACKEND_URL;
  return new BackendClient({ apiKey: key, backendUrl });
}

// ── Arg helpers ─────────────────────────────────────────────────────────────

function flag(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx < 0) return undefined;
  return args[idx + 1];
}

function hasFlag(args: string[], name: string): boolean {
  return args.includes(name);
}

function requireFlag(args: string[], name: string, label: string): string {
  const v = flag(args, name);
  if (!v) {
    console.error(`Required: ${name} <${label}>`);
    process.exit(1);
  }
  return v;
}

async function promptPolicyTemplateId(): Promise<"tpl-1" | "tpl-2" | "tpl-3"> {
  const rl = createInterface({ input, output });
  try {
    console.log("Choose a default policy template:");
    console.log(`  1) ${POLICY_TEMPLATE_PRESETS["tpl-1"].label}`);
    console.log(`  2) ${POLICY_TEMPLATE_PRESETS["tpl-2"].label}`);
    console.log(`  3) ${POLICY_TEMPLATE_PRESETS["tpl-3"].label}`);
    const answer = (await rl.question("Template [1/2/3] (default 2): ")).trim();
    if (answer === "1") return "tpl-1";
    if (answer === "3") return "tpl-3";
    return "tpl-2";
  } finally {
    rl.close();
  }
}

// ── Commands ────────────────────────────────────────────────────────────────

async function cmdInit(args: string[]) {
  const apiKey = args[0];
  const backendUrl = flag(args, "--backend-url") ?? DEFAULT_BACKEND_URL;
  if (!apiKey) {
    console.error("Usage: kairo init <YOUR_KEY> [--backend-url <url>]");
    process.exit(1);
  }

  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_PATH, JSON.stringify({ apiKey, backendUrl }, null, 2) + "\n", "utf8");
  console.log(`  Config written to ${CONFIG_PATH}`);

  const skillDir = join(process.cwd(), ".cursor", "skills", "kairo");
  const refsDir = join(skillDir, "references");
  mkdirSync(refsDir, { recursive: true });

  writeFileSync(join(skillDir, "SKILL.md"), SKILL_MD, "utf8");
  writeFileSync(join(refsDir, "api.md"), API_REFERENCE_MD, "utf8");
  writeFileSync(join(refsDir, "sdk.md"), SDK_REFERENCE_MD, "utf8");
  console.log(`  Skill files installed to ${skillDir}`);

  const client = new BackendClient({ apiKey, backendUrl });
  try {
    await client.getHealth();
    console.log(`  Backend connection verified (${backendUrl}).`);
  } catch {
    console.log(`  Warning: could not reach backend ${backendUrl} (check your network).`);
  }

  console.log("\nKairo is ready. Your AI agent can now read the skill at .cursor/skills/kairo/SKILL.md");
}

async function cmdHealth() {
  const client = getClient();
  const res = await client.getHealth();
  console.log(JSON.stringify(res, null, 2));
}

async function cmdWalletCreate(args: string[]) {
  const curveRaw = flag(args, "--curve") ?? "secp256k1";
  if (curveRaw !== "secp256k1" && curveRaw !== "ed25519") {
    console.error('Invalid --curve value. Use "secp256k1" or "ed25519".');
    process.exit(1);
  }

  const policyId = flag(args, "--policy-id");
  const stableId = flag(args, "--stable-id");
  const autoProvision = hasFlag(args, "--auto-provision");
  const cfg = requireConfig();
  let resolvedPolicyId = policyId;

  if (autoProvision && !resolvedPolicyId) {
    const templateId = await promptPolicyTemplateId();
    const templatePayload = buildPolicyTemplatePayload(templateId);
    const stable = stableId ?? `agent-policy-${Date.now()}`;
    const client = getClient();
    const created = await client.createPolicyV4({
      stableId: stable,
      version: "1.0.0",
      allowNamespaces: templatePayload.allowNamespaces,
      rules: templatePayload.rules,
    });
    if (!created.success || !created.policyObjectId?.startsWith("0x")) {
      throw new Error(created.error ?? "Failed to create default policy from template");
    }
    await client.registerPolicyVersionFromPolicy({ policyObjectId: created.policyObjectId });
    resolvedPolicyId = created.policyObjectId;
    console.log(`Created + registered policy ${resolvedPolicyId} using ${templatePayload.template.id}.`);
  }

  const kairo = new KairoClient({
    apiKey: cfg.apiKey,
    backendUrl: cfg.backendUrl,
  });

  const wallet = await kairo.createWallet({
    curve: curveRaw,
    policyObjectId: resolvedPolicyId,
    stableId,
  });
  console.log(JSON.stringify(wallet, null, 2));
  if (!resolvedPolicyId) {
    console.log(
      "Wallet created but not provisioned. To show it in dashboard policies, run: " +
        `kairo vault-provision --wallet-id ${wallet.walletId} --policy-id <policyObjectId> [--stable-id <id>]`,
    );
  }
}

async function cmdRegister(args: string[]) {
  const label = requireFlag(args, "--label", "name");
  const client = getClient();
  const res = await client.register(label);
  console.log(JSON.stringify(res, null, 2));
}

async function cmdPolicyCreate(args: string[]) {
  const stableId = requireFlag(args, "--stable-id", "id");
  const version = flag(args, "--version") ?? "1.0.0";
  const allowRaw = flag(args, "--allow");
  if (!allowRaw) {
    console.error("Required: --allow <comma-separated addresses>");
    process.exit(1);
  }
  const addresses = allowRaw.split(",").map((a) => a.trim());
  const rules = addresses.map((addr) => ({ ruleType: 1, params: addr }));
  const client = getClient();
  const res = await client.createPolicyV4({ stableId, version, rules });
  console.log(JSON.stringify(res, null, 2));
}

async function cmdPolicyRegister(args: string[]) {
  const policyId = requireFlag(args, "--policy-id", "objectId");
  const client = getClient();
  const res = await client.registerPolicyVersionFromPolicy({ policyObjectId: policyId });
  console.log(JSON.stringify(res, null, 2));
}

async function cmdPolicyDetails(args: string[]) {
  const policyId = requireFlag(args, "--policy-id", "objectId");
  const client = getClient();
  const res = await client.getPolicy(policyId);
  console.log(JSON.stringify(res, null, 2));
}

async function cmdVaultStatus(args: string[]) {
  const walletId = requireFlag(args, "--wallet-id", "dwalletId");
  const client = getClient();
  const res = await client.getVaultStatus(walletId);
  console.log(JSON.stringify(res, null, 2));
}

async function cmdVaultProvision(args: string[]) {
  const walletId = requireFlag(args, "--wallet-id", "dwalletId");
  const policyId = requireFlag(args, "--policy-id", "objectId");
  const stableId = flag(args, "--stable-id");
  const cfg = requireConfig();
  const kairo = new KairoClient({
    apiKey: cfg.apiKey,
    backendUrl: cfg.backendUrl,
  });
  const res = await kairo.provision(walletId, policyId, stableId);
  console.log(JSON.stringify(res, null, 2));
}

async function cmdReaffirm(args: string[]) {
  const walletId = requireFlag(args, "--wallet-id", "dwalletId");
  const cfg = requireConfig();
  const kairo = new KairoClient({
    apiKey: cfg.apiKey,
    backendUrl: cfg.backendUrl,
  });
  const res = await kairo.reaffirmBinding(walletId);
  console.log(JSON.stringify(res, null, 2));
}

async function cmdReceiptMint(args: string[]) {
  const policyId = requireFlag(args, "--policy-id", "objectId");
  const bindingId = requireFlag(args, "--binding-id", "objectId");
  const destination = requireFlag(args, "--destination", "hex");
  const intentHash = requireFlag(args, "--intent-hash", "hex");
  const namespace = Number(flag(args, "--namespace") ?? "1");
  const chainId = flag(args, "--chain-id") ?? "0x0aa36a7f";
  const nativeValue = flag(args, "--native-value") ?? ("0x" + "00".repeat(32));
  const client = getClient();
  const res = await client.mintReceipt({
    policyObjectId: policyId,
    bindingObjectId: bindingId,
    namespace,
    chainId,
    intentHashHex: intentHash,
    destinationHex: destination,
    nativeValueHex: nativeValue,
  });
  console.log(JSON.stringify(res, null, 2));
}

async function cmdAudit(args: string[]) {
  const limit = Number(flag(args, "--limit") ?? "10");
  const client = getClient();
  const res = await client.getAuditEvents(limit);
  console.log(JSON.stringify(res, null, 2));
}

async function cmdAuditVerify(args: string[]) {
  const suiIdx = args.indexOf("--sui");
  const bundleIdx = args.indexOf("--bundle");
  if (suiIdx < 0 || bundleIdx < 0) {
    console.error("Usage: kairo audit verify --sui <suiRpcUrl> --bundle <path.json>");
    process.exit(2);
  }
  const suiRpcUrl = String(args[suiIdx + 1] ?? "").trim();
  const bundlePath = String(args[bundleIdx + 1] ?? "").trim();
  if (!suiRpcUrl || !bundlePath) {
    console.error("Usage: kairo audit verify --sui <suiRpcUrl> --bundle <path.json>");
    process.exit(2);
  }
  const raw = readFileSync(bundlePath, "utf8");
  const bundle = JSON.parse(raw);
  const res = await verifyAuditBundle({ suiRpcUrl, bundle });
  if (!res.ok) {
    console.error(res.error);
    process.exit(1);
  }
  console.log("OK");
}

function printUsage(): void {
  console.log(`Kairo CLI — Agent Wallet Operations

Usage: kairo <command> [options]

Setup:
  init <YOUR_KEY> [--backend-url <url>]  Store API key, backend URL, and install skill files

Wallet & Policy:
  health                            Server health check
  wallet-create [--curve secp256k1|ed25519] [--policy-id <id>] [--stable-id <id>] [--auto-provision]
                                    Create a new dWallet via SDK DKG flow
  register --label <name>           Register new API key
  policy-create --stable-id <id> --allow <addrs>  Create policy
  policy-register --policy-id <id>  Register policy version
  policy-details --policy-id <id>   Get policy details
  vault-status --wallet-id <id>     Check vault registration
  vault-provision --wallet-id <id> --policy-id <id> [--stable-id <id>]
  reaffirm --wallet-id <id>         Reaffirm a wallet's current policy binding
  receipt-mint --policy-id <id> --binding-id <id> --destination <hex> --intent-hash <hex>

Utility:
  audit --limit <n>                 List audit events
  audit verify --sui <url> --bundle <path>  Verify audit bundle`);
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  const rest = args.slice(1);

  switch (cmd) {
    case "init":
      return cmdInit(rest);
    case "health":
      return cmdHealth();
    case "wallet-create":
      return cmdWalletCreate(rest);
    case "register":
      return cmdRegister(rest);
    case "policy-create":
      return cmdPolicyCreate(rest);
    case "policy-register":
      return cmdPolicyRegister(rest);
    case "policy-details":
      return cmdPolicyDetails(rest);
    case "vault-status":
      return cmdVaultStatus(rest);
    case "vault-provision":
      return cmdVaultProvision(rest);
    case "reaffirm":
      return cmdReaffirm(rest);
    case "receipt-mint":
      return cmdReceiptMint(rest);
    case "audit":
      if (rest[0] === "verify") return cmdAuditVerify(rest.slice(1));
      return cmdAudit(rest);
    case "--help":
    case "-h":
    case undefined:
      printUsage();
      return;
    default:
      console.error(`Unknown command: ${cmd}`);
      printUsage();
      process.exit(1);
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
