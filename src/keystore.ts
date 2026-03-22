/**
 * Local file-based key store for agent secret shares.
 *
 * Stores one JSON file per wallet in `storePath`.
 * The agent's secret key share NEVER leaves this directory.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, unlinkSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";

export interface WalletRecord {
  walletId: string;
  dWalletCapId?: string;
  address: string;
  curve: string;
  seed: number[];
  userSecretKeyShare: number[];
  userPublicOutput: number[];
  encryptedUserSecretKeyShareId: string;
  bindingObjectId?: string;
  policyObjectId?: string;
  createdAt: number;
}

function defaultStorePath(): string {
  return join(homedir(), ".kairo", "keys");
}

function sanitizeId(walletId: string): string {
  return walletId.replace(/[^a-zA-Z0-9_-]/g, "_");
}

export class KeyStore {
  private dir: string;

  constructor(storePath?: string) {
    this.dir = resolve(storePath ?? defaultStorePath());
    if (!existsSync(this.dir)) {
      mkdirSync(this.dir, { recursive: true });
    }
  }

  private filePath(walletId: string): string {
    return join(this.dir, `${sanitizeId(walletId)}.json`);
  }

  save(record: WalletRecord): void {
    writeFileSync(this.filePath(record.walletId), JSON.stringify(record, null, 2), "utf-8");
  }

  load(walletId: string): WalletRecord | null {
    const fp = this.filePath(walletId);
    if (!existsSync(fp)) return null;
    return JSON.parse(readFileSync(fp, "utf-8")) as WalletRecord;
  }

  list(): WalletRecord[] {
    const files = readdirSync(this.dir).filter((f) => f.endsWith(".json"));
    return files.map((f) => {
      const raw = readFileSync(join(this.dir, f), "utf-8");
      return JSON.parse(raw) as WalletRecord;
    });
  }

  delete(walletId: string): boolean {
    const fp = this.filePath(walletId);
    if (!existsSync(fp)) return false;
    unlinkSync(fp);
    return true;
  }

  has(walletId: string): boolean {
    return existsSync(this.filePath(walletId));
  }
}
