// Content-addressed snapshot store. Every fetch the investigator makes is written here first; the verifier reads
// only from here, never from the network, so the same inputs always give the same verdict and can be replayed offline.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

export type SnapshotKind = "lockfile" | "zetaris-query" | "zetaris-response" | "source-file";

export interface SnapshotMeta {
  sha256: string;
  kind: SnapshotKind;
  media: "json" | "text";
  source: string; // where it came from: a file path relative to the target repo, or "zetaris"
  fetched_at: string; // ISO time
  sql?: string; // for zetaris-query
  derived_from?: string; // sha256 of the raw response a normalised query snapshot was built from
}

export function sha256(bytes: Buffer | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export class SnapshotStore {
  readonly dir: string;
  constructor(dir: string) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true });
  }

  put(bytes: Buffer | string, meta: Omit<SnapshotMeta, "sha256" | "fetched_at"> & { fetched_at?: string }): string {
    const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, "utf8");
    const h = sha256(buf);
    const full: SnapshotMeta = { ...meta, sha256: h, fetched_at: meta.fetched_at ?? new Date().toISOString() };
    const bin = join(this.dir, `${h}.bin`);
    if (!existsSync(bin)) writeFileSync(bin, buf);
    const metaPath = join(this.dir, `${h}.meta.json`);
    if (!existsSync(metaPath)) writeFileSync(metaPath, JSON.stringify(full, null, 2) + "\n");
    return h;
  }

  has(h: string): boolean {
    return /^[0-9a-f]{64}$/.test(h) && existsSync(join(this.dir, `${h}.bin`));
  }

  /** Raw bytes, re-hashed on every read: a snapshot file edited after the fact is reported, not trusted. */
  bytes(h: string): Buffer | null {
    if (!this.has(h)) return null;
    const b = readFileSync(join(this.dir, `${h}.bin`));
    return sha256(b) === h ? b : null;
  }

  /** Why a snapshot cannot be used: missing, altered after it was stored, or not JSON. null if it reads fine. */
  problem(h: string, asJson = true): string | null {
    if (!this.has(h)) return "is missing";
    if (!this.bytes(h)) return "was altered after it was stored (its bytes no longer hash to its name)";
    if (asJson && this.json(h) === undefined) return "is not JSON";
    return null;
  }

  meta(h: string): SnapshotMeta | null {
    if (!this.has(h)) return null;
    try {
      return JSON.parse(readFileSync(join(this.dir, `${h}.meta.json`), "utf8")) as SnapshotMeta;
    } catch {
      return null;
    }
  }

  json(h: string): unknown | undefined {
    const b = this.bytes(h);
    if (!b) return undefined;
    try {
      return JSON.parse(b.toString("utf8"));
    } catch {
      return undefined;
    }
  }

  list(): string[] {
    return readdirSync(this.dir).filter((f) => f.endsWith(".bin")).map((f) => f.slice(0, -4));
  }
}
