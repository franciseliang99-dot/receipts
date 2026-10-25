// Zetaris is the investigator's data plane. Public advisory sources are registered as Zetaris REST tables
// (GitHub Advisory Database per package, OSV.dev per advisory) and read with SQL over the Zetaris REST API.
// Every query's SQL and result go into the snapshot store; the verifier never calls Zetaris.

import { randomUUID, createHash } from "node:crypto";
import { need } from "./config.ts";
import type { SnapshotStore } from "./snapshot.ts";

export interface QueryResult {
  sql: string;
  rows: unknown[];
  raw: string;
}

export class Zetaris {
  readonly base = need("ZETARIS_REST_URL").replace(/\/$/, "");
  private readonly key = need("ZETARIS_API_KEY");
  private readonly org = need("ZETARIS_ORG_ID");
  readonly log: { sql: string; ms: number; status: number }[] = [];

  async run(sql: string, limit = 1000): Promise<{ status: number; text: string; json?: { data?: unknown[][] } }> {
    const t0 = Date.now();
    const res = await fetch(`${this.base}/sql-editor/sqls/run`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.key}`,
        "X-Org-ID": this.org,
        "X-Request-ID": randomUUID(),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ queryId: randomUUID(), sql, source: "SqlEditor", limit }),
      signal: AbortSignal.timeout(300_000),
    });
    const text = await res.text();
    this.log.push({ sql, ms: Date.now() - t0, status: res.status });
    let json: { data?: unknown[][] } | undefined;
    try {
      json = JSON.parse(text);
    } catch {
      /* not JSON */
    }
    return { status: res.status, text, json };
  }

  private async exec(sql: string): Promise<void> {
    const r = await this.run(sql);
    if (r.status !== 200 && !/already exists/i.test(r.text)) throw new Error(`Zetaris: ${sql.split("\n")[0]} -> ${r.status} ${r.text.slice(0, 200)}`);
  }

  /** Register a GET endpoint as a Lightning REST table if it is not there yet. */
  async ensureRestTable(db: string, table: string, endpoint: string): Promise<void> {
    const probe = await this.run(`SELECT 1 FROM ${db}.${table} LIMIT 1`, 1);
    if (probe.status === 200) return;
    if (!/TABLE_OR_VIEW_NOT_FOUND|cannot be found|not found/i.test(probe.text)) throw new Error(`Zetaris: probing ${db}.${table} -> ${probe.status} ${probe.text.slice(0, 200)}`);
    await this.exec(`CREATE LIGHTNING DATABASE ${db.toUpperCase()} DESCRIBE BY "public advisory source"`).catch(() => undefined);
    await this.exec(
      `CREATE LIGHTNING REST TABLE ${table} FROM ${db.toUpperCase()} REQUEST(\n endpoint "${endpoint}",\n method "get",\n response_type "json",\n http_encoding "URLENCODED"\n) HEADER (\n) BODY (\n)`,
    );
  }

  /** Run a query whose single column is a JSON string per row, snapshot it, and return the parsed rows. */
  async snapshotQuery(store: SnapshotStore, sql: string, endpoint: string): Promise<{ sha: string; rows: unknown[] }> {
    const r = await this.run(sql);
    if (r.status !== 200 || !r.json) throw new Error(`Zetaris: query failed ${r.status} ${r.text.slice(0, 200)}`);
    const rawSha = store.put(r.text, { kind: "zetaris-response", media: "json", source: "zetaris", sql });
    const rows = (r.json.data ?? []).map((row) => JSON.parse(String(row[0])));
    const sha = store.put(JSON.stringify({ engine: "zetaris", sql, endpoint, rows }, null, 1), {
      kind: "zetaris-query",
      media: "json",
      source: "zetaris",
      sql,
      derived_from: rawSha,
    });
    return { sha, rows };
  }
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
const short = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 8);

/** GitHub Advisory Database: every advisory that names this npm package. */
export async function queryAdvisoryList(z: Zetaris, store: SnapshotStore, pkg: string) {
  const table = `npm_${slug(pkg)}_${short(pkg)}`;
  const endpoint = `https://api.github.com/advisories?ecosystem=npm&affects=${encodeURIComponent(pkg)}&per_page=100`;
  await z.ensureRestTable("ghsa_rest", table, endpoint);
  return z.snapshotQuery(store, `SELECT to_json(struct(*)) AS row FROM ghsa_rest.${table} ORDER BY ghsa_id`, endpoint);
}

/** OSV.dev: the machine-readable record (ranges, aliases, withdrawn) of one advisory. */
export async function queryOsvRecord(z: Zetaris, store: SnapshotStore, id: string) {
  const table = `rec_${slug(id)}`;
  const endpoint = `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`;
  await z.ensureRestTable("osv_rest", table, endpoint);
  return z.snapshotQuery(store, `SELECT to_json(struct(*)) AS row FROM osv_rest.${table}`, endpoint);
}
