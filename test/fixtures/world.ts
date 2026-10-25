// A small, fully offline world for verifier tests: one lockfile, one advisory-list query result and three OSV
// records, shaped like the real minimist data returned through Zetaris (GHSA-xvch-5gv4-984h, GHSA-vh95-rmgr-6w4m,
// and the withdrawn GHSA-7fhm-mqm4-2wp7).
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SnapshotStore } from "../../src/snapshot.ts";
import type { Catalog } from "../../src/build.ts";
import type { Lockfile } from "../../src/lockfile.ts";
import type { OsvRecord, AdvisoryRow } from "../../src/verifier.ts";

export const LOCK: Lockfile = {
  name: "demo",
  lockfileVersion: 3,
  packages: {
    "": { name: "demo", dependencies: { mkdirp: "^0.5.5", optimist: "^0.6.1" } },
    "node_modules/mkdirp": { version: "0.5.5", dependencies: { minimist: "^1.2.5" } },
    "node_modules/mkdirp/node_modules/minimist": { version: "1.2.5" },
    "node_modules/optimist": { version: "0.6.1", dependencies: { minimist: "~0.0.1" } },
    "node_modules/optimist/node_modules/minimist": { version: "0.0.10" },
  },
};

export const ROWS: AdvisoryRow[] = [
  { ghsa_id: "GHSA-xvch-5gv4-984h", cve_id: "CVE-2021-44906", summary: "Prototype Pollution in minimist" },
  { ghsa_id: "GHSA-vh95-rmgr-6w4m", cve_id: "CVE-2020-7598", summary: "Prototype Pollution in minimist" },
  { ghsa_id: "GHSA-7fhm-mqm4-2wp7", withdrawn_at: "2020-04-03T21:47:06Z", summary: "Withdrawn advisory" },
];

const npm = (name: string) => ({ ecosystem: "npm", name, purl: `pkg:npm/${name}` });
export const RECORDS: OsvRecord[] = [
  {
    id: "GHSA-xvch-5gv4-984h",
    aliases: ["CVE-2021-44906"],
    details: "Minimist prior to 1.2.6 and 0.2.4 is vulnerable to Prototype Pollution via file `index.js`, function `setKey()` (lines 69-95).",
    affected: [
      { package: npm("minimist"), ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "1.2.6" }] }] },
      { package: npm("minimist"), ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.2.4" }] }] },
    ],
  },
  {
    id: "GHSA-vh95-rmgr-6w4m",
    aliases: ["CVE-2020-7598"],
    details: "Affected versions of `minimist` are vulnerable to prototype pollution.",
    affected: [
      { package: npm("minimist"), ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.2.1" }] }] },
      { package: npm("minimist"), ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "1.2.3" }] }] },
    ],
  },
  {
    id: "GHSA-7fhm-mqm4-2wp7",
    withdrawn: "2020-04-03T21:47:06Z",
    details: "Withdrawn.",
    affected: [{ package: npm("minimist"), ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.2" }] }] }],
  },
];

export function makeWorld(opts: { lock?: Lockfile; rows?: AdvisoryRow[]; records?: OsvRecord[] } = {}) {
  const store = new SnapshotStore(mkdtempSync(join(tmpdir(), "receipts-test-")));
  const lock = opts.lock ?? LOCK;
  const lockSha = store.put(JSON.stringify(lock, null, 2), { kind: "lockfile", media: "json", source: "package-lock.json" });
  const rows = opts.rows ?? ROWS;
  const listSha = store.put(JSON.stringify({ engine: "zetaris", sql: "SELECT … FROM ghsa_rest.npm_minimist", rows }), {
    kind: "zetaris-query",
    media: "json",
    source: "zetaris",
  });
  const records: Catalog["records"] = {};
  for (const r of opts.records ?? RECORDS) {
    const sha = store.put(JSON.stringify({ engine: "zetaris", sql: `SELECT … FROM osv_rest.${r.id}`, rows: [r] }), { kind: "zetaris-query", media: "json", source: "zetaris" });
    records[r.id] = { sha, record: r };
  }
  const cat: Catalog = { question: { package: "minimist", ecosystem: "npm", lockfile: lockSha, advisory_list: listSha }, lock, rows, records };
  return { store, cat };
}

export const MKDIRP_PATH = ["", "node_modules/mkdirp", "node_modules/mkdirp/node_modules/minimist"];
export const OPTIMIST_PATH = ["", "node_modules/optimist", "node_modules/optimist/node_modules/minimist"];
