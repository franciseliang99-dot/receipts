// The verifier: deterministic, no model calls, reads only the snapshot store. It re-derives every claim in an
// explanation graph and decides, edge by edge, whether the claim is proved, supported by a verbatim citation,
// or unverified. A verdict passes only if the edges it rests on are proved and V4, V5 and V6 all pass.

import { canonicalize } from "./jcs.ts";
import { resolvePointer } from "./jsonPointer.ts";
import { checkHop, entryName, enumerateInstances, type Instance, type Lockfile } from "./lockfile.ts";
import { isAffected, type OsvAffected } from "./osvRange.ts";
import type { SnapshotStore } from "./snapshot.ts";
import {
  PROJECT_ID,
  type Evidence,
  type ExplanationGraph,
  type GraphEdge,
  type GraphNode,
  type JsonEvidence,
  type QuoteEvidence,
  type TextEvidence,
  type Verdict,
} from "./graph.ts";

export type EdgeStatus = "proved" | "cited" | "unverified";
export type CheckResult = "pass" | "fail" | "undecidable";

export interface EdgeReport {
  status: EdgeStatus;
  reasons: string[];
  decorative?: boolean;
  backup_support?: boolean;
}

export interface VerifyReport {
  schema: "receipts/verify@1";
  edges: Record<string, EdgeReport>;
  checks: Record<"V1" | "V1b" | "V2" | "V3" | "V4" | "V5" | "V6", { result: CheckResult; details: string[] }>;
  verdict: { claimed: Verdict; recomputed: Verdict; verified: boolean; why_not: string[] };
  coverage: { instances: number | null; advisory_groups: number; withdrawn: string[] };
}

export interface AdvisoryRow {
  ghsa_id: string;
  cve_id?: string | null;
  withdrawn_at?: string | null;
  summary?: string;
}

/** Advisory-list snapshot rows (normalised Zetaris query result). */
export function advisoryRows(store: SnapshotStore, sha: string): AdvisoryRow[] | null {
  if (store.meta(sha)?.kind !== "zetaris-query") return null;
  const doc = store.json(sha) as { rows?: unknown } | undefined;
  if (!doc || !Array.isArray(doc.rows)) return null;
  const rows: AdvisoryRow[] = [];
  for (const r of doc.rows) {
    if (!r || typeof r !== "object" || typeof (r as AdvisoryRow).ghsa_id !== "string") return null;
    rows.push(r as AdvisoryRow);
  }
  return rows;
}

export interface OsvRecord {
  id: string;
  aliases?: string[];
  withdrawn?: string;
  summary?: string;
  details?: string;
  affected?: OsvAffected[];
}

/** The OSV record held by an advisory node's record snapshot (first row of a Zetaris query). */
export function osvRecord(store: SnapshotStore, sha: string | undefined): OsvRecord | null {
  if (!sha || store.meta(sha)?.kind !== "zetaris-query") return null;
  const doc = store.json(sha) as { rows?: unknown[] } | undefined;
  const r = doc?.rows?.[0] as OsvRecord | undefined;
  return r && typeof r.id === "string" ? r : null;
}

/** Split text into identifier tokens; used for V1b's whole-word match (`parse` does not match `parser`). */
export function identifiers(text: string): Set<string> {
  return new Set(text.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) ?? []);
}

class UnionFind {
  private p = new Map<string, string>();
  find(x: string): string {
    if (!this.p.has(x)) this.p.set(x, x);
    let r = x;
    while (this.p.get(r) !== r) r = this.p.get(r)!;
    let c = x;
    while (this.p.get(c) !== r) {
      const n = this.p.get(c)!;
      this.p.set(c, r);
      c = n;
    }
    return r;
  }
  union(a: string, b: string) {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.p.set(ra < rb ? rb : ra, ra < rb ? ra : rb);
  }
}

const MAX_MINIMAL_DERIVATIONS = 256;

export function verify(graph: ExplanationGraph, store: SnapshotStore): VerifyReport {
  const checks: VerifyReport["checks"] = {
    V1: { result: "pass", details: [] },
    V1b: { result: "pass", details: [] },
    V2: { result: "pass", details: [] },
    V3: { result: "pass", details: [] },
    V4: { result: "pass", details: [] },
    V5: { result: "pass", details: [] },
    V6: { result: "pass", details: [] },
  };
  const fail = (k: keyof typeof checks, msg: string, how: "fail" | "undecidable" = "fail") => {
    const c = checks[k];
    if (how === "fail") c.result = "fail";
    else if (c.result === "pass") c.result = "undecidable";
    c.details.push(msg);
  };
  const edges: Record<string, EdgeReport> = {};
  const whyNot: string[] = [];

  const q = graph.question;
  const nodes = new Map<string, GraphNode>();
  for (const n of graph.nodes ?? []) {
    if (nodes.has(n.id)) whyNot.push(`duplicate node id ${n.id}`);
    nodes.set(n.id, n);
  }
  const lock = store.json(q?.lockfile ?? "") as Lockfile | undefined;
  const listRows = q ? advisoryRows(store, q.advisory_list) : null;
  if (!lock) whyNot.push(`lockfile snapshot ${store.problem(q?.lockfile ?? "") ?? "is unreadable"}`);
  if (!listRows) whyNot.push(`advisory list snapshot ${(q && store.problem(q.advisory_list)) ?? "has no advisory rows"}`);

  // ---- Package nodes must match the lockfile entry they name (V2, node level).
  const badNode = new Map<string, string>();
  for (const n of nodes.values()) {
    if (n.type === "Advisory") {
      const rec = osvRecord(store, n.record);
      const id = n.id.replace(/^adv:/, "");
      if (!rec) badNode.set(n.id, `advisory ${id} has no readable OSV record snapshot`);
      else if (rec.id !== id) badNode.set(n.id, `record snapshot holds ${rec.id}, not ${id}`);
    }
    if (n.type !== "Package") continue;
    const e = lock?.packages?.[n.install_path ?? "\u0000"];
    if (!e) badNode.set(n.id, `install path ${JSON.stringify(n.install_path)} is not in the lockfile`);
    else if (e.version !== n.version) badNode.set(n.id, `lockfile says ${n.install_path} is ${e.version}, node says ${n.version}`);
    else if (entryName(n.install_path!, e) !== n.name) badNode.set(n.id, `lockfile says ${n.install_path} is ${entryName(n.install_path!, e)}, node says ${n.name}`);
  }
  for (const [id, why] of badNode) fail(id.startsWith("adv:") ? "V1" : "V2", `node ${id}: ${why}`);

  // ---- Alias groups over everything the snapshots say (list rows + every advisory record we hold).
  const uf = new UnionFind();
  const withdrawn = new Set<string>();
  for (const r of listRows ?? []) {
    uf.find(r.ghsa_id);
    if (r.cve_id) uf.union(r.ghsa_id, r.cve_id);
    if (r.withdrawn_at) withdrawn.add(r.ghsa_id);
  }
  for (const n of nodes.values()) {
    if (n.type !== "Advisory" || badNode.has(n.id)) continue;
    const rec = osvRecord(store, n.record)!;
    for (const a of rec.aliases ?? []) uf.union(rec.id, a);
    if (rec.withdrawn) withdrawn.add(rec.id);
  }
  const advId = (nodeId: string) => nodeId.replace(/^adv:/, "");
  const isWithdrawn = (id: string) => withdrawn.has(id);

  // ---- V1 evidence resolution.
  const checkEvidence = (ev: Evidence): string | null => {
    if (!store.has(ev.snapshot)) return `snapshot ${String(ev.snapshot).slice(0, 12)}… does not exist`;
    if ("byte_start" in ev) {
      const t = ev as TextEvidence;
      const b = store.bytes(t.snapshot);
      if (!b) return `snapshot ${t.snapshot.slice(0, 12)}… does not match its hash`;
      if (!Number.isInteger(t.byte_start) || !Number.isInteger(t.byte_end) || t.byte_start < 0 || t.byte_end > b.length || t.byte_start >= t.byte_end) {
        return `byte range [${t.byte_start}, ${t.byte_end}) is outside the snapshot`;
      }
      const got = b.subarray(t.byte_start, t.byte_end);
      if (!got.equals(Buffer.from(t.expected_text, "utf8"))) return `bytes [${t.byte_start}, ${t.byte_end}) are ${JSON.stringify(got.toString("utf8").slice(0, 80))}, not the quoted text`;
      return null;
    }
    const doc = store.json(ev.snapshot);
    if (doc === undefined) return `snapshot ${ev.snapshot.slice(0, 12)}… ${store.problem(ev.snapshot) ?? "is unreadable"}`;
    const r = resolvePointer(doc, ev.pointer);
    if (!r.found) return `pointer ${ev.pointer}: ${r.reason}`;
    if ("quote" in ev) {
      const qe = ev as QuoteEvidence;
      if (typeof r.value !== "string") return `pointer ${qe.pointer} is not text`;
      if (typeof qe.quote !== "string" || qe.quote.length < 3) return `quote is empty`;
      if (!r.value.includes(qe.quote)) return `quote ${JSON.stringify(qe.quote.slice(0, 80))} does not occur at ${qe.pointer}`;
      return null;
    }
    const je = ev as JsonEvidence;
    if (canonicalize(r.value) !== canonicalize(je.expected)) {
      return `value at ${je.pointer} is ${canonicalize(r.value).slice(0, 80)}, not ${canonicalize(je.expected).slice(0, 80)}`;
    }
    return null;
  };

  const evidenceOn = (e: GraphEdge, sha: string | undefined) => !!sha && e.evidence.some((ev) => ev.snapshot === sha);

  // ---- Per-edge checks.
  for (const e of graph.edges ?? []) {
    const reasons: string[] = [];
    let status: EdgeStatus = "proved";
    if (edges[e.id]) reasons.push(`duplicate edge id ${e.id}`);
    const from = nodes.get(e.from);
    const to = nodes.get(e.to);
    if (!from || !to) reasons.push(`edge endpoints must be nodes (${e.from} → ${e.to})`);
    if (!Array.isArray(e.evidence) || e.evidence.length === 0) reasons.push("edge has no evidence");
    for (const ev of e.evidence ?? []) {
      const err = checkEvidence(ev);
      if (err) {
        reasons.push(`V1: ${err}`);
        fail("V1", `${e.id}: ${err}`);
      }
    }
    let endpointsOk = !!from && !!to;
    for (const n of [from, to]) {
      if (n && badNode.has(n.id)) {
        reasons.push(`endpoint ${n.id}: ${badNode.get(n.id)}`);
        endpointsOk = false;
      }
    }

    // Semantic checks run even when evidence failed V1, so the report names the underlying fault too.
    if (from && to && endpointsOk) {
      switch (e.type) {
        case "DEPENDS_ON": {
          const fromPath = from.id === PROJECT_ID ? "" : from.install_path;
          if ((from.type !== "Project" && from.type !== "Package") || to.type !== "Package" || fromPath === undefined) {
            reasons.push("DEPENDS_ON must go from the project or a package to a package");
            break;
          }
          if (!evidenceOn(e, q.lockfile)) reasons.push("DEPENDS_ON must cite the lockfile snapshot");
          const err = lock ? checkHop(lock, fromPath, to.install_path!) : "no lockfile";
          if (err) {
            reasons.push(`V2: ${err}`);
            fail("V2", `${e.id}: ${err}`);
          }
          break;
        }
        case "MATCHES": {
          if (from.type !== "Package" || to.type !== "Advisory") {
            reasons.push("MATCHES must go from a package to an advisory");
            break;
          }
          const id = advId(to.id);
          if (from.name !== q.package) reasons.push(`the advisory list was queried for ${q.package}, not ${from.name}`);
          if (!listRows?.some((r) => r.ghsa_id === id)) reasons.push(`${id} is not in the advisory list snapshot`);
          if (!evidenceOn(e, q.advisory_list)) reasons.push("MATCHES must cite the advisory list snapshot");
          const rec = osvRecord(store, to.record);
          if (!rec?.affected?.some((a) => a.package?.name === from.name && a.package?.ecosystem === "npm")) {
            reasons.push(`the OSV record of ${id} has no npm/${from.name} entry`);
          }
          break;
        }
        case "IN_RANGE":
        case "OUT_OF_RANGE":
        case "RANGE_UNKNOWN": {
          if (from.type !== "Package" || to.type !== "Advisory") {
            reasons.push(`${e.type} must go from a package to an advisory`);
            break;
          }
          const id = advId(to.id);
          if (isWithdrawn(id)) {
            reasons.push(`V3: ${id} is withdrawn and cannot carry a range verdict`);
            fail("V3", `${e.id}: ${id} is withdrawn`);
            break;
          }
          if (!evidenceOn(e, q.lockfile) || !evidenceOn(e, to.record)) reasons.push(`${e.type} must cite both the lockfile and the advisory record`);
          const rec = osvRecord(store, to.record)!;
          const res = isAffected(from.version!, from.name!, rec.affected ?? []);
          const want = res.kind === "in" ? "IN_RANGE" : res.kind === "out" ? "OUT_OF_RANGE" : "RANGE_UNKNOWN";
          if (want !== e.type) {
            const msg = `${from.name}@${from.version} vs ${id}: recomputed ${want}${res.kind === "undecidable" ? ` (${res.reason})` : ""}, claimed ${e.type}`;
            reasons.push(`V3: ${msg}`);
            fail("V3", `${e.id}: ${msg}`);
          } else if (res.kind === "undecidable") {
            checks.V3.details.push(`${e.id}: undecidable, ${res.reason}`);
          }
          break;
        }
        case "ALIAS_OF": {
          if (from.type !== "Advisory" || to.type !== "Advisory") reasons.push("ALIAS_OF must join two advisories");
          else if (uf.find(advId(from.id)) !== uf.find(advId(to.id))) reasons.push(`${advId(from.id)} and ${advId(to.id)} are not aliases in any snapshot`);
          break;
        }
        case "WITHDRAWN": {
          if (from.type !== "Advisory") reasons.push("WITHDRAWN must start at an advisory");
          else if (!isWithdrawn(advId(from.id))) reasons.push(`${advId(from.id)} is not withdrawn in any snapshot`);
          break;
        }
        case "NAMES_SYMBOL":
        case "REFERENCES": {
          const sym = to;
          if (sym.type !== "Symbol" || !sym.symbol) {
            reasons.push(`${e.type} must point at a symbol`);
            break;
          }
          if (e.type === "NAMES_SYMBOL" && (from.type !== "Advisory" || !e.evidence.every((ev) => "quote" in ev && ev.snapshot === from.record))) {
            reasons.push("NAMES_SYMBOL must quote the advisory's own record");
            break;
          }
          if (e.type === "REFERENCES" && (from.type !== "CodeSite" || !e.evidence.every((ev) => "byte_start" in ev))) {
            reasons.push("REFERENCES must quote source bytes from a code site");
            break;
          }
          const texts = e.evidence.map((ev) => ("quote" in ev ? ev.quote : (ev as TextEvidence).expected_text));
          const base = sym.symbol.split(".").pop()!;
          if (!texts.some((t) => identifiers(t).has(base))) {
            reasons.push(`V1b: the cited text does not contain the identifier ${base}`);
            fail("V1b", `${e.id}: cited text does not name ${base}`);
          }
          status = "cited";
          break;
        }
        default:
          reasons.push(`unknown edge type ${String(e.type)}`);
      }
    }
    if (reasons.length) status = "unverified";
    edges[e.id] = { status, reasons };
  }

  // ---- V2 / V6: instance enumeration and coverage.
  let instances: Instance[] | null = null;
  if (lock) {
    const en = enumerateInstances(lock, q.package);
    if (en.ok) instances = en.instances;
    else fail("V2", `cannot enumerate ${q.package}: ${en.reason}`, "undecidable");
  }
  const pkgNodeFor = new Map<string, GraphNode>();
  for (const n of nodes.values()) if (n.type === "Package" && n.name === q.package && n.install_path) pkgNodeFor.set(n.install_path, n);
  if (instances) {
    for (const i of instances) if (!pkgNodeFor.has(i.path)) fail("V6", `instance ${i.path}@${i.version} has no node in the graph`);
    for (const p of pkgNodeFor.keys()) if (!instances.some((i) => i.path === p)) fail("V2", `graph names an instance ${p} that the lockfile does not have`);
  } else {
    fail("V6", "instance set is undecidable, so coverage cannot be shown", "undecidable");
  }

  const groups = new Map<string, string[]>(); // live (non-withdrawn) alias groups from the list snapshot
  for (const r of listRows ?? []) {
    if (isWithdrawn(r.ghsa_id)) continue;
    const g = uf.find(r.ghsa_id);
    groups.set(g, [...(groups.get(g) ?? []), r.ghsa_id]);
  }
  const rangeEdges = (graph.edges ?? []).filter((e) => ["IN_RANGE", "OUT_OF_RANGE", "RANGE_UNKNOWN"].includes(e.type) && edges[e.id]?.status === "proved");
  if (instances) {
    for (const i of instances) {
      const node = pkgNodeFor.get(i.path);
      if (!node) continue;
      for (const [g, ids] of groups) {
        const hit = rangeEdges.some((e) => e.from === node.id && uf.find(advId(e.to)) === g);
        if (!hit) fail("V6", `no verified range verdict for ${i.path}@${i.version} against ${ids.join(" / ")}`);
      }
    }
  }
  for (const r of listRows ?? []) {
    if (!r.withdrawn_at) continue;
    const ok = (graph.edges ?? []).some((e) => e.type === "WITHDRAWN" && advId(e.from) === r.ghsa_id && edges[e.id]?.status === "proved");
    if (!ok) fail("V6", `withdrawn advisory ${r.ghsa_id} is not recorded with a WITHDRAWN edge`);
  }

  // ---- V4: recompute the verdict from the derivation's own edges.
  const d = graph.derivation;
  const listed = new Map<string, GraphEdge>();
  for (const id of d?.edges ?? []) {
    const e = (graph.edges ?? []).find((x) => x.id === id);
    if (!e) {
      fail("V4", `derivation names edge ${id}, which does not exist`);
      continue;
    }
    if (edges[id].status !== "proved") {
      fail("V4", `derivation rests on ${id}, which is ${edges[id].status}`);
      continue;
    }
    listed.set(id, e);
  }
  const instanceIds = new Set([...pkgNodeFor.values()].map((n) => n.id));

  const chains = (target: string, use: Map<string, GraphEdge>): string[][] => {
    // every simple DEPENDS_ON path from the project to `target`, as lists of edge ids
    const out: string[][] = [];
    const walk = (node: string, path: string[], seen: Set<string>) => {
      if (out.length > MAX_MINIMAL_DERIVATIONS) return;
      if (node === PROJECT_ID) {
        out.push([...path]);
        return;
      }
      for (const e of use.values()) {
        if (e.type !== "DEPENDS_ON" || e.to !== node || seen.has(e.from)) continue;
        seen.add(e.from);
        walk(e.from, [e.id, ...path], seen);
        seen.delete(e.from);
      }
    };
    walk(target, [], new Set([target]));
    return out;
  };

  const r1Sets = (use: Map<string, GraphEdge>): string[][] => {
    const sets: string[][] = [];
    for (const e of use.values()) {
      if (e.type !== "IN_RANGE" || !instanceIds.has(e.from) || isWithdrawn(advId(e.to))) continue;
      const m = [...use.values()].find((x) => x.type === "MATCHES" && x.from === e.from && x.to === e.to);
      if (!m) continue;
      for (const c of chains(e.from, use)) sets.push([e.id, m.id, ...c]);
    }
    return sets;
  };
  const r2Holds = (use: Map<string, GraphEdge>): boolean => {
    if (!d?.premise_instances_complete || !instances || checks.V2.result !== "pass") return false;
    if (instances.some((i) => !pkgNodeFor.has(i.path))) return false;
    for (const i of instances) {
      const node = pkgNodeFor.get(i.path)!;
      for (const g of groups.keys()) {
        const ok = [...use.values()].some((e) => e.type === "OUT_OF_RANGE" && e.from === node.id && uf.find(advId(e.to)) === g);
        if (!ok) return false;
      }
    }
    return true;
  };
  const recompute = (use: Map<string, GraphEdge>): Verdict => (r1Sets(use).length > 0 ? "affected" : r2Holds(use) ? "not_affected" : "unknown");

  const recomputed = recompute(listed);
  const claimed = d?.verdict ?? "unknown";
  const ruleFor: Record<Verdict, string> = { affected: "R1", not_affected: "R2", unknown: "R3" };
  if (claimed !== recomputed) fail("V4", `claimed ${claimed}, but the derivation's edges give ${recomputed}`);
  if (d && d.rule !== ruleFor[claimed]) fail("V4", `verdict ${claimed} must use rule ${ruleFor[claimed]}, not ${d.rule}`);

  // ---- V5: counterfactual ablation over the verdict edges only.
  if (checks.V4.result === "pass" && recomputed === "affected") {
    const sets = r1Sets(listed);
    if (sets.length > MAX_MINIMAL_DERIVATIONS) fail("V5", "too many derivations to enumerate", "undecidable");
    else {
      const minimal = sets.filter((s) => !sets.some((t) => t !== s && t.length < s.length && t.every((x) => s.includes(x))));
      for (const id of listed.keys()) {
        const n = minimal.filter((s) => s.includes(id)).length;
        if (n === 0) {
          edges[id].decorative = true;
          fail("V5", `${id} is decorative: the verdict does not depend on it`);
        } else if (n < minimal.length) edges[id].backup_support = true;
      }
    }
  } else if (checks.V4.result === "pass" && recomputed === "not_affected") {
    for (const id of listed.keys()) {
      const without = new Map(listed);
      without.delete(id);
      if (recompute(without) === "not_affected") {
        edges[id].decorative = true;
        fail("V5", `${id} is decorative: removing it leaves the verdict unchanged`);
      }
    }
  }

  if (recomputed === "unknown" && claimed === "unknown") whyNot.push("the verdict is unknown");
  for (const k of ["V4", "V5", "V6"] as const) if (checks[k].result !== "pass") whyNot.push(`${k} ${checks[k].result}: ${checks[k].details[0] ?? ""}`);
  // V2 blocks every verdict: a node that misnames its lockfile entry can carry a false "affected" chain.
  if (checks.V2.result !== "pass") whyNot.push(`V2 ${checks.V2.result}: ${checks.V2.details[0] ?? ""}`);
  const verified = whyNot.length === 0 && claimed === recomputed && claimed !== "unknown";

  return {
    schema: "receipts/verify@1",
    edges,
    checks,
    verdict: { claimed, recomputed, verified, why_not: whyNot },
    coverage: { instances: instances?.length ?? null, advisory_groups: groups.size, withdrawn: [...withdrawn].sort() },
  };
}
