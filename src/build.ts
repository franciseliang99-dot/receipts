// Turns the investigator's compact claims into an explanation graph with evidence pointers. Deterministic.
// It attaches pointers to wherever the claims say the facts are; it does not check whether the claims are true.
// That is the verifier's job, so a wrong claim here becomes a failing edge there, never a silent fix.

import { pointerOf } from "./jsonPointer.ts";
import { hopField, nameFromPath, type Lockfile } from "./lockfile.ts";
import type { AdvisoryRow, OsvRecord } from "./verifier.ts";
import {
  PROJECT_ID,
  advNodeId,
  pkgNodeId,
  type Derivation,
  type EdgeType,
  type ExplanationGraph,
  type GraphEdge,
  type GraphNode,
  type Question,
  type Verdict,
} from "./graph.ts";

export interface Catalog {
  question: Question;
  lock: Lockfile;
  rows: AdvisoryRow[];
  records: Record<string, { sha: string; record: OsvRecord }>; // by advisory id
  sources?: Record<string, { sha: string; text: string }>; // by repo-relative file path
}

export interface Claims {
  verdict: Verdict;
  instances: { path: string; dependency_path: string[] }[];
  assessments: { instance: string; advisory: string; status: "IN_RANGE" | "OUT_OF_RANGE" | "RANGE_UNKNOWN" }[];
  withdrawn?: string[];
  symbols?: { advisory: string; symbol: string; quote: string; field?: "details" | "summary" }[];
  code_sites?: { file: string; line: number; symbol: string }[];
  /** For "affected": which (instance, advisory) pairs the conclusion rests on. Ignored for other verdicts. */
  because?: { instance: string; advisory: string }[];
}

export const depEdgeId = (from: string, to: string) => `dep:${from || "<root>"}>${to}`;
export const matchEdgeId = (inst: string, adv: string) => `match:${inst}|${adv}`;
export const rangeEdgeId = (inst: string, adv: string) => `range:${inst}|${adv}`;

export function buildGraph(cat: Catalog, claims: Claims): ExplanationGraph {
  const q = cat.question;
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  nodes.set(PROJECT_ID, { id: PROJECT_ID, type: "Project", label: cat.lock.name ?? "project" });

  const pkgNode = (path: string): string => {
    const id = pkgNodeId(path);
    if (!nodes.has(id)) {
      const e = cat.lock.packages?.[path];
      nodes.set(id, {
        id,
        type: "Package",
        name: (e?.name as string | undefined) ?? nameFromPath(path) ?? path,
        version: e?.version,
        install_path: path,
        dev: !!(e?.dev || e?.devOptional),
        optional: !!(e?.optional || e?.devOptional),
      });
    }
    return id;
  };
  const advNode = (id: string): string => {
    const nid = advNodeId(id);
    if (!nodes.has(nid)) nodes.set(nid, { id: nid, type: "Advisory", label: id, record: cat.records[id]?.sha });
    return nid;
  };
  const rowIndex = (id: string) => cat.rows.findIndex((r) => r.ghsa_id === id);

  const chainOf = new Map<string, string[]>();
  for (const inst of claims.instances) {
    pkgNode(inst.path);
    const ids: string[] = [];
    const p = inst.dependency_path;
    for (let i = 0; i + 1 < p.length; i++) {
      const from = p[i];
      const to = p[i + 1];
      const fromId = from === "" ? PROJECT_ID : pkgNode(from);
      const toId = pkgNode(to);
      const field = hopField(cat.lock, from, to) ?? "dependencies";
      const key = nameFromPath(to) ?? to;
      const spec = (cat.lock.packages?.[from] as Record<string, Record<string, string>> | undefined)?.[field]?.[key] ?? null;
      const id = depEdgeId(from, to);
      edges.set(id, { id, type: "DEPENDS_ON", from: fromId, to: toId, evidence: [{ snapshot: q.lockfile, pointer: pointerOf(["packages", from, field, key]), expected: spec }] });
      ids.push(id);
    }
    chainOf.set(inst.path, ids);
  }

  for (const a of claims.assessments) {
    const from = pkgNode(a.instance);
    const to = advNode(a.advisory);
    const ri = rowIndex(a.advisory);
    const mid = matchEdgeId(a.instance, a.advisory);
    edges.set(mid, {
      id: mid,
      type: "MATCHES",
      from,
      to,
      evidence: [{ snapshot: q.advisory_list, pointer: pointerOf(["rows", Math.max(ri, 0), "ghsa_id"]), expected: a.advisory }],
    });
    const rec = cat.records[a.advisory];
    const rid = rangeEdgeId(a.instance, a.advisory);
    edges.set(rid, {
      id: rid,
      type: a.status as EdgeType,
      from,
      to,
      evidence: [
        { snapshot: q.lockfile, pointer: pointerOf(["packages", a.instance, "version"]), expected: cat.lock.packages?.[a.instance]?.version ?? null },
        { snapshot: rec?.sha ?? "missing", pointer: "/rows/0/affected", expected: rec?.record.affected ?? null },
      ],
    });
  }

  for (const id of claims.withdrawn ?? []) {
    const nid = advNode(id);
    const ri = rowIndex(id);
    const eid = `withdrawn:${id}`;
    edges.set(eid, {
      id: eid,
      type: "WITHDRAWN",
      from: nid,
      to: nid,
      evidence: [{ snapshot: q.advisory_list, pointer: pointerOf(["rows", Math.max(ri, 0), "withdrawn_at"]), expected: cat.rows[ri]?.withdrawn_at ?? null }],
    });
  }

  for (const s of claims.symbols ?? []) {
    const from = advNode(s.advisory);
    const sid = `sym:${s.symbol}`;
    if (!nodes.has(sid)) nodes.set(sid, { id: sid, type: "Symbol", symbol: s.symbol, label: s.symbol });
    const eid = `names:${s.advisory}|${s.symbol}`;
    edges.set(eid, {
      id: eid,
      type: "NAMES_SYMBOL",
      from,
      to: sid,
      evidence: [{ snapshot: cat.records[s.advisory]?.sha ?? "missing", pointer: `/rows/0/${s.field ?? "details"}`, quote: s.quote }],
    });
  }

  for (const c of claims.code_sites ?? []) {
    const src = cat.sources?.[c.file];
    const sid = `sym:${c.symbol}`;
    if (!nodes.has(sid)) nodes.set(sid, { id: sid, type: "Symbol", symbol: c.symbol, label: c.symbol });
    const cid = `site:${c.file}:${c.line}`;
    nodes.set(cid, { id: cid, type: "CodeSite", file: c.file, line: c.line, label: `${c.file}:${c.line}` });
    let start = 0;
    let end = 0;
    let text = "";
    if (src) {
      const buf = Buffer.from(src.text, "utf8");
      let line = 1;
      for (let i = 0; i < buf.length && line < c.line; i++) if (buf[i] === 0x0a) (line++, (start = i + 1));
      end = buf.indexOf(0x0a, start);
      if (end < 0) end = buf.length;
      text = buf.subarray(start, end).toString("utf8");
    }
    const eid = `refs:${c.file}:${c.line}|${c.symbol}`;
    edges.set(eid, { id: eid, type: "REFERENCES", from: cid, to: sid, evidence: [{ snapshot: src?.sha ?? "missing", byte_start: start, byte_end: end, expected_text: text }] });
  }

  let derivation: Derivation;
  if (claims.verdict === "affected") {
    const use = new Set<string>();
    for (const b of claims.because ?? []) {
      use.add(rangeEdgeId(b.instance, b.advisory));
      use.add(matchEdgeId(b.instance, b.advisory));
      for (const id of chainOf.get(b.instance) ?? []) use.add(id);
    }
    derivation = { verdict: "affected", rule: "R1", edges: [...use] };
  } else if (claims.verdict === "not_affected") {
    derivation = {
      verdict: "not_affected",
      rule: "R2",
      edges: claims.assessments.filter((a) => a.status === "OUT_OF_RANGE").map((a) => rangeEdgeId(a.instance, a.advisory)),
      premise_instances_complete: true,
    };
  } else {
    derivation = { verdict: "unknown", rule: "R3", edges: [] };
  }

  return { schema: "receipts/graph@1", question: q, nodes: [...nodes.values()], edges: [...edges.values()], derivation };
}
