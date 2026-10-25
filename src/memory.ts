// Receipts' memory, built on the Meterless H-MEM engine (vendor/hmem). Only facts the verifier proved are written.
// Recalled memories are hints for the model, never evidence: the verifier re-checks everything against this run's
// snapshots, and each recalled fact gets H-MEM feedback from that check (agreed -> helpful, contradicted -> wrong).

import { HMEM, type MemoryRecord } from "../vendor/hmem/src/index.ts";
import type { VerifyReport } from "./verifier.ts";
import type { ExplanationGraph } from "./graph.ts";

export type RangeStatus = "IN_RANGE" | "OUT_OF_RANGE";

/** A machine-readable fact carried in a memory's tags: `fact:range|<pkg>@<version>|<advisory>|<status>`. */
export interface RangeFact {
  pkg: string;
  version: string;
  advisory: string;
  status: RangeStatus;
}

const FACT_PREFIX = "fact:range|";
const factTag = (f: RangeFact) => `${FACT_PREFIX}${f.pkg}@${f.version}|${f.advisory}|${f.status}`;

export function parseFactTag(tag: string): RangeFact | null {
  if (!tag.startsWith(FACT_PREFIX)) return null;
  const [pv, advisory, status] = tag.slice(FACT_PREFIX.length).split("|");
  const at = pv?.lastIndexOf("@") ?? -1;
  if (at <= 0 || !advisory || (status !== "IN_RANGE" && status !== "OUT_OF_RANGE")) return null;
  return { pkg: pv.slice(0, at), version: pv.slice(at + 1), advisory, status };
}

export interface Hint {
  memory_id: string;
  content: string;
  confidence: number;
  fact: RangeFact | null;
}

export type FeedbackGiven = { memory_id: string; kind: "helpful" | "wrong"; reason: string };

export class Memory {
  readonly engine: HMEM;
  constructor(dir: string) {
    this.engine = new HMEM({ persistDir: dir, actor: "receipts" });
  }

  recall(pkg: string, topN = 8): { hints: Hint[]; trace: unknown } {
    const r = this.engine.query(`npm package ${pkg} advisory range verdict`, { topN, threshold: 0.05 });
    const hints = r.memories
      .filter((m) => m.memory.tags.includes(`npm:${pkg}`) && !m.memory.supersededBy && !m.memory.tags.includes("review"))
      .map((m) => ({ memory_id: m.memory.id, content: m.memory.content, confidence: m.memory.confidence, fact: this.factOf(m.memory) }));
    return { hints, trace: r.trace };
  }

  private factOf(m: MemoryRecord): RangeFact | null {
    for (const t of m.tags) {
      const f = parseFactTag(t);
      if (f) return f;
    }
    return null;
  }

  /** Range facts this run proved, keyed `<pkg>@<version>|<advisory>`. */
  static provedFacts(graph: ExplanationGraph, report: VerifyReport): Map<string, RangeFact> {
    const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
    const out = new Map<string, RangeFact>();
    for (const e of graph.edges) {
      if (e.type !== "IN_RANGE" && e.type !== "OUT_OF_RANGE") continue;
      if (report.edges[e.id]?.status !== "proved") continue;
      const pkg = nodes.get(e.from);
      const adv = nodes.get(e.to);
      if (pkg?.type !== "Package" || adv?.type !== "Advisory" || !pkg.name || !pkg.version) continue;
      const f: RangeFact = { pkg: pkg.name, version: pkg.version, advisory: adv.id.replace(/^adv:/, ""), status: e.type };
      out.set(`${f.pkg}@${f.version}|${f.advisory}`, f);
    }
    return out;
  }

  /** Grade each recalled hint against what this run proved, and give H-MEM feedback. Unrelated hints get none. */
  grade(hints: Hint[], proved: Map<string, RangeFact>): FeedbackGiven[] {
    const given: FeedbackGiven[] = [];
    for (const h of hints) {
      if (!h.fact) continue;
      const now = proved.get(`${h.fact.pkg}@${h.fact.version}|${h.fact.advisory}`);
      if (!now) continue;
      const kind = now.status === h.fact.status ? "helpful" : "wrong";
      this.engine.feedback(h.memory_id, kind);
      given.push({ memory_id: h.memory_id, kind, reason: `this run proved ${now.status} for ${h.fact.pkg}@${h.fact.version} / ${h.fact.advisory}` });
    }
    return given;
  }

  /** Store each proved range fact that memory does not already hold. */
  remember(proved: Map<string, RangeFact>, runId: string, recordSha: (advisory: string) => string | undefined): MemoryRecord[] {
    const existing = new Set<string>();
    for (const m of this.engine.store.all()) for (const t of m.tags) if (t.startsWith(FACT_PREFIX) && !m.tags.includes("review")) existing.add(t);
    const written: MemoryRecord[] = [];
    for (const f of proved.values()) {
      const tag = factTag(f);
      if (existing.has(tag)) continue;
      const sha = recordSha(f.advisory);
      written.push(
        this.engine.add({
          content: `npm ${f.pkg} ${f.version} is ${f.status === "IN_RANGE" ? "inside" : "outside"} the affected range of ${f.advisory} (verified)`,
          source: `receipts run ${runId}`,
          type: "factual",
          layer: "long_term",
          confidence: 0.9,
          tags: ["receipts", `npm:${f.pkg}`, `adv:${f.advisory}`, tag],
          provenance: { origin: "plan_completion", learnedAt: this.engine.clock(), label: `verified range edge, run ${runId}`, refs: sha ? [`snapshot:${sha}`] : [] },
        }),
      );
    }
    return written;
  }
}
