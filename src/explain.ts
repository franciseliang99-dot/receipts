// Plain-text explanation tree: why a finished run reached its verdict. Pure; no I/O.

import { PROJECT_ID, type Evidence, type ExplanationGraph, type GraphEdge, type GraphNode, type JsonEvidence } from "./graph.ts";
import type { EdgeStatus, VerifyReport } from "./verifier.ts";

const statusTag = (s: EdgeStatus | undefined): string => (s === "proved" ? "[ok]" : s === "cited" ? "[cited]" : "[X]");

function nodeLabel(n: GraphNode | undefined): string {
  if (!n) return "?";
  if (n.type === "Package") return `${n.name}@${n.version}`;
  return n.label ?? n.id;
}

function evidenceLine(ev: Evidence): string | null {
  if ("quote" in ev || "byte_start" in ev) return null;
  const je = ev as JsonEvidence;
  return `${je.pointer} = ${JSON.stringify(je.expected).slice(0, 80)} @ ${je.snapshot.slice(0, 12)}`;
}

/** Walk DEPENDS_ON edges from the project to `target`, preferring proved hops. Deterministic. */
function pathTo(target: string, deps: GraphEdge[], report: VerifyReport): GraphEdge[] {
  const byTo = new Map<string, GraphEdge[]>();
  for (const e of deps) {
    const list = byTo.get(e.to) ?? [];
    list.push(e);
    byTo.set(e.to, list);
  }
  for (const list of byTo.values()) {
    list.sort((a, b) => {
      const sa = report.edges[a.id]?.status === "proved" ? 0 : 1;
      const sb = report.edges[b.id]?.status === "proved" ? 0 : 1;
      return sa - sb || a.id.localeCompare(b.id);
    });
  }
  const edges: GraphEdge[] = [];
  let cur = target;
  const seen = new Set<string>([target]);
  for (let i = 0; i < 64; i++) {
    if (cur === PROJECT_ID) break;
    const candidates = byTo.get(cur);
    if (!candidates?.length) break;
    const e = candidates[0];
    edges.unshift(e);
    if (seen.has(e.from)) break;
    seen.add(e.from);
    cur = e.from;
  }
  return cur === PROJECT_ID ? edges : [];
}

function pushNode(lines: string[], depth: number, edge: GraphEdge, node: GraphNode | undefined, report: VerifyReport) {
  const indent = "  ".repeat(depth);
  lines.push(`${indent}${statusTag(report.edges[edge.id]?.status)} ${nodeLabel(node)}`);
  for (const ev of edge.evidence) {
    const t = evidenceLine(ev);
    if (t) lines.push(`${indent}  ${t}`);
  }
}

export function explainTree(graph: ExplanationGraph, report: VerifyReport): string {
  const lines: string[] = [];
  const v = report.verdict;
  if (v.verified) lines.push(`verdict: ${v.recomputed.toUpperCase()} (verified)`);
  else lines.push(`verdict: UNKNOWN (claimed ${v.claimed}; not verified)`);

  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const byId = new Map(graph.edges.map((e) => [e.id, e]));
  const deps = graph.edges.filter((e) => e.type === "DEPENDS_ON");
  // Affected rests on IN_RANGE; not_affected on OUT_OF_RANGE. A flipped range edge stays in
  // derivation.edges with the wrong type — still print it so the tree can mark it [X].
  const showRange =
    graph.derivation.verdict === "affected" || graph.derivation.verdict === "not_affected"
      ? (t: string) => t === "IN_RANGE" || t === "OUT_OF_RANGE" || t === "RANGE_UNKNOWN"
      : null;

  if (showRange) {
    for (const id of graph.derivation.edges) {
      const range = byId.get(id);
      if (!range || !showRange(range.type)) continue;
      lines.push(nodeLabel(nodes.get(PROJECT_ID)));
      const chain = pathTo(range.from, deps, report);
      let depth = 1;
      for (const hop of chain) {
        pushNode(lines, depth, hop, nodes.get(hop.to), report);
        depth++;
      }
      if (chain.length === 0) {
        // No DEPENDS_ON path; still name the package before the advisory.
        lines.push(`${"  ".repeat(depth)}[X] ${nodeLabel(nodes.get(range.from))}`);
        depth++;
      }
      pushNode(lines, depth, range, nodes.get(range.to), report);
    }
  }

  if (!v.verified) {
    lines.push("why not:");
    for (const w of v.why_not) lines.push(w);
  }

  let proved = 0,
    cited = 0,
    unverified = 0;
  for (const e of Object.values(report.edges)) {
    if (e.status === "proved") proved++;
    else if (e.status === "cited") cited++;
    else unverified++;
  }
  lines.push(`edges: ${proved} proved, ${cited} cited, ${unverified} unverified of ${proved + cited + unverified}`);
  return lines.join("\n");
}
