// Turns a run into what a person reads: a templated answer (built only from the verifier's results, never from model
// prose), an OpenVEX draft, and a static HTML receipt page. Deterministic: same run files, same output.

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { PROJECT_ID, type ExplanationGraph, type GraphEdge, type GraphNode, type JsonEvidence, type QuoteEvidence, type TextEvidence } from "./graph.ts";
import type { VerifyReport } from "./verifier.ts";
import type { RunResult } from "./investigator.ts";

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const short = (sha: string) => sha.slice(0, 12);

function nodeLabel(n: GraphNode | undefined): string {
  if (!n) return "?";
  if (n.type === "Project") return n.label ?? "project";
  if (n.type === "Package") return `${n.name}@${n.version}`;
  return n.label ?? n.id;
}

function evidenceText(e: JsonEvidence | QuoteEvidence | TextEvidence): string {
  if ("quote" in e) return `quote "${e.quote}" at ${e.pointer} in snapshot ${short(e.snapshot)}`;
  if ("byte_start" in e) return `bytes ${e.byte_start}-${e.byte_end} of snapshot ${short(e.snapshot)}: ${e.expected_text}`;
  const v = JSON.stringify(e.expected);
  return `${e.pointer} = ${v.length > 120 ? v.slice(0, 117) + "..." : v} in snapshot ${short(e.snapshot)}`;
}

/** The plain-language answer. Every sentence comes from a proved edge or a verifier check. */
export function answerText(r: RunResult): string {
  const pkg = r.question.pkg;
  if (!r.graph || !r.report) return `No answer: ${r.stopped ?? "the model produced no usable claims"}. Verdict: unknown.`;
  const g = r.graph;
  const rep = r.report;
  const nodes = new Map(g.nodes.map((n) => [n.id, n]));
  const lines: string[] = [];
  const v = rep.verdict;
  if (!v.verified) {
    lines.push(`Not verified. The model claimed "${v.claimed}" but the verifier could not confirm it, so the answer is: unknown.`);
    for (const w of v.why_not) lines.push(`- ${w}`);
    return lines.join("\n");
  }
  const proved = (e: GraphEdge) => rep.edges[e.id]?.status === "proved";
  if (v.recomputed === "affected") {
    lines.push(`Yes: this project installs a version of ${pkg} that a security advisory covers.`);
    for (const id of g.derivation.edges) {
      const e = g.edges.find((x) => x.id === id);
      if (!e || e.type !== "IN_RANGE" || !proved(e)) continue;
      const pk = nodes.get(e.from);
      const chain = g.edges.filter((d) => d.type === "DEPENDS_ON" && proved(d));
      const via = pathTo(pk?.id ?? "", chain, nodes);
      lines.push(`- ${nodeLabel(pk)} at ${pk?.install_path} is inside the affected range of ${nodeLabel(nodes.get(e.to))}${via ? `, installed through ${via}` : ""}.`);
    }
  } else if (v.recomputed === "not_affected") {
    lines.push(`No: every installed copy of ${pkg} is outside the affected range of every advisory that names it.`);
    for (const e of g.edges.filter((x) => x.type === "OUT_OF_RANGE" && proved(x))) lines.push(`- ${nodeLabel(nodes.get(e.from))} is outside ${nodeLabel(nodes.get(e.to))}.`);
  }
  const wd = g.edges.filter((e) => e.type === "WITHDRAWN" && proved(e)).map((e) => nodeLabel(nodes.get(e.from)));
  if (wd.length) lines.push(`Ignored as withdrawn: ${wd.join(", ")}.`);
  lines.push(`Checked: ${rep.coverage.instances} installed instance(s) against ${rep.coverage.advisory_groups} advisory group(s); ${Object.values(rep.edges).filter((e) => e.status === "proved").length} of ${g.edges.length} edges proved from snapshots.`);
  lines.push("This says which installed versions are covered by an advisory. It does not say whether the vulnerable code is reachable.");
  return lines.join("\n");
}

function pathTo(target: string, deps: GraphEdge[], nodes: Map<string, GraphNode>): string {
  const into = new Map(deps.map((d) => [d.to, d]));
  const chain: string[] = [];
  let cur = target;
  for (let i = 0; i < 50; i++) {
    const d = into.get(cur);
    if (!d) break;
    if (d.from !== "project") chain.unshift(nodeLabel(nodes.get(d.from)));
    cur = d.from;
  }
  return chain.join(" -> ");
}

/** OpenVEX draft: one statement per advisory the verified graph decides; everything else is under_investigation. */
export function openVex(r: RunResult): unknown {
  const g = r.graph;
  const rep = r.report;
  const statements: unknown[] = [];
  if (g && rep) {
    const advs = g.nodes.filter((n) => n.type === "Advisory");
    for (const a of advs) {
      if (g.edges.some((e) => e.type === "WITHDRAWN" && e.from === a.id && rep.edges[e.id]?.status === "proved")) continue;
      const ranges = g.edges.filter((e) => e.to === a.id && (e.type === "IN_RANGE" || e.type === "OUT_OF_RANGE" || e.type === "RANGE_UNKNOWN"));
      const ok = rep.verdict.verified && ranges.length > 0 && ranges.every((e) => rep.edges[e.id]?.status === "proved");
      const anyIn = ranges.some((e) => e.type === "IN_RANGE");
      const allOut = ranges.every((e) => e.type === "OUT_OF_RANGE");
      const status = !ok ? "under_investigation" : anyIn ? "affected" : allOut ? "not_affected" : "under_investigation";
      statements.push({
        vulnerability: { name: a.label },
        products: [{ "@id": `pkg:npm/${r.question.pkg}` }],
        status,
        ...(status === "not_affected" ? { justification: "vulnerable_code_not_present", impact_statement: "Every installed version is outside the advisory's affected ranges (checked against the lockfile and the OSV record)." } : {}),
        ...(status === "affected" ? { action_statement: "Upgrade the dependency that pulls in the affected version, then re-run Receipts." } : {}),
      });
    }
  }
  return {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": `urn:receipts:${r.run_id}`,
    author: "Receipts (draft; a person must review before publishing)",
    timestamp: new Date().toISOString(),
    version: 1,
    statements,
  };
}

const STATUS_COLOR: Record<string, string> = { proved: "var(--ok)", cited: "var(--warn)", unverified: "var(--bad)" };
const RANGE_EDGE = new Set(["IN_RANGE", "OUT_OF_RANGE", "RANGE_UNKNOWN"]);

/** Walk DEPENDS_ON edges from `target` back to the project. Deterministic. */
function depsToProject(target: string, deps: GraphEdge[]): GraphEdge[] {
  const byTo = new Map<string, GraphEdge[]>();
  for (const e of deps) {
    const list = byTo.get(e.to) ?? [];
    list.push(e);
    byTo.set(e.to, list);
  }
  for (const list of byTo.values()) list.sort((a, b) => a.id.localeCompare(b.id));
  const chain: GraphEdge[] = [];
  let cur = target;
  const seen = new Set<string>([target]);
  for (let i = 0; i < 64; i++) {
    if (cur === PROJECT_ID) break;
    const candidates = byTo.get(cur);
    if (!candidates?.length) break;
    const e = candidates[0]!;
    chain.unshift(e);
    if (seen.has(e.from)) break;
    seen.add(e.from);
    cur = e.from;
  }
  return cur === PROJECT_ID ? chain : [];
}

/** Inline SVG of the derivation's range edges and the DEPENDS_ON chains that reach them. */
export function whySvg(graph: ExplanationGraph, report: VerifyReport): string {
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const byId = new Map(graph.edges.map((e) => [e.id, e]));
  const deps = graph.edges.filter((e) => e.type === "DEPENDS_ON");
  const ranges: GraphEdge[] = [];
  for (const id of graph.derivation.edges) {
    const e = byId.get(id);
    if (e && RANGE_EDGE.has(e.type)) ranges.push(e);
  }
  if (!ranges.length) return "";

  const depthOf = new Map<string, number>();
  const drawEdges = new Map<string, GraphEdge>();
  depthOf.set(PROJECT_ID, 0);

  for (const range of ranges) {
    const chain = depsToProject(range.from, deps);
    let depth = 0;
    for (const hop of chain) {
      depth++;
      const prev = depthOf.get(hop.to);
      if (prev === undefined || depth < prev) depthOf.set(hop.to, depth);
      drawEdges.set(hop.id, hop);
    }
    if (chain.length === 0 && range.from !== PROJECT_ID && !depthOf.has(range.from)) {
      depthOf.set(range.from, 1);
    }
    drawEdges.set(range.id, range);
  }

  let maxPkgDepth = 0;
  for (const d of depthOf.values()) if (d > maxPkgDepth) maxPkgDepth = d;
  const advDepth = maxPkgDepth + 1;
  for (const range of ranges) {
    if (nodes.get(range.to)) depthOf.set(range.to, advDepth);
  }

  const columns = new Map<number, string[]>();
  for (const [id, depth] of depthOf) {
    if (!nodes.has(id)) continue;
    const list = columns.get(depth) ?? [];
    list.push(id);
    columns.set(depth, list);
  }
  for (const list of columns.values()) list.sort((a, b) => a.localeCompare(b));

  const colCount = Math.max(...columns.keys()) + 1;
  const rowCount = Math.max(1, ...[...columns.values()].map((l) => l.length));
  const boxW = 200;
  const boxH = 40;
  const gapX = 90;
  const gapY = 28;
  const pad = 36;
  const width = pad * 2 + colCount * boxW + (colCount - 1) * gapX;
  const height = pad * 2 + rowCount * boxH + (rowCount - 1) * gapY;

  const pos = new Map<string, { x: number; y: number }>();
  for (const [depth, ids] of columns) {
    ids.forEach((id, row) => {
      pos.set(id, { x: pad + depth * (boxW + gapX), y: pad + row * (boxH + gapY) });
    });
  }

  const out: string[] = [];
  out.push(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" role="img" aria-label="Why graph">`);
  out.push(`<defs>
<marker id="why-arrow-proved" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="var(--ok)"/></marker>
<marker id="why-arrow-cited" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="var(--warn)"/></marker>
<marker id="why-arrow-unverified" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="var(--bad)"/></marker>
</defs>`);

  const edgeList = [...drawEdges.values()].sort((a, b) => a.id.localeCompare(b.id));
  for (const e of edgeList) {
    const a = pos.get(e.from);
    const b = pos.get(e.to);
    if (!a || !b) continue;
    const raw = report.edges[e.id]?.status ?? "unverified";
    const status = raw in STATUS_COLOR ? raw : "unverified"; // only known names reach the marker id
    const color = STATUS_COLOR[status];
    const dash = status === "unverified" ? ' stroke-dasharray="6 4"' : "";
    const x1 = a.x + boxW;
    const y1 = a.y + boxH / 2;
    const x2 = b.x;
    const y2 = b.y + boxH / 2;
    const mx = (x1 + x2) / 2;
    out.push(`<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" fill="none" stroke="${color}" stroke-width="1.75"${dash} marker-end="url(#why-arrow-${status})"/>`);
    out.push(`<text x="${mx}" y="${(y1 + y2) / 2 - 6}" text-anchor="middle" fill="var(--mut)" font-size="10">${esc(e.type)}</text>`);
  }

  const nodeIds = [...depthOf.keys()].filter((id) => nodes.has(id) && pos.has(id)).sort((a, b) => a.localeCompare(b));
  for (const id of nodeIds) {
    const n = nodes.get(id)!;
    const p = pos.get(id)!;
    out.push(`<rect x="${p.x}" y="${p.y}" width="${boxW}" height="${boxH}" rx="6" ry="6" fill="var(--card)" stroke="var(--line)"/>`);
    out.push(`<text x="${p.x + boxW / 2}" y="${p.y + boxH / 2 + 4}" text-anchor="middle" fill="var(--fg)" font-size="12">${esc(nodeLabel(n))}</text>`);
  }

  out.push("</svg>");
  return out.join("");
}

export function htmlPage(r: RunResult): string {
  const g = r.graph;
  const rep = r.report;
  const nodes = new Map((g?.nodes ?? []).map((n) => [n.id, n]));
  const v = rep?.verdict;
  const banner = !rep ? ["unknown", "No graph was produced", "var(--bad)"] : v!.verified ? [v!.recomputed, "Verified: every edge the answer rests on was re-checked against the snapshots", "var(--ok)"] : ["unknown", `Not verified: model claimed "${v!.claimed}"`, "var(--bad)"];
  const derivation = new Set(g?.derivation.edges ?? []);
  const edgeRows = (g?.edges ?? [])
    .map((e) => {
      const st = rep?.edges[e.id];
      const tag = st?.decorative ? " (not needed)" : st?.backup_support ? " (backup)" : "";
      return `<tr${derivation.has(e.id) ? ' class="why"' : ""}><td><span class="dot" style="background:${STATUS_COLOR[st?.status ?? "unverified"]}"></span>${esc(st?.status ?? "-")}${tag}</td><td>${esc(nodeLabel(nodes.get(e.from)))}</td><td><code>${esc(e.type)}</code></td><td>${esc(nodeLabel(nodes.get(e.to)))}</td><td class="ev">${e.evidence.map((x) => esc(evidenceText(x))).join("<br>")}${st?.reasons.length ? `<div class="bad">${st.reasons.map(esc).join("<br>")}</div>` : ""}</td></tr>`;
    })
    .join("\n");
  const checks = rep ? Object.entries(rep.checks).map(([k, c]) => `<li><b>${k}</b> <span style="color:${c.result === "pass" ? "var(--ok)" : c.result === "fail" ? "var(--bad)" : "var(--warn)"}">${c.result}</span>${c.details.length ? `<ul>${c.details.slice(0, 6).map((d) => `<li>${esc(d)}</li>`).join("")}</ul>` : ""}</li>`).join("") : "";
  const rounds = r.rounds.map((x) => `<li>round ${x.round}: ${esc(x.model)} claimed <b>${esc(x.claims?.verdict ?? "nothing usable")}</b>, ${x.verified ? "verified" : "rejected"} (${x.ms} ms)${x.parse_error ? ` - ${esc(x.parse_error)}` : ""}${x.why_not.length ? `<ul>${x.why_not.slice(0, 4).map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}</li>`).join("");
  const hints = r.hints.map((h) => { const f = r.feedback.find((x) => x.memory_id === h.memory_id); return `<li>${esc(h.content)} <small>(${h.memory_id}, confidence ${h.confidence.toFixed(2)})</small>${f ? ` -> <b style="color:${f.kind === "wrong" ? "var(--bad)" : "var(--ok)"}">${f.kind}</b>` : ""}</li>`; }).join("");
  const why = g && rep ? whySvg(g, rep) : "";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Receipts run</title>
<style>
:root{--bg:#fbfaf7;--fg:#1d1d1b;--mut:#6b6a66;--line:#e2e0da;--ok:#1f7a4d;--warn:#a86b00;--bad:#b3261e;--card:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--mut:#a3a19b;--line:#33322f;--ok:#4cc38a;--warn:#e0a43a;--bad:#f2766b;--card:#1f1f1d}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;margin:0;padding:24px 16px}
main{max-width:1100px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px}
.banner{border-left:6px solid;padding:12px 16px;background:var(--card);border-radius:6px}
.banner b{font-size:20px;text-transform:uppercase}pre{white-space:pre-wrap;background:var(--card);border:1px solid var(--line);padding:12px;border-radius:6px}
table{border-collapse:collapse;width:100%;font-size:13px;background:var(--card)}td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
tr.why td{background:color-mix(in srgb,var(--ok) 8%,transparent)}.ev{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}.bad{color:var(--bad)}small,.mut{color:var(--mut)}
.wrap{overflow-x:auto}
</style></head><body><main>
<h1>Receipts: does this project install a vulnerable <code>${esc(r.question.pkg)}</code>?</h1>
<p class="mut">run ${esc(r.run_id)} · lockfile ${esc(r.lockfile ?? "none")} · question bound to snapshots ${g ? `${short(g.question.lockfile)} (lockfile), ${short(g.question.advisory_list)} (advisory list)` : "-"}</p>
<div class="banner" style="border-color:${banner[2]}"><b>${esc(banner[0])}</b><br>${esc(banner[1])}</div>
<h2>Answer</h2><pre>${esc(answerText(r))}</pre>
${why ? `<h2>Why, as a graph</h2>${why}` : ""}
<h2>Explanation graph</h2><p class="mut">Highlighted rows are the edges the verdict rests on. Each edge names the snapshot bytes it was checked against.</p>
<div class="wrap"><table><tr><th>status</th><th>from</th><th>edge</th><th>to</th><th>evidence</th></tr>${edgeRows}</table></div>
<h2>Verifier checks</h2><ul>${checks}</ul>
<h2>Model rounds (via Meterless Nightshift)</h2><ul>${rounds || "<li>none</li>"}</ul>
<h2>Memory (Meterless H-MEM)</h2><p class="mut">Recalled hints are leads for the model, never evidence. After the run each one is graded against what this run proved.</p>
<ul>${hints || "<li>no hints recalled</li>"}</ul><p>${r.remembered.length} new verified fact(s) stored.</p>
${r.stopped ? `<h2>Stopped</h2><p class="bad">${esc(r.stopped)}</p>` : ""}
</main></body></html>
`;
}

export function writeOutputs(r: RunResult): void {
  writeFileSync(join(r.dir, "answer.txt"), answerText(r) + "\n");
  writeFileSync(join(r.dir, "openvex.json"), JSON.stringify(openVex(r), null, 2) + "\n");
  writeFileSync(join(r.dir, "index.html"), htmlPage(r));
}

export type { VerifyReport, ExplanationGraph };
