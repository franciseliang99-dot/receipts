#!/usr/bin/env -S npx tsx
// Receipts command line.
//   check  <repo> <package>        investigate, verify, write the run folder (answer, graph, OpenVEX, HTML)
//   replay <run-dir>               re-verify a finished run offline from its snapshots; must match the saved report
//   explain <run-dir>              print why the run reached its verdict, as a tree of proved/cited/unverified edges
//   tamper <run-dir> <kind>        copy a run, inject a fake fact, re-verify: kinds flip | evidence | quote | snapshot
//   plant-hint <pkg> <version> <advisory> IN_RANGE|OUT_OF_RANGE   store a deliberately wrong memory (demo of grading)
//   status                         is Nightshift reachable and authorised, is Zetaris reachable
// Settings: ENV_FILE (default .env). Runs go to ./runs, memory to ./runs/memory (override with RECEIPTS_HOME).

import { cpSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { loadEnv } from "./config.ts";
import { investigate, type RunResult } from "./investigator.ts";
import { writeOutputs } from "./render.ts";
import { verify } from "./verifier.ts";
import { SnapshotStore } from "./snapshot.ts";
import { Memory } from "./memory.ts";
import { Nightshift } from "./llm.ts";
import { Zetaris } from "./zetaris.ts";
import { explainTree } from "./explain.ts";
import type { ExplanationGraph } from "./graph.ts";

loadEnv();
const HOME = resolve(process.env.RECEIPTS_HOME ?? "runs");
const MEMORY = join(HOME, "memory");
const [cmd, ...args] = process.argv.slice(2);

function load(dir: string): RunResult {
  const run = JSON.parse(readFileSync(join(dir, "run.json"), "utf8")) as RunResult;
  const read = (f: string) => (existsSync(join(dir, f)) ? JSON.parse(readFileSync(join(dir, f), "utf8")) : null);
  return { ...run, dir, graph: read("graph.json"), report: read("report.json") };
}

function summary(r: RunResult) {
  const v = r.report?.verdict;
  console.log(`\n${r.dir}`);
  console.log(v ? `verdict: ${v.verified ? v.recomputed.toUpperCase() + " (verified)" : `UNKNOWN (model claimed ${v.claimed}; not verified)`}` : `verdict: UNKNOWN (${r.stopped})`);
  if (v && !v.verified) for (const w of v.why_not) console.log(`  why not: ${w}`);
  console.log(readFileSync(join(r.dir, "answer.txt"), "utf8"));
  console.log(`open ${join(r.dir, "index.html")}`);
}

async function main(): Promise<number> {
  switch (cmd) {
    case "check": {
      const [repo, pkg] = args;
      if (!repo || !pkg) return usage();
      const r = await investigate({ repo: resolve(repo), pkg, runsDir: HOME, memoryDir: MEMORY, log: (l) => console.log(`· ${l}`) });
      writeOutputs(r);
      summary(r);
      return r.report?.verdict.verified ? 0 : 1;
    }
    case "replay": {
      const dir = resolve(args[0] ?? "");
      const r = load(dir);
      if (!r.graph || !r.report) return console.error("no graph/report in that run"), 2;
      const again = verify(r.graph, new SnapshotStore(join(dir, "snapshots")));
      const same = isDeepStrictEqual(again, r.report);
      console.log(`replayed offline from ${join(dir, "snapshots")}: verdict ${again.verdict.verified ? again.verdict.recomputed : "unknown"} (verified=${again.verdict.verified}); ${same ? "identical to the saved report" : "DIFFERS from the saved report"}`);
      return same ? 0 : 1;
    }
    case "explain": {
      const dir = resolve(args[0] ?? "");
      const r = load(dir);
      if (!r.graph || !r.report) return console.error("no graph/report in that run"), 2;
      console.log(explainTree(r.graph, r.report));
      return 0;
    }
    case "tamper": {
      const [src, kind] = args;
      if (!src || !kind) return usage();
      const dir = resolve(src) + `-tamper-${kind}`;
      cpSync(resolve(src), dir, { recursive: true });
      const r = load(dir);
      if (!r.graph) return console.error("no graph in that run"), 2;
      const g: ExplanationGraph = r.graph;
      const store = new SnapshotStore(join(dir, "snapshots"));
      let what = "";
      let target = "";
      const inWhy = new Set(g.derivation.edges);
      const rangeEdges = g.edges.filter((x) => x.type === "IN_RANGE" || x.type === "OUT_OF_RANGE");
      const pick = rangeEdges.find((x) => inWhy.has(x.id)) ?? rangeEdges[0];
      if (kind === "flip") {
        const e = pick;
        if (!e) return console.error("no range edge to flip"), 2;
        target = e.id;
        what = `relabelled ${e.id} as ${e.type === "IN_RANGE" ? "OUT_OF_RANGE" : "IN_RANGE"} (a misread version range)`;
        e.type = e.type === "IN_RANGE" ? "OUT_OF_RANGE" : "IN_RANGE";
      } else if (kind === "evidence") {
        const e = pick;
        const ev = e?.evidence[0] as { expected?: unknown } | undefined;
        if (!e || !ev) return console.error("no range edge"), 2;
        target = e.id;
        what = `changed the cited installed version on ${e.id} from ${JSON.stringify(ev.expected)} to "1.2.6" (a made-up fact)`;
        ev.expected = "1.2.6";
      } else if (kind === "quote") {
        const adv = g.nodes.find((n) => n.type === "Advisory");
        if (!adv) return console.error("no advisory node"), 2;
        g.nodes.push({ id: "sym:parseArgsSafely", type: "Symbol", symbol: "parseArgsSafely", label: "parseArgsSafely" });
        g.edges.push({ id: `names:${adv.label}|parseArgsSafely`, type: "NAMES_SYMBOL", from: adv.id, to: "sym:parseArgsSafely", evidence: [{ snapshot: adv.record ?? "", pointer: "/rows/0/details", quote: "only parseArgsSafely() is affected" }] });
        target = `names:${adv.label}|parseArgsSafely`;
        what = `added a symbol edge quoting advisory text that does not exist`;
      } else if (kind === "snapshot") {
        const sha = g.question.lockfile;
        const p = join(dir, "snapshots", `${sha}.bin`);
        writeFileSync(p, readFileSync(p, "utf8").replace(/"0\.0\.10"/, '"1.2.8"'));
        target = pick?.id ?? "";
        what = `edited the stored lockfile snapshot on disk (0.0.10 -> 1.2.8) without changing its name`;
      } else return usage();
      const rep = verify(g, store);
      const out: RunResult = { ...r, dir, graph: g, report: rep, run_id: `${r.run_id}-tamper-${kind}` };
      writeFileSync(join(dir, "graph.json"), JSON.stringify(g, null, 2) + "\n");
      writeFileSync(join(dir, "report.json"), JSON.stringify(rep, null, 2) + "\n");
      writeOutputs(out);
      const hit = rep.edges[target];
      const caught = hit?.status === "unverified" || !rep.verdict.verified;
      console.log(`tamper: ${what}`);
      console.log(`tampered edge ${target}: ${hit?.status ?? "missing"}${hit?.reasons.length ? ` - ${hit.reasons[0]}` : ""}`);
      console.log(caught ? "CAUGHT: the verifier did not accept the injected fact" : "NOT CAUGHT");
      summary(out);
      return caught ? 0 : 1;
    }
    case "plant-hint": {
      const [pkg, version, advisory, status] = args;
      if (!pkg || !version || !advisory || (status !== "IN_RANGE" && status !== "OUT_OF_RANGE")) return usage();
      const m = new Memory(MEMORY);
      const rec = m.engine.add({
        content: `npm ${pkg} ${version} is ${status === "IN_RANGE" ? "inside" : "outside"} the affected range of ${advisory}`,
        source: "planted by the demo (deliberately wrong)",
        type: "factual",
        layer: "long_term",
        confidence: 0.9,
        tags: ["receipts", `npm:${pkg}`, `adv:${advisory}`, `fact:range|${pkg}@${version}|${advisory}|${status}`],
      });
      console.log(`stored ${rec.id}: ${rec.content}`);
      return 0;
    }
    case "status": {
      const ns = await new Nightshift().status();
      console.log(`Nightshift: ${ns.state}${ns.state === "online" ? ` (${ns.models.length} models)` : ns.state === "offline" ? ` - ${ns.reason}` : ""}`);
      let zs = "unreachable";
      try {
        const r = await new Zetaris().run("SELECT 1 AS ok", 1);
        zs = r.status === 200 ? "reachable" : `HTTP ${r.status}`;
      } catch (e) {
        zs = `unreachable - ${(e as Error).message}`;
      }
      console.log(`Zetaris: ${zs}`);
      return ns.state === "online" && zs === "reachable" ? 0 : 1;
    }
    default:
      return usage();
  }
}

function usage(): number {
  console.error("usage: receipts check <repo> <package> | replay <run-dir> | explain <run-dir> | tamper <run-dir> flip|evidence|quote|snapshot | plant-hint <pkg> <version> <advisory> IN_RANGE|OUT_OF_RANGE | status");
  return 2;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(`error: ${(e as Error).message}`);
    process.exit(3);
  },
);
