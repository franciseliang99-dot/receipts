// Offline tests for the layer around the verifier: H-MEM grading, the templated answer, OpenVEX, reply parsing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildGraph, type Claims } from "../src/build.ts";
import { verify } from "../src/verifier.ts";
import { Memory, parseFactTag } from "../src/memory.ts";
import { answerText, openVex, whySvg } from "../src/render.ts";
import { extractJson, normaliseBaseUrl } from "../src/llm.ts";
import { findUsages, type RunResult } from "../src/investigator.ts";
import { makeWorld, MKDIRP_PATH, OPTIMIST_PATH } from "./fixtures/world.ts";

const A = "node_modules/mkdirp/node_modules/minimist";
const B = "node_modules/optimist/node_modules/minimist";
const X = "GHSA-xvch-5gv4-984h";
const V = "GHSA-vh95-rmgr-6w4m";
const W = "GHSA-7fhm-mqm4-2wp7";

const claims = (over: Partial<Claims> = {}): Claims => ({
  verdict: "affected",
  instances: [
    { path: A, dependency_path: MKDIRP_PATH },
    { path: B, dependency_path: OPTIMIST_PATH },
  ],
  assessments: [
    { instance: A, advisory: X, status: "IN_RANGE" },
    { instance: A, advisory: V, status: "OUT_OF_RANGE" },
    { instance: B, advisory: X, status: "IN_RANGE" },
    { instance: B, advisory: V, status: "IN_RANGE" },
  ],
  withdrawn: [W],
  because: [{ instance: A, advisory: X }],
  ...over,
});

function run(c: Claims): RunResult {
  const { store, cat } = makeWorld();
  const graph = buildGraph(cat, c);
  return { run_id: "t", dir: "", question: { repo: "", pkg: "minimist" }, lockfile: "package-lock.json", graph, report: verify(graph, store), rounds: [], hints: [], feedback: [], remembered: [] };
}

test("memory: only proved range facts are stored, once", () => {
  const r = run(claims());
  const mem = new Memory(mkdtempSync(join(tmpdir(), "receipts-mem-")));
  const proved = Memory.provedFacts(r.graph!, r.report!);
  assert.equal(proved.size, 4);
  assert.equal(mem.remember(proved, "r1", () => undefined).length, 4);
  assert.equal(mem.remember(proved, "r2", () => undefined).length, 0, "a second run must not duplicate facts");
});

test("memory: an unproved (wrong) claim is never stored", () => {
  const c = claims();
  c.assessments[1].status = "IN_RANGE"; // 1.2.5 is outside GHSA-vh95; this edge fails V3
  const r = run(c);
  const proved = Memory.provedFacts(r.graph!, r.report!);
  assert.equal(proved.has(`minimist@1.2.5|${V}`), false);
});

test("memory: recalled hints are graded helpful when the run agrees and wrong when it contradicts", () => {
  const dir = mkdtempSync(join(tmpdir(), "receipts-mem-"));
  const mem = new Memory(dir);
  const good = mem.engine.add({ content: "minimist 0.0.10 inside xvch", source: "test", tags: ["receipts", "npm:minimist", `fact:range|minimist@0.0.10|${X}|IN_RANGE`] });
  const bad = mem.engine.add({ content: "minimist 0.0.10 outside xvch", source: "test", confidence: 0.9, tags: ["receipts", "npm:minimist", `fact:range|minimist@0.0.10|${X}|OUT_OF_RANGE`] });
  const hints = mem.recall("minimist").hints;
  assert.equal(hints.length, 2);
  const given = mem.grade(hints, Memory.provedFacts(run(claims()).graph!, run(claims()).report!));
  assert.deepEqual(given.map((g) => [g.memory_id, g.kind]).sort(), [[bad.id, "wrong"], [good.id, "helpful"]].sort());
  const after = mem.engine.store.get(bad.id)!;
  assert.ok(after.confidence < 0.9 && after.tags.includes("review"));
  assert.equal(new Memory(dir).recall("minimist").hints.some((h) => h.memory_id === bad.id), false, "a hint flagged for review is not offered again");
});

test("memory: fact tags round-trip and reject junk", () => {
  assert.deepEqual(parseFactTag(`fact:range|@scope/pkg@1.0.0|${X}|IN_RANGE`), { pkg: "@scope/pkg", version: "1.0.0", advisory: X, status: "IN_RANGE" });
  assert.equal(parseFactTag(`fact:range|minimist@1.0.0|${X}|MAYBE`), null);
  assert.equal(parseFactTag("npm:minimist"), null);
});

test("answer: a verified graph names the instance and path; an unverified one says unknown", () => {
  const ok = answerText(run(claims()));
  assert.match(ok, /^Yes:/);
  assert.match(ok, /minimist@1\.2\.5 at node_modules\/mkdirp\/node_modules\/minimist is inside the affected range of GHSA-xvch-5gv4-984h, installed through mkdirp@0\.5\.5/);
  assert.match(ok, /does not say whether the vulnerable code is reachable/);
  const c = claims();
  c.assessments[0].status = "OUT_OF_RANGE";
  const bad = answerText(run(c));
  assert.match(bad, /^Not verified\..*unknown/);
  assert.doesNotMatch(bad, /^Yes/m);
});

test("openvex: verified statuses per advisory, withdrawn omitted, unverified -> under_investigation", () => {
  const v = openVex(run(claims())) as { statements: { vulnerability: { name: string }; status: string }[] };
  assert.deepEqual(v.statements.map((s) => [s.vulnerability.name, s.status]).sort(), [[V, "affected"], [X, "affected"]].sort());
  const c = claims();
  c.assessments[0].status = "OUT_OF_RANGE";
  const u = openVex(run(c)) as { statements: { status: string }[] };
  assert.ok(u.statements.every((s) => s.status === "under_investigation"));
});

test("html: whySvg draws the derivation chain; a flipped range edge is dashed", () => {
  const ok = run(claims({ because: [{ instance: B, advisory: X }] }));
  assert.equal(ok.report!.verdict.verified, true);
  const svg = whySvg(ok.graph!, ok.report!);
  assert.match(svg, /optimist@0\.6\.1/);
  assert.match(svg, /minimist@0\.0\.10/);
  assert.match(svg, /GHSA-xvch-5gv4-984h/);
  assert.doesNotMatch(svg, /stroke-dasharray/);

  const c = claims({ because: [{ instance: B, advisory: X }] });
  c.assessments[2].status = "OUT_OF_RANGE"; // B|X is actually in range; this edge fails
  const bad = run(c);
  assert.equal(bad.report!.verdict.verified, false);
  assert.match(whySvg(bad.graph!, bad.report!), /stroke-dasharray/);
});

test("llm: JSON is pulled out of fences and prose; braces inside strings do not confuse it", () => {
  assert.deepEqual(extractJson('Sure.\n```json\n{"a": "x}y", "b": {"c": 1}}\n```'), { a: "x}y", b: { c: 1 } });
  assert.deepEqual(extractJson('prefix {"verdict":"unknown"} suffix'), { verdict: "unknown" });
  assert.throws(() => extractJson("no json here"));
  assert.equal(normaliseBaseUrl("127.0.0.1:8088"), "http://127.0.0.1:8088/v1");
  assert.equal(normaliseBaseUrl("http://localhost:8088/v1/chat/completions"), "http://localhost:8088/v1");
});

test("usages: require/import of the package are found, look-alikes are not", () => {
  const found = findUsages(new URL("../demo/patched-cli", import.meta.url).pathname, "minimist");
  assert.deepEqual(found.map((f) => [f.file, f.lines.map((l) => l.line)]), [["cli.js", [2]]]);
  assert.deepEqual(findUsages(new URL("../demo/legacy-cli", import.meta.url).pathname, "minimist"), []);
  assert.deepEqual(findUsages(new URL("../demo/legacy-cli", import.meta.url).pathname, "mkdirp").map((f) => f.file), ["cli.js"]);
});
