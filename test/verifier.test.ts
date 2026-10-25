// Fault-injection suite: every fault arm must be caught, and every arm has a clean control that passes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildGraph, type Claims } from "../src/build.ts";
import { verify } from "../src/verifier.ts";
import { makeWorld, MKDIRP_PATH, OPTIMIST_PATH, LOCK } from "./fixtures/world.ts";
import type { SnapshotStore } from "../src/snapshot.ts";

const A = "node_modules/mkdirp/node_modules/minimist"; // 1.2.5: inside GHSA-xvch (fixed 1.2.6), outside GHSA-vh95 (fixed 1.2.3)
const B = "node_modules/optimist/node_modules/minimist"; // 0.0.10: inside both
const X = "GHSA-xvch-5gv4-984h";
const V = "GHSA-vh95-rmgr-6w4m";
const W = "GHSA-7fhm-mqm4-2wp7";

const goodAffected = (): Claims => ({
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
});

test("control: a correct affected graph is verified, and its edges are proved", () => {
  const { store, cat } = makeWorld();
  const r = verify(buildGraph(cat, goodAffected()), store);
  assert.deepEqual(r.verdict.why_not, []);
  assert.equal(r.verdict.verified, true);
  for (const [id, e] of Object.entries(r.edges)) assert.equal(e.status, "proved", `${id}: ${e.reasons.join("; ")}`);
  assert.equal(r.coverage.instances, 2);
  assert.equal(r.coverage.advisory_groups, 2);
});

test("control: two independent derivations are both backup support, not decorative", () => {
  const { store, cat } = makeWorld();
  const c = goodAffected();
  c.because = [{ instance: A, advisory: X }, { instance: B, advisory: V }];
  const r = verify(buildGraph(cat, c), store);
  assert.equal(r.verdict.verified, true, r.verdict.why_not.join("; "));
  assert.equal(r.edges[`range:${A}|${X}`].backup_support, true);
  assert.equal(r.edges[`range:${A}|${X}`].decorative, undefined);
});

test("F1: an invented dependency hop is caught by V2", () => {
  const { store, cat } = makeWorld();
  const c = goodAffected();
  c.instances[0].dependency_path = ["", A]; // the root does not depend on minimist directly
  const r = verify(buildGraph(cat, c), store);
  assert.equal(r.checks.V2.result, "fail");
  assert.equal(r.verdict.verified, false);
});

test("F2: a misread range is caught by V3 (claiming 1.2.5 is outside GHSA-xvch)", () => {
  const { store, cat } = makeWorld();
  const c = goodAffected();
  c.assessments[0].status = "OUT_OF_RANGE";
  const r = verify(buildGraph(cat, c), store);
  assert.equal(r.checks.V3.result, "fail");
  assert.equal(r.edges[`range:${A}|${X}`].status, "unverified");
  assert.equal(r.verdict.verified, false);
});

test("F3: alias double counting does not create a second advisory group", () => {
  const { store, cat } = makeWorld({ rows: [...makeWorld().cat.rows, { ghsa_id: "GHSA-dupe-dupe-dupe", cve_id: "CVE-2021-44906" }] });
  const r = verify(buildGraph(cat, goodAffected()), store);
  assert.equal(r.coverage.advisory_groups, 2, "GHSA-dupe shares CVE-2021-44906 with GHSA-xvch, so it is the same vulnerability");
  assert.equal(r.verdict.verified, true, r.verdict.why_not.join("; "));
});

test("F4: a withdrawn advisory cannot carry a range verdict, and must be recorded", () => {
  const { store, cat } = makeWorld();
  const c = goodAffected();
  c.assessments.push({ instance: A, advisory: W, status: "IN_RANGE" });
  c.because = [{ instance: A, advisory: W }];
  const r = verify(buildGraph(cat, c), store);
  assert.equal(r.checks.V3.result, "fail");
  assert.equal(r.verdict.verified, false);
  const c2 = goodAffected();
  delete c2.withdrawn;
  assert.equal(verify(buildGraph(cat, c2), store).checks.V6.result, "fail", "forgetting the withdrawn advisory is a coverage gap");
});

test("F5: a quote that drifts by one character fails V1; tampering with a snapshot fails V1", () => {
  const { store, cat } = makeWorld();
  const c = goodAffected();
  c.symbols = [{ advisory: X, symbol: "setKey", quote: "function `setKey()` (lines 69-95)" }];
  const ok = verify(buildGraph(cat, c), store);
  assert.equal(ok.edges[`names:${X}|setKey`].status, "cited");
  c.symbols = [{ advisory: X, symbol: "setKey", quote: "function `setkey()` (lines 69-95)" }];
  const bad = verify(buildGraph(cat, c), store);
  assert.equal(bad.edges[`names:${X}|setKey`].status, "unverified");
  assert.equal(bad.checks.V1.result, "fail");
  assert.equal(bad.verdict.verified, true, "a bad symbol edge flags that edge, it does not overturn a verified range verdict");

  const g = buildGraph(cat, goodAffected());
  const ev = g.edges.find((e) => e.id === `range:${A}|${X}`)!.evidence[0] as { expected: unknown };
  ev.expected = "1.2.6"; // a forged version
  const forged = verify(g, store);
  assert.equal(forged.edges[`range:${A}|${X}`].status, "unverified");
  assert.equal(forged.verdict.verified, false);
});

test("F6: decorative evidence in the derivation is caught by V5", () => {
  const { store, cat } = makeWorld();
  const g = buildGraph(cat, goodAffected());
  g.derivation.edges.push(`range:${A}|${V}`); // an OUT_OF_RANGE edge cannot support "affected"
  const r = verify(g, store);
  assert.equal(r.checks.V5.result, "fail");
  assert.equal(r.edges[`range:${A}|${V}`].decorative, true);
  assert.equal(r.verdict.verified, false);
});

test("F7: not_affected needs every instance; checking one copy is caught", () => {
  const lock = structuredClone(LOCK);
  lock.packages!["node_modules/mkdirp/node_modules/minimist"].version = "1.2.8";
  lock.packages!["node_modules/optimist/node_modules/minimist"].version = "1.2.8";
  const { store, cat } = makeWorld({ lock });
  const all: Claims = {
    verdict: "not_affected",
    instances: [
      { path: A, dependency_path: MKDIRP_PATH },
      { path: B, dependency_path: OPTIMIST_PATH },
    ],
    assessments: [
      { instance: A, advisory: X, status: "OUT_OF_RANGE" },
      { instance: A, advisory: V, status: "OUT_OF_RANGE" },
      { instance: B, advisory: X, status: "OUT_OF_RANGE" },
      { instance: B, advisory: V, status: "OUT_OF_RANGE" },
    ],
    withdrawn: [W],
  };
  const ok = verify(buildGraph(cat, all), store);
  assert.equal(ok.verdict.verified, true, ok.verdict.why_not.join("; "));
  const one: Claims = { ...all, instances: [all.instances[0]], assessments: all.assessments.slice(0, 2) };
  const r = verify(buildGraph(cat, one), store);
  assert.equal(r.verdict.verified, false);
  assert.equal(r.checks.V6.result, "fail");
  assert.equal(r.checks.V4.result, "fail");
});

test("F9: an unsupported lockfile is undecidable, never 'not affected'", () => {
  const { store, cat } = makeWorld({ lock: { ...LOCK, lockfileVersion: 1 } });
  const claims: Claims = { verdict: "not_affected", instances: [], assessments: [], withdrawn: [W] };
  const r = verify(buildGraph(cat, claims), store);
  assert.equal(r.verdict.verified, false);
  assert.equal(r.checks.V2.result, "undecidable");
});

test("V4: a verdict that does not follow from its own derivation is rejected", () => {
  const { store, cat } = makeWorld();
  const c = goodAffected();
  c.because = []; // claims affected but cites nothing
  const r = verify(buildGraph(cat, c), store);
  assert.equal(r.checks.V4.result, "fail");
  assert.equal(r.verdict.verified, false);
});

test("V1b: a code line that does not name the symbol is caught", () => {
  const { store, cat } = makeWorld();
  const text = "const parse = require('minimist');\nconst args = parse(process.argv.slice(2));\nconst parser = 1;\n";
  const sha = store.put(text, { kind: "source-file", media: "text", source: "bin/cli.js" });
  cat.sources = { "bin/cli.js": { sha, text } };
  const c = goodAffected();
  c.code_sites = [{ file: "bin/cli.js", line: 2, symbol: "parse" }];
  assert.equal(verify(buildGraph(cat, c), store).edges["refs:bin/cli.js:2|parse"].status, "cited");
  c.code_sites = [{ file: "bin/cli.js", line: 3, symbol: "parse" }]; // `parser` must not match `parse`
  const r = verify(buildGraph(cat, c), store);
  assert.equal(r.edges["refs:bin/cli.js:3|parse"].status, "unverified");
  assert.equal(r.checks.V1b.result, "fail");
});

test("F10: a Package node that misnames its lockfile entry blocks an affected verdict (V2)", () => {
  const { store, cat } = makeWorld();
  const g = buildGraph(cat, goodAffected());
  // optimist is off the derivation (which rests on A via mkdirp), so only V2 can catch this.
  const op = g.nodes.find((n) => n.type === "Package" && n.install_path === "node_modules/optimist")!;
  op.name = "minimist"; // optimist@0.6.1 dressed up as a copy of minimist
  const r = verify(g, store);
  assert.equal(r.checks.V2.result, "fail");
  assert.ok(r.checks.V2.details.some((d) => d.includes("node says minimist")), r.checks.V2.details.join("; "));
  assert.equal(r.verdict.verified, false, "V2 must block affected verdicts too");
});

test("F11: an advisory record must be a Zetaris query snapshot, not any JSON with the right shape", () => {
  const { store, cat } = makeWorld();
  const g = buildGraph(cat, goodAffected());
  const adv = g.nodes.find((n) => n.id === `adv:${X}`)!;
  const real = (store as SnapshotStore).json(adv.record!) as object;
  adv.record = store.put(JSON.stringify(real, null, 1), { kind: "source-file", media: "json", source: "lib/fake.json" });
  const r = verify(g, store);
  assert.equal(r.checks.V1.result, "fail");
  assert.equal(r.verdict.verified, false);
});
