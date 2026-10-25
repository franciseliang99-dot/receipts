import { test } from "node:test";
import assert from "node:assert/strict";
import { buildGraph, type Claims } from "../src/build.ts";
import { verify } from "../src/verifier.ts";
import { explainTree } from "../src/explain.ts";
import { makeWorld, MKDIRP_PATH, OPTIMIST_PATH } from "./fixtures/world.ts";

const A = "node_modules/mkdirp/node_modules/minimist";
const B = "node_modules/optimist/node_modules/minimist";
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
  because: [{ instance: B, advisory: X }],
});

test("explain: verified affected graph shows optimist -> minimist@0.0.10 with [ok]", () => {
  const { store, cat } = makeWorld();
  const g = buildGraph(cat, goodAffected());
  const report = verify(g, store);
  assert.equal(report.verdict.verified, true, report.verdict.why_not.join("; "));
  const text = explainTree(g, report);
  assert.match(text, /^verdict: AFFECTED \(verified\)$/m);
  assert.match(text, /\[ok\] optimist@0\.6\.1/);
  assert.match(text, /\[ok\] minimist@0\.0\.10/);
  assert.match(text, /\[ok\] GHSA-xvch-5gv4-984h/);
  assert.doesNotMatch(text, /^why not:/m);
  assert.match(text, /edges: \d+ proved, \d+ cited, \d+ unverified of \d+$/);
});

test("explain: flipped range edge shows [X] and a why not: section", () => {
  const { store, cat } = makeWorld();
  const g = buildGraph(cat, goodAffected());
  const range = g.edges.find((e) => e.id === `range:${B}|${X}`)!;
  range.type = "OUT_OF_RANGE";
  const report = verify(g, store);
  assert.equal(report.verdict.verified, false);
  assert.equal(report.edges[range.id].status, "unverified");
  const text = explainTree(g, report);
  assert.match(text, /^verdict: UNKNOWN \(claimed affected; not verified\)$/m);
  assert.match(text, /\[X\] GHSA-xvch-5gv4-984h/);
  assert.match(text, /^why not:$/m);
  for (const w of report.verdict.why_not) assert.match(text, new RegExp(`^${w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"));
  assert.match(text, /unverified of \d+$/);
});
