// Vectors come from the SemVer 2.0.0 spec itself (section 11), not from node-semver's test suite.
import { test } from "node:test";
import assert from "node:assert/strict";
import { compareSemVer, parseSemVer } from "../src/semver.ts";

const p = (s: string) => {
  const v = parseSemVer(s);
  assert.ok(v, `should parse ${s}`);
  return v;
};

test("spec 11.2: major, minor, patch compare numerically", () => {
  const chain = ["1.0.0", "2.0.0", "2.1.0", "2.1.1"];
  for (let i = 1; i < chain.length; i++) assert.ok(compareSemVer(p(chain[i - 1]), p(chain[i])) < 0, `${chain[i - 1]} < ${chain[i]}`);
  assert.ok(compareSemVer(p("1.10.0"), p("1.9.0")) > 0, "numeric, not lexical");
});

test("spec 11.4: prerelease precedence chain", () => {
  const chain = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"];
  for (let i = 1; i < chain.length; i++) assert.ok(compareSemVer(p(chain[i - 1]), p(chain[i])) < 0, `${chain[i - 1]} < ${chain[i]}`);
  for (let i = 0; i < chain.length; i++) assert.equal(compareSemVer(p(chain[i]), p(chain[i])), 0);
});

test("spec 10: build metadata is ignored for precedence", () => {
  assert.equal(compareSemVer(p("1.0.0+20130313144700"), p("1.0.0+exp.sha.5114f85")), 0);
  assert.equal(compareSemVer(p("1.0.0-beta+exp.sha.5114f85"), p("1.0.0-beta")), 0);
});

test("invalid strings are rejected, not guessed", () => {
  for (const bad of ["v1.2.3", "1.2", "1.2.3.4", "01.2.3", "1.2.3-01", "1.2.3-", "1.2.3+", "1.2.3-a..b", "latest", "", " 1.2.3"]) {
    assert.equal(parseSemVer(bad), null, bad);
  }
});

test("large numbers do not overflow", () => {
  assert.ok(compareSemVer(p("1.0.99999999999999999999"), p("1.0.99999999999999999998")) > 0);
});
