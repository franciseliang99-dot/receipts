// Vectors from the OSV schema "Evaluation" section and its examples, plus edge cases we found while building.
import { test } from "node:test";
import assert from "node:assert/strict";
import { inSemverRange, isAffected, type OsvAffected } from "../src/osvRange.ts";
import { parseSemVer } from "../src/semver.ts";

const v = (s: string) => parseSemVer(s)!;
const kind = (ver: string, events: object[], type = "SEMVER") => inSemverRange(v(ver), { type, events } as never).kind;

test("introduced 0: every version is affected", () => {
  assert.equal(kind("0.0.1", [{ introduced: "0" }]), "in");
  assert.equal(kind("99.0.0", [{ introduced: "0" }]), "in");
});

test("fixed is exclusive, introduced is inclusive", () => {
  const ev = [{ introduced: "0" }, { fixed: "1.0.2" }];
  assert.equal(kind("1.0.1", ev), "in");
  assert.equal(kind("1.0.2", ev), "out");
  assert.equal(kind("1.0.3", ev), "out");
  const ev2 = [{ introduced: "1.0.0" }, { fixed: "1.2.6" }];
  assert.equal(kind("1.0.0", ev2), "in");
  assert.equal(kind("0.9.9", ev2), "out");
});

test("last_affected is inclusive", () => {
  const ev = [{ introduced: "1.0.0" }, { last_affected: "1.4.0" }];
  assert.equal(kind("1.4.0", ev), "in");
  assert.equal(kind("1.4.1", ev), "out");
});

test("multiple windows inside one range (schema example)", () => {
  const ev = [{ introduced: "1.0.0" }, { fixed: "1.0.2" }, { introduced: "3.0.0" }, { fixed: "3.2.5" }];
  assert.equal(kind("1.0.1", ev), "in");
  assert.equal(kind("2.0.0", ev), "out");
  assert.equal(kind("3.2.4", ev), "in");
  assert.equal(kind("3.2.5", ev), "out");
});

test("events are sorted before evaluation (unsorted input gives the same answer)", () => {
  const ev = [{ fixed: "3.2.5" }, { introduced: "3.0.0" }, { fixed: "1.0.2" }, { introduced: "1.0.0" }];
  assert.equal(kind("3.1.0", ev), "in");
  assert.equal(kind("2.0.0", ev), "out");
});

test("prereleases follow SemVer 2.0 precedence", () => {
  const ev = [{ introduced: "0" }, { fixed: "2.0.0" }];
  assert.equal(kind("2.0.0-rc.1", ev), "in", "2.0.0-rc.1 < 2.0.0");
  const ev2 = [{ introduced: "2.0.0-beta.2" }, { fixed: "2.0.0" }];
  assert.equal(kind("2.0.0-beta.11", ev2), "in", "beta.11 > beta.2 numerically");
  assert.equal(kind("2.0.0-alpha", ev2), "out");
});

test("refuses to guess: unsupported types, mixed fixed/last_affected, limit, bad versions, ties", () => {
  assert.equal(kind("1.0.0", [{ introduced: "0" }], "GIT"), "undecidable");
  assert.equal(kind("1.0.0", [{ introduced: "0" }], "ECOSYSTEM"), "undecidable");
  assert.equal(kind("1.0.0", [{ introduced: "0" }, { fixed: "2.0.0" }, { last_affected: "1.5.0" }]), "undecidable");
  assert.equal(kind("1.0.0", [{ introduced: "0" }, { limit: "2.0.0" }]), "undecidable");
  assert.equal(kind("1.0.0", [{ introduced: "v0.5.0" }]), "undecidable");
  assert.equal(kind("1.0.0", [{ introduced: "1.0.0" }, { fixed: "1.0.0" }]), "undecidable");
  assert.equal(kind("1.0.0", [{ introduced: "1.0.0", fixed: "2.0.0" }]), "undecidable");
  assert.equal(kind("1.0.0", []), "undecidable");
});

test("isAffected: union of ranges and the versions list, per package", () => {
  // Shape of the real GHSA-xvch-5gv4-984h (minimist) record: two affected entries.
  const affected: OsvAffected[] = [
    { package: { ecosystem: "npm", name: "minimist" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "1.2.6" }] }] },
    { package: { ecosystem: "npm", name: "minimist" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.2.4" }] }] },
  ];
  assert.equal(isAffected("1.2.5", "minimist", affected).kind, "in");
  assert.equal(isAffected("0.2.3", "minimist", affected).kind, "in");
  assert.equal(isAffected("0.2.4", "minimist", affected).kind, "out");
  assert.equal(isAffected("1.2.6", "minimist", affected).kind, "out");
  assert.equal(isAffected("1.2.5", "other", affected).kind, "undecidable", "no entry for this package");
  const listed: OsvAffected[] = [{ package: { ecosystem: "npm", name: "x" }, versions: ["1.0.3"] }];
  assert.equal(isAffected("1.0.3", "x", listed).kind, "in");
  assert.equal(isAffected("1.0.4", "x", listed).kind, "out");
});

test("isAffected: an undecidable range is never silently read as 'out'", () => {
  const affected: OsvAffected[] = [
    { package: { ecosystem: "npm", name: "x" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] }] },
    { package: { ecosystem: "npm", name: "x" }, ranges: [{ type: "GIT", events: [{ introduced: "abc" }] }] },
  ];
  assert.equal(isAffected("2.0.0", "x", affected).kind, "undecidable");
  assert.equal(isAffected("0.5.0", "x", affected).kind, "in", "a decidable 'in' still wins");
  assert.equal(isAffected("not-a-version", "x", affected).kind, "undecidable");
});

test("isAffected: an entry with neither ranges nor versions is undecidable, never 'out'", () => {
  const affected: OsvAffected[] = [{ package: { ecosystem: "npm", name: "x" } }];
  assert.equal(isAffected("1.0.0", "x", affected).kind, "undecidable");
});
