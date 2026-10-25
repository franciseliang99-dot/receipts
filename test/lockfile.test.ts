import { test } from "node:test";
import assert from "node:assert/strict";
import { checkHop, checkPath, enumerateInstances, findPath, nameFromPath, resolveFrom, type Lockfile } from "../src/lockfile.ts";

// A project with two copies of minimist: a hoisted 1.2.8 and a nested 1.2.5 under mkdirp.
const lock: Lockfile = {
  lockfileVersion: 3,
  name: "demo",
  packages: {
    "": { name: "demo", dependencies: { mkdirp: "^0.5.5", optimist: "^0.6.1" }, devDependencies: { argv: "npm:minimist@1.2.8" } },
    "node_modules/mkdirp": { version: "0.5.5", dependencies: { minimist: "1.2.5" } },
    "node_modules/mkdirp/node_modules/minimist": { version: "1.2.5" },
    "node_modules/optimist": { version: "0.6.1", dependencies: { minimist: "~0.0.1", wordwrap: "~0.0.2" } },
    "node_modules/optimist/node_modules/minimist": { version: "0.0.10" },
    "node_modules/wordwrap": { version: "0.0.3" },
    "node_modules/minimist": { version: "1.2.8" },
    "node_modules/argv": { name: "minimist", version: "1.2.8", dev: true },
  },
};

test("nameFromPath handles nesting and scopes", () => {
  assert.equal(nameFromPath("node_modules/a/node_modules/b"), "b");
  assert.equal(nameFromPath("node_modules/@s/x"), "@s/x");
  assert.equal(nameFromPath("node_modules/a/node_modules/@s/x"), "@s/x");
  assert.equal(nameFromPath("packages/foo"), null);
});

test("enumerates every instance, uses the name field for aliases, marks dev", () => {
  const r = enumerateInstances(lock, "minimist");
  assert.ok(r.ok);
  const got = r.instances.map((i) => `${i.path}@${i.version}${i.dev ? " dev" : ""}`).sort();
  assert.deepEqual(got, [
    "node_modules/argv@1.2.8 dev",
    "node_modules/minimist@1.2.8",
    "node_modules/mkdirp/node_modules/minimist@1.2.5",
    "node_modules/optimist/node_modules/minimist@0.0.10",
  ]);
  const argv = enumerateInstances(lock, "argv");
  assert.ok(argv.ok && argv.instances.length === 0, "an alias key is not an instance of the alias name");
});

test("Node resolution: nested copy wins, else walk up to the root", () => {
  assert.equal(resolveFrom(lock, "node_modules/mkdirp", "minimist"), "node_modules/mkdirp/node_modules/minimist");
  assert.equal(resolveFrom(lock, "node_modules/optimist", "wordwrap"), "node_modules/wordwrap");
  assert.equal(resolveFrom(lock, "", "minimist"), "node_modules/minimist");
  assert.equal(resolveFrom(lock, "node_modules/optimist", "nope"), null);
});

test("checkPath accepts a real path and names the broken hop of a fake one", () => {
  assert.equal(checkPath(lock, ["", "node_modules/mkdirp", "node_modules/mkdirp/node_modules/minimist"]), null);
  assert.match(checkPath(lock, ["", "node_modules/mkdirp", "node_modules/minimist"])!, /resolves to "node_modules\/mkdirp\/node_modules\/minimist"/);
  assert.match(checkPath(lock, ["", "node_modules/wordwrap"])!, /does not declare/);
  assert.match(checkPath(lock, ["", "node_modules/ghost"])!, /not in the lockfile/);
  assert.match(checkPath(lock, ["node_modules/mkdirp", "node_modules/mkdirp/node_modules/minimist"])!, /must start at the project root/);
  assert.equal(checkPath(lock, ["", "node_modules/argv"]), null, "dev dependency of the root through an alias");
});

test("findPath returns a path that checkPath accepts", () => {
  for (const t of ["node_modules/mkdirp/node_modules/minimist", "node_modules/optimist/node_modules/minimist", "node_modules/wordwrap", "node_modules/argv"]) {
    const p = findPath(lock, t);
    assert.ok(p, t);
    assert.equal(checkPath(lock, p), null, t);
  }
  assert.equal(findPath(lock, "node_modules/minimist"), null, "the hoisted 1.2.8 is installed but nothing in this tree requires it");
});

test("unsupported shapes are undecidable, never empty", () => {
  assert.equal(enumerateInstances({ lockfileVersion: 1 } as Lockfile, "x").ok, false);
  const linked: Lockfile = { lockfileVersion: 3, packages: { "": {}, "node_modules/x": { link: true, resolved: "packages/x" }, "packages/x": { name: "x", version: "1.0.0" } } };
  assert.equal(enumerateInstances(linked, "x").ok, false);
  const bundled: Lockfile = { lockfileVersion: 2, packages: { "": {}, "node_modules/a/node_modules/x": { version: "1.0.0", inBundle: true } } };
  assert.equal(enumerateInstances(bundled, "x").ok, false);
});

test("a hop is only accepted for an own declared dependency, not an inherited property name", () => {
  const bare: Lockfile = { lockfileVersion: 3, packages: { "": { name: "x" }, "node_modules/constructor": { version: "1.0.0" } } };
  assert.notEqual(checkHop(bare, "", "node_modules/constructor"), null);
});
