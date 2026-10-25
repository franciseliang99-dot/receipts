// npm lockfile reading for V2 / V6: enumerate every installed instance of a package, and rebuild or check
// dependency paths with Node's module resolution walk. Only lockfileVersion 2 and 3 (the `packages` section)
// are supported; version 1 and unhandled shapes are reported as undecidable instead of guessed.

export interface LockEntry {
  name?: string;
  version?: string;
  resolved?: string;
  link?: boolean;
  inBundle?: boolean;
  dev?: boolean;
  optional?: boolean;
  devOptional?: boolean;
  peer?: boolean;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

export interface Lockfile {
  lockfileVersion?: number;
  name?: string;
  packages?: Record<string, LockEntry>;
}

export interface Instance {
  path: string; // key in `packages`, e.g. "node_modules/a/node_modules/minimist"
  name: string;
  version: string;
  dev: boolean;
  optional: boolean;
}

export type Enumeration =
  | { ok: true; instances: Instance[] }
  | { ok: false; reason: string };

const NM = "node_modules/";

/** Package name of a `packages` key, from its last node_modules segment (handles @scope/name). */
export function nameFromPath(path: string): string | null {
  const i = path.lastIndexOf(NM);
  if (i < 0) return null;
  const tail = path.slice(i + NM.length);
  const parts = tail.split("/");
  if (parts[0].startsWith("@")) return parts.length === 2 ? `${parts[0]}/${parts[1]}` : null;
  return parts.length === 1 ? parts[0] : null;
}

/** Real package name of an entry: the `name` field wins (npm aliases), else the path segment. */
export function entryName(path: string, e: LockEntry): string | null {
  return typeof e.name === "string" && e.name ? e.name : nameFromPath(path);
}

export function checkSupported(lock: Lockfile): string | null {
  if (lock.lockfileVersion !== 2 && lock.lockfileVersion !== 3) {
    return `lockfileVersion ${String(lock.lockfileVersion)} is not supported (only 2 and 3, which carry the packages section)`;
  }
  if (!lock.packages || typeof lock.packages !== "object") return "lockfile has no packages section";
  return null;
}

/** Every installed instance of `pkg`. Undecidable if the package appears in a shape we do not handle. */
export function enumerateInstances(lock: Lockfile, pkg: string): Enumeration {
  const unsupported = checkSupported(lock);
  if (unsupported) return { ok: false, reason: unsupported };
  const out: Instance[] = [];
  for (const [path, e] of Object.entries(lock.packages!)) {
    if (path === "") continue;
    const n = entryName(path, e);
    if (n !== pkg) continue; // an alias whose path says `pkg` but whose real package differs is not an instance of pkg
    if (!path.includes(NM)) return { ok: false, reason: `"${path}" is a workspace folder for ${pkg}; workspaces are not supported yet` };
    if (e.link) return { ok: false, reason: `"${path}" is a link entry; links are not supported yet` };
    if (e.inBundle) return { ok: false, reason: `"${path}" is a bundled dependency; bundled entries are not supported yet` };
    if (typeof e.version !== "string") return { ok: false, reason: `"${path}" has no version` };
    out.push({ path, name: pkg, version: e.version, dev: !!(e.dev || e.devOptional), optional: !!(e.optional || e.devOptional) });
  }
  return { ok: true, instances: out };
}

function declaredDeps(e: LockEntry, isRoot: boolean): Record<string, string> {
  return {
    ...(e.peerDependencies ?? {}),
    ...(e.optionalDependencies ?? {}),
    ...(isRoot ? (e.devDependencies ?? {}) : {}),
    ...(e.dependencies ?? {}),
  };
}

/**
 * Node's resolution walk: from the package installed at `fromPath`, which `packages` key does `require(depKey)` load?
 * Looks in fromPath/node_modules/depKey, then in each ancestor's node_modules, then the root.
 */
export function resolveFrom(lock: Lockfile, fromPath: string, depKey: string): string | null {
  const pk = lock.packages!;
  let base = fromPath;
  for (;;) {
    const cand = (base === "" ? "" : base + "/") + NM + depKey;
    if (Object.prototype.hasOwnProperty.call(pk, cand)) return cand;
    if (base === "") return null;
    const i = base.lastIndexOf("/" + NM);
    base = i < 0 ? "" : base.slice(0, i);
  }
}

/** One hop: does the package at `from` declare a dependency that Node resolves to exactly `to`? */
export function checkHop(lock: Lockfile, from: string, to: string): string | null {
  const unsupported = checkSupported(lock);
  if (unsupported) return unsupported;
  const pk = lock.packages!;
  const e = pk[from];
  if (!e) return `"${from}" is not in the lockfile`;
  if (!pk[to]) return `"${to}" is not in the lockfile`;
  const key = nameFromPath(to);
  if (!key || !Object.hasOwn(declaredDeps(e, from === ""), key)) return `"${from || "<root>"}" does not declare a dependency on "${key ?? to}"`;
  const resolved = resolveFrom(lock, from, key);
  if (resolved !== to) return `from "${from || "<root>"}", "${key}" resolves to "${resolved ?? "nothing"}", not "${to}"`;
  return null;
}

/** The lockfile field that declares the hop (for evidence pointers), e.g. "dependencies". */
export function hopField(lock: Lockfile, from: string, to: string): string | null {
  const e = lock.packages?.[from];
  const key = nameFromPath(to);
  if (!e || !key) return null;
  for (const f of ["dependencies", "optionalDependencies", "peerDependencies", ...(from === "" ? ["devDependencies"] : [])] as const) {
    const d = (e as Record<string, unknown>)[f] as Record<string, string> | undefined;
    if (d && key in d) return f;
  }
  return null;
}

/** Check one claimed path ["", p1, ..., target]: every hop must be a declared dependency that resolves to exactly the next key. */
export function checkPath(lock: Lockfile, path: string[]): string | null {
  const unsupported = checkSupported(lock);
  if (unsupported) return unsupported;
  if (path.length < 2 || path[0] !== "") return `a dependency path must start at the project root ("") and have at least one hop`;
  for (let i = 0; i + 1 < path.length; i++) {
    const err = checkHop(lock, path[i], path[i + 1]);
    if (err) return err;
  }
  return null;
}

/** Shortest dependency path from the root to `target` (breadth-first over declared dependencies). */
export function findPath(lock: Lockfile, target: string): string[] | null {
  if (checkSupported(lock)) return null;
  const pk = lock.packages!;
  const prev = new Map<string, string>();
  const seen = new Set<string>([""]);
  const queue = [""];
  while (queue.length) {
    const cur = queue.shift()!;
    if (cur === target) {
      const out = [cur];
      let c = cur;
      while (c !== "") {
        c = prev.get(c)!;
        out.unshift(c);
      }
      return out;
    }
    const e = pk[cur];
    if (!e) continue;
    for (const dep of Object.keys(declaredDeps(e, cur === "")).sort()) {
      const r = resolveFrom(lock, cur, dep);
      if (r !== null && !seen.has(r)) {
        seen.add(r);
        prev.set(r, cur);
        queue.push(r);
      }
    }
  }
  return null;
}
