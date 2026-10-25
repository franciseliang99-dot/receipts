// V3: is a version inside an OSV record's affected ranges? Recomputed by the verifier, never taken from the model.
// Implements the IsVulnerable pseudocode of the OSV schema ("Evaluation" section) for SEMVER ranges.
// Anything outside that (GIT ranges, ECOSYSTEM ranges, unparseable versions, ambiguous event order)
// is reported as "undecidable" rather than guessed.

import { compareSemVer, parseSemVer, type SemVer } from "./semver.ts";

export type RangeVerdict =
  | { kind: "in" }
  | { kind: "out" }
  | { kind: "undecidable"; reason: string };

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}
export interface OsvRange {
  type: string;
  events: OsvEvent[];
  repo?: string;
}
export interface OsvAffected {
  package?: { ecosystem?: string; name?: string; purl?: string };
  ranges?: OsvRange[];
  versions?: string[];
}

type Ev = { kind: "introduced" | "fixed" | "last_affected" | "limit"; v: SemVer | "zero" };

function eventOf(e: OsvEvent): { kind: Ev["kind"]; value: string } | string {
  const keys = (["introduced", "fixed", "last_affected", "limit"] as const).filter((k) => e[k] !== undefined);
  if (keys.length !== 1) return `event must have exactly one of introduced/fixed/last_affected/limit, got ${JSON.stringify(e)}`;
  return { kind: keys[0], value: String(e[keys[0]]) };
}

function cmp(a: SemVer | "zero", b: SemVer | "zero"): number {
  if (a === "zero") return b === "zero" ? 0 : -1;
  if (b === "zero") return 1;
  return compareSemVer(a, b);
}

/** Evaluate one SEMVER range. */
export function inSemverRange(version: SemVer, range: OsvRange): RangeVerdict {
  if (range.type !== "SEMVER") return { kind: "undecidable", reason: `range type ${range.type} is not supported (only SEMVER)` };
  if (!Array.isArray(range.events) || range.events.length === 0) return { kind: "undecidable", reason: "range has no events" };
  const evs: Ev[] = [];
  let hasFixed = false;
  let hasLast = false;
  for (const raw of range.events) {
    const e = eventOf(raw);
    if (typeof e === "string") return { kind: "undecidable", reason: e };
    if (e.kind === "fixed") hasFixed = true;
    if (e.kind === "last_affected") hasLast = true;
    if (e.kind === "introduced" && e.value === "0") {
      evs.push({ kind: e.kind, v: "zero" });
      continue;
    }
    const v = parseSemVer(e.value);
    if (!v) return { kind: "undecidable", reason: `event version ${JSON.stringify(e.value)} is not valid SemVer 2.0` };
    evs.push({ kind: e.kind, v });
  }
  if (hasFixed && hasLast) return { kind: "undecidable", reason: "range mixes fixed and last_affected (not allowed by the schema)" };
  if (evs.some((e) => e.kind === "limit")) {
    // limit only has meaning for GIT ranges; for SEMVER we refuse to guess.
    return { kind: "undecidable", reason: "limit event on a SEMVER range" };
  }
  const sorted = [...evs].sort((a, b) => cmp(a.v, b.v));
  for (let i = 1; i < sorted.length; i++) {
    if (cmp(sorted[i - 1].v, sorted[i].v) === 0 && sorted[i - 1].kind !== sorted[i].kind) {
      return { kind: "undecidable", reason: "two different events at the same version; order is ambiguous" };
    }
  }
  let vulnerable = false;
  for (const e of sorted) {
    if (e.kind === "introduced" && cmp(version, e.v) >= 0) vulnerable = true;
    else if (e.kind === "fixed" && cmp(version, e.v) >= 0) vulnerable = false;
    else if (e.kind === "last_affected" && cmp(version, e.v) > 0) vulnerable = false;
  }
  return vulnerable ? { kind: "in" } : { kind: "out" };
}

/**
 * Is `version` of `pkgName` affected by this OSV record's `affected[]` entries?
 * Union over every matching affected entry: explicit versions list plus every range.
 * If any entry for the package is undecidable and no entry says "in", the answer is undecidable.
 */
export function isAffected(version: string, pkgName: string, affected: OsvAffected[], ecosystem = "npm"): RangeVerdict {
  const v = parseSemVer(version);
  const entries = affected.filter((a) => a.package?.name === pkgName && a.package?.ecosystem === ecosystem);
  if (entries.length === 0) return { kind: "undecidable", reason: `record has no affected entry for ${ecosystem}/${pkgName}` };
  let undecided: string | null = null;
  for (const a of entries) {
    if (!a.ranges?.length && !a.versions?.length) {
      undecided ??= "affected entry lists neither ranges nor versions";
      continue;
    }
    if (Array.isArray(a.versions) && a.versions.includes(version)) return { kind: "in" };
    for (const r of a.ranges ?? []) {
      if (!v) {
        undecided ??= `installed version ${JSON.stringify(version)} is not valid SemVer 2.0`;
        continue;
      }
      const res = inSemverRange(v, r);
      if (res.kind === "in") return res;
      if (res.kind === "undecidable") undecided ??= res.reason;
    }
  }
  return undecided ? { kind: "undecidable", reason: undecided } : { kind: "out" };
}
