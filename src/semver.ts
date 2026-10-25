// SemVer 2.0.0 parsing and precedence (https://semver.org/spec/v2.0.0.html, section 11).
// Deliberately not node-semver: node-semver's range matching treats prereleases differently,
// and OSV's SEMVER range type is defined against the SemVer 2.0 precedence rules.

export interface SemVer {
  major: bigint;
  minor: bigint;
  patch: bigint;
  pre: (bigint | string)[];
  build: string[];
  raw: string;
}

const NUM = /^(0|[1-9]\d*)$/;
const IDENT = /^[0-9A-Za-z-]+$/;

/** Parse a SemVer 2.0 string. Returns null for anything that is not strictly valid (including a leading "v"). */
export function parseSemVer(raw: string): SemVer | null {
  if (typeof raw !== "string") return null;
  let rest = raw;
  let build: string[] = [];
  const plus = rest.indexOf("+");
  if (plus >= 0) {
    build = rest.slice(plus + 1).split(".");
    rest = rest.slice(0, plus);
    if (build.some((b) => !IDENT.test(b))) return null;
  }
  let pre: (bigint | string)[] = [];
  const dash = rest.indexOf("-");
  if (dash >= 0) {
    const parts = rest.slice(dash + 1).split(".");
    rest = rest.slice(0, dash);
    for (const p of parts) {
      if (!IDENT.test(p)) return null;
      if (/^\d+$/.test(p)) {
        if (!NUM.test(p)) return null; // numeric identifiers must not have leading zeros
        pre.push(BigInt(p));
      } else {
        pre.push(p);
      }
    }
  }
  const core = rest.split(".");
  if (core.length !== 3 || core.some((c) => !NUM.test(c))) return null;
  return { major: BigInt(core[0]), minor: BigInt(core[1]), patch: BigInt(core[2]), pre, build, raw };
}

function cmpBig(a: bigint, b: bigint): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** SemVer 2.0 precedence: negative if a < b, 0 if equal precedence, positive if a > b. Build metadata is ignored. */
export function compareSemVer(a: SemVer, b: SemVer): number {
  const c = cmpBig(a.major, b.major) || cmpBig(a.minor, b.minor) || cmpBig(a.patch, b.patch);
  if (c) return c;
  if (a.pre.length === 0 && b.pre.length === 0) return 0;
  if (a.pre.length === 0) return 1; // a normal version has higher precedence than a prerelease
  if (b.pre.length === 0) return -1;
  const n = Math.min(a.pre.length, b.pre.length);
  for (let i = 0; i < n; i++) {
    const x = a.pre[i];
    const y = b.pre[i];
    if (typeof x === "bigint" && typeof y === "bigint") {
      const d = cmpBig(x, y);
      if (d) return d;
    } else if (typeof x === "bigint") {
      return -1; // numeric identifiers have lower precedence than alphanumeric ones
    } else if (typeof y === "bigint") {
      return 1;
    } else if (x !== y) {
      return x < y ? -1 : 1; // ASCII order
    }
  }
  return cmpBig(BigInt(a.pre.length), BigInt(b.pre.length));
}
