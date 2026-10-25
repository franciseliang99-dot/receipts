// The explanation graph: what the investigator hands to the verifier. Every edge carries evidence pointers into
// snapshots; an edge without evidence is invalid at the schema level.

export type NodeType = "Project" | "Package" | "Advisory" | "Symbol" | "CodeSite";

export interface GraphNode {
  id: string;
  type: NodeType;
  label?: string;
  // Package
  name?: string;
  version?: string;
  install_path?: string;
  dev?: boolean;
  optional?: boolean;
  // Advisory: snapshot of its OSV record query
  record?: string;
  // Symbol
  symbol?: string;
  // CodeSite
  file?: string;
  line?: number;
}

export type EdgeType =
  | "DEPENDS_ON"
  | "MATCHES"
  | "IN_RANGE"
  | "OUT_OF_RANGE"
  | "RANGE_UNKNOWN"
  | "ALIAS_OF"
  | "WITHDRAWN"
  | "NAMES_SYMBOL"
  | "REFERENCES";

/** JSON evidence: the value at `pointer` must equal `expected` after RFC 8785 canonicalisation. */
export interface JsonEvidence {
  snapshot: string;
  pointer: string;
  expected: unknown;
}
/** Quote evidence: `quote` must occur verbatim inside the string at `pointer` (advisory prose). */
export interface QuoteEvidence {
  snapshot: string;
  pointer: string;
  quote: string;
}
/** Text evidence: bytes [byte_start, byte_end) of a text snapshot must equal `expected_text` (source code). */
export interface TextEvidence {
  snapshot: string;
  byte_start: number;
  byte_end: number;
  expected_text: string;
}
export type Evidence = JsonEvidence | QuoteEvidence | TextEvidence;

export interface GraphEdge {
  id: string;
  type: EdgeType;
  from: string;
  to: string;
  evidence: Evidence[];
  note?: string;
}

export type Verdict = "affected" | "not_affected" | "unknown";

export interface Derivation {
  verdict: Verdict;
  rule: "R1" | "R2" | "R3";
  /** Edge ids the conclusion is drawn from. */
  edges: string[];
  /** R2 premise: the set of installed instances is complete. Checked by V2/V6, never ablated by V5. */
  premise_instances_complete?: boolean;
}

/** What was asked, bound to the input snapshots by the tool layer (not by the model). */
export interface Question {
  package: string;
  ecosystem: "npm";
  lockfile: string; // snapshot sha256
  advisory_list: string; // snapshot sha256 of the Zetaris query listing advisories for the package
}

export interface ExplanationGraph {
  schema: "receipts/graph@1";
  question: Question;
  nodes: GraphNode[];
  edges: GraphEdge[];
  derivation: Derivation;
}

export const PROJECT_ID = "project";
export const pkgNodeId = (installPath: string) => `pkg:${installPath}`;
export const advNodeId = (id: string) => `adv:${id}`;
