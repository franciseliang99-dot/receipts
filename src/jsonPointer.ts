// RFC 6901 JSON Pointer resolution. Returns { found: false } instead of throwing.

export function escapePointerToken(t: string): string {
  return t.replace(/~/g, "~0").replace(/\//g, "~1");
}

export function pointerOf(tokens: (string | number)[]): string {
  return tokens.map((t) => "/" + escapePointerToken(String(t))).join("");
}

export function resolvePointer(doc: unknown, pointer: string): { found: true; value: unknown } | { found: false; reason: string } {
  if (pointer === "") return { found: true, value: doc };
  if (!pointer.startsWith("/")) return { found: false, reason: `pointer must start with "/": ${pointer}` };
  let cur: unknown = doc;
  for (const rawTok of pointer.slice(1).split("/")) {
    const tok = rawTok.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(cur)) {
      if (!/^(0|[1-9]\d*)$/.test(tok) || Number(tok) >= cur.length) return { found: false, reason: `no array index ${tok}` };
      cur = cur[Number(tok)];
    } else if (cur !== null && typeof cur === "object") {
      if (!Object.prototype.hasOwnProperty.call(cur, tok)) return { found: false, reason: `no key ${JSON.stringify(tok)}` };
      cur = (cur as Record<string, unknown>)[tok];
    } else {
      return { found: false, reason: `cannot descend into a ${cur === null ? "null" : typeof cur} at ${JSON.stringify(tok)}` };
    }
  }
  return { found: true, value: cur };
}
