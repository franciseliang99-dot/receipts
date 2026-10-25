# Sponsor technology in Receipts

This file explains where each sponsor's technology sits in Receipts and what it does there.
It also says which parts were written before the hackathon window.

```
lockfile ──┐
           ├─> case file ──> Nightshift (meterless/auto -> NVIDIA Nemotron) ──> claimed graph ──> verifier V1-V6 ──> answer
Zetaris ───┘        ^                                                                  |
(GitHub advisories,  └──────────── H-MEM hints (graded after each run) <─── proved facts ┘
 OSV records)
```

## Zetaris: the data plane for advisory data

Receipts never calls the advisory APIs itself. Every advisory record it reasons about is read through Zetaris.

- For each question, `src/zetaris.ts` registers two public sources as **Lightning REST tables** (`CREATE LIGHTNING REST TABLE ... REQUEST(endpoint ..., method "get", response_type "json")`):
  - `ghsa_rest.npm_<pkg>_<hash>`: the GitHub Advisory Database list of advisories that name the npm package.
  - `osv_rest.rec_<id>`: the OSV.dev record of one advisory, with its affected ranges, aliases and withdrawn date.
- It then queries them with SQL through the Zetaris REST endpoint `/sql-editor/sqls/run`,
  for example `SELECT to_json(struct(*)) AS row FROM ghsa_rest.<table> ORDER BY ghsa_id`.
- Each query result is stored as a content-addressed snapshot (named by its sha256). The verifier reads **only** those
  snapshots, so every edge in the explanation points to exact bytes that came out of Zetaris. `replay` re-verifies a
  run offline from them, and the `snapshot` tamper test shows that a single changed byte is caught.

Why it matters for the track: the "why" is only checkable if the evidence is frozen. Zetaris gives one SQL surface over
several outside sources, and Receipts turns each answer from that surface into a fixed, hashable piece of evidence.

Only public advisory data goes into Zetaris. The project's own lockfile and source stay on the local machine.

## Meterless Nightshift: the model runtime

All model calls go to Nightshift's local OpenAI-compatible runtime (`src/llm.ts`, default `http://127.0.0.1:8088/v1`).

- Requests ask for `meterless/auto` and carry the headers `meterless-app: receipts` and `meterless-scope: user`,
  so Nightshift does the routing and the accounting per app.
- `receipts status` reports Nightshift as online, unauthorized or offline, and the run log records which model was
  requested and which one actually served each round (`transcript.json` → `model_served`).
- Receipts does not pin a model to make the demo look better. In our runs Nightshift routed `meterless/auto` to a small
  Nemotron model. It made real mistakes: it invented an advisory id and put a fixed version inside a range. The verifier
  caught both and sent the reasons back. That loop is what this track asks for.

## Meterless H-MEM: memory that is checked, not trusted

`vendor/hmem` is the Meterless H-MEM reference engine, copied without changes (Apache-2.0, upstream commit and path in
`vendor/hmem/SOURCE.md`). `npm run hmem:conformance` runs the engine's own conformance suite against that copy: 13 of 13.

How Receipts uses it (`src/memory.ts`):

- **What is stored:** only range facts that the verifier proved on a run, tagged
  `fact:range|<package>@<version>|<advisory>|<IN_RANGE or OUT_OF_RANGE>`. A claim the model made but the verifier did
  not prove is never stored.
- **How it is used:** on the next run, matching facts are recalled and given to the model as *hints*. They are labelled
  as hints, not as evidence. The verifier still checks every edge against the snapshots.
- **Grading:** after the run, each hint is compared with what the verifier proved. If they agree, the hint is graded
  `helpful`. If they contradict, it is graded `wrong`: H-MEM lowers its confidence, tags it for review, and it is not
  offered again.
- Demo: `plant-hint minimist 0.0.10 GHSA-xvch-5gv4-984h OUT_OF_RANGE` plants a wrong fact. The next run is still
  verified, and the planted fact is graded `wrong`.

## NVIDIA: Nemotron through Nightshift

NVIDIA is connected as a provider inside Nightshift (an NVIDIA API key in Nightshift > Providers). Receipts does not
call NVIDIA directly. Nightshift's router chose `nvidia/nemotron-3.5-bolt-e4b` for every round in our recorded runs. The
model's job is the part that needs language: reading the case file and the advisory text and proposing an explanation
graph. Everything after that is deterministic code.

## Cursor

The rules ask teams to use Cursor for development. Here is exactly how it was used, without overstating it:

- The verifier core and the live layer were written with Claude Code before Cursor was set up for this project.
- After that, features were written in Cursor's agent (the `cursor-agent` CLI, model Auto) from a written task brief,
  then reviewed, tested and committed:
  - `explain`: prints a run's verdict as a tree of checked edges (`src/explain.ts`, `test/explain.test.ts`).
  - The "Why, as a graph" SVG on the HTML receipt page (`whySvg()` in `src/render.ts`, plus its test).
- In our working repository, the commits for these two features say in their message that they were written in Cursor.
- `.cursorignore` keeps internal notes, run outputs and env files out of Cursor's context.

## What existed before the hackathon window

- `DESIGN.md` (the design of the verifier and the graph format) was written before the build window. It holds internal notes
  and is not part of the submitted tree.
- `vendor/hmem` is upstream Meterless code, unchanged.
- Everything else in `src/`, `test/` and `demo/` was written during the window (all commits are dated 2026-10-25).
  This public repository is a clean export of the reviewed files with a single commit. We can share the full
  development history on request.
