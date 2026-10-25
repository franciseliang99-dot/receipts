# Receipts

**An agent whose "why" has to survive a machine check before it is shown to anyone.**

Ask Receipts: *does this project install a version of `minimist` that a security advisory covers, and why?*
It reads the project's lockfile, pulls the advisories through **Zetaris**, asks a model served by **Meterless Nightshift**
(routed to **NVIDIA Nemotron**) to explain the answer as a graph, and then a deterministic verifier re-derives every edge of
that graph from stored snapshots. An edge that can't be re-derived is marked *unverified*, and an answer that rests on one
is not shown as an answer. The verifier's reasons go back to the model, which gets two tries to fix its claims.
Facts that were proved go into **Meterless H-MEM**. On later runs they come back as hints, and each hint is graded
against what the verifier proves on that run.

Track 02 · *The Agent That Can Explain Why*.

Demo video (2:34): [receipts-demo.mp4](https://github.com/franciseliang99-dot/receipts/releases/download/v1.0/receipts-demo.mp4), attached to the [v1.0 release](https://github.com/franciseliang99-dot/receipts/releases/tag/v1.0). Narration is synthetic text-to-speech.
Slide deck: [receipts-deck.pdf](https://github.com/franciseliang99-dot/receipts/releases/download/v1.0/receipts-deck.pdf) (12 slides).

```
project ──DEPENDS_ON──> optimist@0.6.1 ──DEPENDS_ON──> minimist@0.0.10 ──IN_RANGE──> GHSA-xvch-5gv4-984h
            evidence: lockfile /packages/.../dependencies/minimist      evidence: lockfile version + OSV "affected" ranges
```

## What a run looks like

From a real run on `demo/legacy-cli` (2026-10-25, empty memory):

```
· lockfile package-lock.json: 2 instance(s) of minimist: 1.2.8 at node_modules/minimist, 0.0.10 at node_modules/optimist/node_modules/minimist
· Zetaris: 3 advisories name minimist
· round 0: nvidia/nemotron-3.5-bolt-e4b claimed affected; verifier rejected it (2 reason(s))
· round 1: nvidia/nemotron-3.5-bolt-e4b claimed affected; verifier rejected it (2 reason(s))
· round 2: nvidia/nemotron-3.5-bolt-e4b claimed affected; verifier verified it
```

The answer it wrote (`answer.txt`), built only from proved edges:

```
Yes: this project installs a version of minimist that a security advisory covers.
- minimist@0.0.10 at node_modules/optimist/node_modules/minimist is inside the affected range of GHSA-vh95-rmgr-6w4m, installed through optimist@0.6.1.
- minimist@0.0.10 at node_modules/optimist/node_modules/minimist is inside the affected range of GHSA-xvch-5gv4-984h, installed through optimist@0.6.1.
Ignored as withdrawn: GHSA-7fhm-mqm4-2wp7.
Checked: 2 installed instance(s) against 2 advisory group(s); 15 of 17 edges proved from snapshots.
This says which installed versions are covered by an advisory. It does not say whether the vulnerable code is reachable.
```

The verdict was right on round 0, but the reasons were wrong, and the verifier rejected them. In round 0 the model cited an
advisory id that does not exist (`GHHA-xvch-…`). In round 1 it said `minimist@1.2.8` is inside GHSA-vh95, but that advisory
was fixed in 1.2.3. Each rejection went back to the model with the failing check and the pointer into the snapshot. Most
tools would have shown the round-0 answer, because its verdict was right.

Every run writes a folder under `runs/`. It holds the answer, the explanation graph, the verifier report, an OpenVEX draft,
an HTML page, the model transcript, and every input snapshot, each named by its sha256.

## Install

Requirements: Node.js 23.6 or newer · a local Zetaris platform (the hackathon's Docker setup, REST API on `:8888`) · Meterless
Nightshift running locally (runtime on `127.0.0.1:8088`), with an NVIDIA API key added in Nightshift > Providers.

```sh
npm install
cp .env.example .env        # fill in the Zetaris API key and the Nightshift runtime token
npm run receipts -- status  # both must say reachable / online
```

## Use

```sh
npm run receipts -- check demo/legacy-cli minimist     # investigate, verify, write runs/<id>/
npm run receipts -- check demo/patched-cli minimist    # same CLI on minimist 1.2.8 -> NOT_AFFECTED (verified)
npm run receipts -- explain runs/<id>                  # the verdict as a tree of checked edges
npm run receipts -- replay runs/<id>                   # re-verify offline from the snapshots; must match the saved report
npm run receipts -- tamper runs/<id> flip              # inject a fake fact and watch the verifier refuse it
                                                       #   kinds: flip | evidence | quote | snapshot
npm run receipts -- plant-hint minimist 0.0.10 GHSA-xvch-5gv4-984h OUT_OF_RANGE   # a deliberately wrong memory
open runs/<id>/index.html                              # the receipt page, with the "why" drawn as a graph
```

`check` exits 0 only when the verdict is verified. `tamper` exits 0 when the injected fact was caught.

## What the verifier checks

The verifier is plain TypeScript. It makes no model calls and no network calls, and it reads only the snapshot store.

| check | question |
|---|---|
| V1 | Does every piece of evidence resolve in its snapshot? (JSON pointer + expected value, verbatim quote, or exact byte range. Snapshots are re-hashed on every read.) |
| V1b | Does a quoted advisory sentence really contain the function name it is cited for? |
| V2 | Is every dependency hop real under Node's resolution rules? Does every package node match the lockfile entry it names (path, version and package name)? A V2 failure blocks any verdict. |
| V3 | Recomputes "is version X inside these OSV ranges" with its own SemVer code. Ranges it can't evaluate become *undecidable*, never guessed. |
| V4 | Does the verdict follow from the edges it cites? |
| V5 | Ablation: which edges does the verdict actually need? Unneeded edges are marked as such. |
| V6 | Coverage: does every installed copy have a verified verdict against every non-withdrawn advisory group? Aliases are merged so one CVE is not counted twice. |

An answer is shown as verified only if the edges it rests on are proved and V4, V5 and V6 pass. Otherwise it is
**unknown**, with the reasons listed.

What it deliberately does not claim: whether the vulnerable code is reachable from your program. Receipts never outputs
`vulnerable_code_not_in_execute_path`. It tells you which installed versions an advisory covers, and it proves that part.

## Measured on the demo projects (2026-10-25)

| what | result |
|---|---|
| `check demo/legacy-cli minimist`, empty memory | AFFECTED, verified on round 2 (rounds 0 and 1 rejected, reasons above) |
| `check demo/patched-cli minimist` | NOT_AFFECTED, verified on round 0 |
| `check demo/legacy-cli minimist` again, with 4 proved facts and 1 planted wrong fact in memory | AFFECTED, verified on round 0. Planted fact graded `wrong` (confidence down, flagged for review, not offered again) |
| `replay` of the first run | identical to the saved report |
| `tamper` flip / evidence / quote / snapshot | 4 of 4 caught |
| unit tests (`npm test`) | 47 of 47 pass, including fault-injection tests that each plant one kind of wrong claim |
| H-MEM conformance suite on the vendored engine (`npm run hmem:conformance`) | 13 of 13 |

These are single runs, so read them as observations, not benchmarks. Model behaviour varies between runs.

## Limits

- npm only, with `package-lock.json` / `npm-shrinkwrap.json` v2 or v3. Linked, bundled and workspace packages make the instance set undecidable, and the answer becomes unknown.
- The advisory list comes from one page of up to 100 GitHub advisories per package. Receipts warns when it reaches that limit.
- OSV `GIT` and `ECOSYSTEM` ranges, and records that mix `fixed` with `last_affected`, are treated as undecidable.
- The OpenVEX file is a draft for a person to review. It is not a published statement.

## Sponsor technology

See [SPONSORS.md](SPONSORS.md) for how Zetaris, Meterless (Nightshift and H-MEM), NVIDIA Nemotron and Cursor are used.

## License

Apache-2.0 (see `LICENSE`). `vendor/hmem` keeps its own upstream Apache-2.0 license.

## Layout

```
src/        investigator, verifier, graph builder, Zetaris / Nightshift clients, H-MEM memory, renderer, CLI
test/       unit and fault-injection tests (offline)
demo/       two small npm projects with npm-generated lockfiles
vendor/hmem Meterless H-MEM reference engine, unchanged (Apache-2.0, see vendor/hmem/SOURCE.md)
```
