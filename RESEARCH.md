# Registry export (.reg v5) canonicalization matrix — research record

## Research question

Which registry value types and key shapes canonicalize to which exact
`.reg` text — and where do `regedit.exe /e` and `reg.exe export`
diverge?

NOT a .reg writer, NOT an import/deploy tool, NOT a second help page.
Deliverable: emitter differential + canonicalization rules with byte
evidence, plus a strict read-only inspector and a normalizing differ.

## Scope

- IN: v5 exports (`Windows Registry Editor Version 5.00`, UTF-16LE +
  BOM, CRLF) of synthetic keys under `HKCU\SOFTWARE\REStudyTmp*`
  (created/removed per run, absent→absent); REG_SZ incl. default,
  DWORD, QWORD, BINARY (short/wrap/multi-wrap/long-name),
  MULTI_SZ incl. empty element, EXPAND_SZ, REG_NONE (hex(0), 3-byte
  and empty, via .NET exact kind), empty keys, spaced names,
  subkey ordering (incl. ASCII mixed-case), value ordering
  (incl. ASCII mixed-case).
- OUT: writing/deploying .reg files (artifact is read-only),
  HKLM/other hives/user keys, exotic discriminants beyond REG_NONE
  (no exact-type producer API; native APIs out of scope),
  deletion-marker generation (parsed, never produced by exporters),
  security-relevant registry content of any kind.

## Safety boundary

Own scratch keys only. `reg_seed.ps1` refuses paths outside
`HKCU\...\REStudyTmp*`. `reg.exe import` runs ONLY on files our own
exporters just wrote, restoring our own scratch keys (round-trip
oracle), then everything is deleted. No payloads, no persistence, no
user data.

## Provenance

- Generators: `regedit.exe /e` and `reg.exe export` on Windows 10 Home
  build 26200 (`platform.platform()`: `Windows-11-10.0.26200-SP0`),
  pwsh 7.6.6, Python 3.12.6. Recorded in `matrix.json.environment`.
- Corpus setter: PowerShell/.NET exact types (REG_BINARY via byte
  arrays, REG_NONE via `RegistryValueKind.None`, etc.) — deliberately
  NOT `reg.exe add`, whose `/d` text parsing mangled a 30-byte hex
  string during feasibility (nibble shift observed; input-side quirk,
  out of scope, avoided by construction).
- Prior art: MS prose docs of the .reg layout, countless blog
  transcriptions, forensic parsers. Gap: no canonical
  differential/canonicalization study — wrap rule, ordering
  guarantees, and emitter equivalence were unwritten.

## Method

1. `scripts/reg_inspect.py`: strict v5 parser (exit 3 on malformed),
   stdlib only. BOM required, header required, continuations joined,
   sections/values/delete-markers parsed, hex payloads validated,
   QWORD/EXPAND/MULTI decoded (terminator framing handled, empty
   MULTI_SZ elements preserved).
2. `scripts/reg_seed.ps1`: confined exact-type corpus seeder
   (REG_SZ/EXPAND/DWORD/QWORD/BINARY/MULTI_SZ/SUBKEY plus REG_NONE
   via .NET exact kind).
3. `scripts/reg_matrix.py`: seeds 23 probes, exports each with BOTH
   emitters, parses both, byte-compares, then round-trips
   (delete→import→re-export) and compares bytes + model. Scratch tree
   removed in `finally`. Launches are spaced 20 s apart: regedit.exe
   carries a requireAdministrator manifest, so every launch raises a
   UAC consent prompt and rapid respawns get auto-denied (operability
   only; captured bytes unaffected).
4. `scripts/reg_diff.py`: semantic model differ (order-sensitive).
5. `tests/test_reg_study.py`: 24 platform-independent unit tests on
   hand-built synthetic text (24/24 green, no Windows needed).

## Experiment matrix (23 probes)

| Probe | Input | Finding |
| ----- | ----- | ------- |
| K00 | one REG_SZ | baseline shape: header, blank, `[key]`, `"S"="hello"`, trailing blank |
| K01 | default value | `@="defval"` |
| K02 | DWORD 42, 0 | `dword:0000002a`, `dword:00000000` — 8 lowercase hex, zero-padded |
| K03 | QWORD 0x1122334455667788 | `hex(b):88,77,...,11` — letter discriminant, LE bytes |
| K04 | BINARY 8 B | single `hex:` line |
| K05 | BINARY 30 B | wraps: 23 + 7 bytes |
| K06 | MULTI_SZ ["one","","two"] | `hex(7)` NUL-joined + NUL term; empty element = bare extra NUL; survives round-trip |
| K07 | EXPAND_SZ `%REStudyTmp%\sub` | `hex(2)` UTF-16LE + NUL term, content NOT expanded |
| K08 | empty key | bare `[key]` section, no values |
| K09 | name `a b` | verbatim in quotes |
| K10 | subkeys created c,a,b | exported a,b,c — SORTED |
| K11 | values created zeta,alpha,mid | exported zeta,alpha,mid — CREATION order, not sorted |
| K12 | BINARY 60 B | wraps 23 + 25 + 12 — continuation holds 25 |
| K13 | 10-char name, 30 B | first line 20, then 10 — prefix shifts the break |
| K14 | 20-char name, 30 B | first line 17, then 13 — refutes floor, fits ceil |
| K15 | 69-char name, 30 B | prefix 76: first line 1 byte, then 25 + 4 |
| K16 | 70-char name, 30 B | prefix 77: first line 1 byte, then 25 + 4 |
| K17 | 71-char name, 30 B | prefix 78: first line 1 byte, then 25 + 4 |
| K18 | 100-char name, 30 B | prefix 107: first line 1 byte, then 25 + 4 |
| K19 | subkeys created b1,A1,B2,a2 | exported A1,a2,b1,B2 — case-folded stable, not ordinal |
| K20 | values created zeta,Alpha,MID,beta | exported identical — creation order incl. mixed case |
| K21 | REG_NONE 3 B | `hex(0):01,02,03` — discriminant preserved, round-trip clean |
| K22 | REG_NONE empty | bare `hex(0):` — agreement, round-trip clean |

Emitter comparison: 23/23 BYTE-IDENTICAL (`regedit /e` vs `reg export`).
Round-trip: 23/23 byte-identical after delete→import→re-export.

## Canonicalization rules (observed, build-pinned)

1. UTF-16LE + BOM, CRLF, fixed header line, blank line after header
   and between/trailing sections.
2. `dword:` = exactly 8 lowercase hex digits.
3. `hex(b)` = 8 LE bytes; `hex:`/`hex(2)`/`hex(7)` analogous;
   REG_NONE is emitted as `hex(0)` (bare colon when empty).
4. Hex lines: the first line carries max(1, ceil((77 − P)/3)) bytes
   where P is the rendered prefix width (quoted name + `=hex:`);
   continuations carry 25 bytes. `\` continuation, 2-space indent,
   trailing comma retained before the backslash. The earlier
   floor((77 − P)/3) formula coincided at the old probe points
   (77 − P divisible by 3 there) and is superseded: K14 (P=27)
   carries 17, not 16; prefixes ≥77 columns still carry exactly
   1 first-line byte (K15–K18).
5. Subkey sections: ASCII case-folded stable order (K19:
   b1,A1,B2,a2 → A1,a2,b1,B2 — ordinal refuted). Values: registry
   enumeration (creation) order, including mixed-case ASCII names
   (K20) — asymmetric, explicitly refuted-sorted (H4).
6. Empty MULTI_SZ elements preserved; EXPAND_SZ never expanded.

## Hypotheses ledger

### H1 — The two emitters diverge somewhere in the knob set
Prediction: ≥1 probe with byte/semantic delta. Observation: 23/23
identical, deltas all empty. Verdict: REFUTED (scope).

### H2 — Hex wraps at a fixed byte count
Prediction: constant first-line bytes. Observation: 23/22/20 with
varying prefixes, all at 77 columns; continuations full at 25.
Verdict: REFINED to the 77-column rule (falsifiable, confirmed by
K12/K13 which were designed to break byte-count variants).

### H2b (R6-A) — The wrap rule is floor((77 − P)/3)
Prediction: K14 (P=27) carries 16 first-line bytes; P≥77 carries 0.
Observation: K14 carries 17; K15–K18 (P=76..107) carry exactly 1.
Both emitters agree byte-for-byte; round-trips clean. Verdict:
REFUTED as stated; REFINED to max(1, ceil((77 − P)/3)) with zero
residuals across all 8 wrap probes (old floor coincided wherever
77 − P was divisible by 3). Minimal pair: K13 (P=17, both formulas
give 20) vs K14 (P=27: floor 16, ceil 17, observed 17).

### H3 — Subkey sections export sorted
Prediction: c,a,b → a,b,c. Observation: exact. Verdict: SUPPORTED.

### H3b (R6-B) — Subkey sorting is ordinal (ASCIIbetical)
Prediction: [b1,A1,B2,a2] → A1,B2,a2,b1. Observation: A1,a2,b1,B2.
Verdict: REFUTED; ordering is ASCII case-folded stable. Tie-break
pairs (Ab vs aB) are UNPRODUCIBLE: the namespace folds case at
identity (scratch-proven: one key survives, first spelling; same
for value names) — documented, not probed. ASCII-only scope kept.

### H4 — Values export sorted like subkeys
Prediction: zeta,alpha,mid → alpha,mid,zeta. Observation: creation
order preserved. Verdict: REFUTED — asymmetry finding.

### H4b (R6-B) — The asymmetry breaks under mixed case
Prediction: [zeta,Alpha,MID,beta] exports sorted somehow.
Observation: creation order preserved (K20). Verdict: REFUTED —
asymmetry generalizes to mixed-case ASCII names.

### H5 — Import normalizes edge content (drops empty MULTI_SZ, etc.)
Prediction: round-trip delta on K06/K07. Observation: 23/23
byte-identical round-trips. Verdict: REFUTED.

### H6 (R6-C) — Exotic discriminants are out of reach
Prediction: no exact-type producer for hex(N) beyond inventoried
kinds. Observation: REG_NONE IS producible via .NET
`RegistryValueKind.None` (scratch-proven, then K21/K22): both
emitters emit `hex(0)` (bare colon when empty); import round-trip
preserves discriminant and bytes. Other discriminants (4,5,6,8,9,10)
remain UNPRODUCIBLE_WITH_CURRENT_ORACLE (no exact-type API; native
APIs out of scope). Verdict: NARROWED — REG_NONE closed, rest
documented unproducible.

## Determinism

Reconstruction-deterministic: delete → import own export →
re-export is byte-identical (23/23). No wall-clock or machine bytes
observed in v5 text exports (contrast: .lnk IDList bytes).

## Claim ledger

| Claim | Status | Evidence | Falsifier | Confidence |
| ----- | ------ | -------- | --------- | ---------- |
| Emitters byte-identical on all probes | OBSERVED | 23/23 sha256 equal | any divergent probe | high (scope) |
| Hex wrap: max(1, ceil((77−P)/3)) + 25s | OBSERVED | K05/K12/K13/K14–K18 widths, both emitters | a width residual | high (scope) |
| Subkeys ASCII-folded-stable, values creation order | OBSERVED | K10/K11/K19/K20 | counter-ordered probe | high (ASCII scope) |
| Round-trips byte-identical incl. edges + REG_NONE | OBSERVED | 23/23 | any lossy probe | high (scope) |
| Empty MULTI_SZ preserved | OBSERVED | K06 bytes + round-trip | dropped element | high |
| REG_NONE hex(0) preserved 3-byte + empty | OBSERVED | K21/K22 bytes + round-trip | dropped/altered discriminant | high (scope) |
| Tie-break ordering | UNPRODUCIBLE | namespace folds case at identity (scratch) | an exact-type tie producer | — |
| Non-REG_NONE exotic hex(N) | UNPRODUCIBLE_WITH_CURRENT_ORACLE | no exact-type API | a supported producer | — |
| Rules generalize beyond build 26200 | NOT CLAIMED | — | other-build matrix | — |

## R6 verdict

R6 OBSERVED (narrowed scope): axis A resolved to the ceil+min-one
rule (H2b), axis B resolved for ASCII folded/stable + creation order
(H3b/H4b, tie-break unproducible by construction), axis C resolved
for REG_NONE with the remaining discriminants documented
unproducible (H6). No locale/Unicode ordering claimed; no
universal-Windows claim. Replay: a targeted byte-replay of K14/K17
(after UAC backoff cleared) reproduced run-1 bytes exactly in both
emitters (regedit e2657bd2…, regexe identical; K17 f2810653… both
lanes) — the surprising wrap results are replay-confirmed, not
single-run. (An earlier immediate replay attempt hit UAC consent
degradation; spacing the launches resolved it.)

## Limitations

- One Windows build; one hive branch (HKCU synthetic).
- Residual R6 unknowns: non-ASCII ordering; tie-break (unproducible
  by namespace construction); non-REG_NONE exotic `hex(N)`
  (unproducible with the exact-type oracle); deletion markers
  parse-only.
- `reg.exe add` input parsing explicitly out of scope.
- regedit.exe launches need UAC consent spacing (≈20 s) under rapid
  respawn; replay attempts after a full run may hit consent
  degradation (see R6 verdict note).

## Privacy handling

- All key/value names synthetic (`REStudyTmp`, single letters).
- `matrix.json` contains no user paths, no SIDs, no machine data
  (machine-scanned before commit).
- No binary artifacts committed; corpus regenerates via
  `reg_matrix.py` on Windows.
