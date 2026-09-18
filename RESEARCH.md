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
  MULTI_SZ incl. empty element, EXPAND_SZ, empty keys, spaced names,
  subkey ordering, value ordering.
- OUT: writing/deploying .reg files (artifact is read-only),
  HKLM/other hives/user keys, exotic discriminants beyond inventory,
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
  arrays etc.) — deliberately NOT `reg.exe add`, whose `/d` text
  parsing mangled a 30-byte hex string during feasibility (nibble
  shift observed; input-side quirk, out of scope, avoided by
  construction).
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
2. `scripts/reg_seed.ps1`: confined exact-type corpus seeder.
3. `scripts/reg_matrix.py`: seeds 14 probes, exports each with BOTH
   emitters, parses both, byte-compares, then round-trips
   (delete→import→re-export) and compares bytes + model. Scratch tree
   removed in `finally`.
4. `scripts/reg_diff.py`: semantic model differ (order-sensitive).
5. `tests/test_reg_study.py`: 20 platform-independent unit tests on
   hand-built synthetic text (20/20 green, no Windows needed).

## Experiment matrix (14 probes)

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

Emitter comparison: 14/14 BYTE-IDENTICAL (`regedit /e` vs `reg export`).
Round-trip: 14/14 byte-identical after delete→import→re-export.

## Canonicalization rules (observed, build-pinned)

1. UTF-16LE + BOM, CRLF, fixed header line, blank line after header
   and between/trailing sections.
2. `dword:` = exactly 8 lowercase hex digits.
3. `hex(b)` = 8 LE bytes; `hex:`/`hex(2)`/`hex(7)` analogous.
4. Hex lines wrap at 77 content columns: `\` continuation, 2-space
   indent, trailing comma retained before the backslash. First-line
   byte count = floor((77 − len(prefix)) / 3); continuation = 25.
5. Subkey sections: alphabetical. Values: registry enumeration
   (creation) order — asymmetric, explicitly refuted-sorted (H4).
6. Empty MULTI_SZ elements preserved; EXPAND_SZ never expanded.

## Hypotheses ledger

### H1 — The two emitters diverge somewhere in the knob set
Prediction: ≥1 probe with byte/semantic delta. Observation: 14/14
identical, deltas all empty. Verdict: REFUTED (scope).

### H2 — Hex wraps at a fixed byte count
Prediction: constant first-line bytes. Observation: 23/22/20 with
varying prefixes, all at 77 columns; continuations full at 25.
Verdict: REFINED to the 77-column rule (falsifiable, confirmed by
K12/K13 which were designed to break byte-count variants).

### H3 — Subkey sections export sorted
Prediction: c,a,b → a,b,c. Observation: exact. Verdict: SUPPORTED.

### H4 — Values export sorted like subkeys
Prediction: zeta,alpha,mid → alpha,mid,zeta. Observation: creation
order preserved. Verdict: REFUTED — asymmetry finding.

### H5 — Import normalizes edge content (drops empty MULTI_SZ, etc.)
Prediction: round-trip delta on K06/K07. Observation: 14/14
byte-identical round-trips. Verdict: REFUTED.

## Determinism

Reconstruction-deterministic: delete → import own export →
re-export is byte-identical (14/14). No wall-clock or machine bytes
observed in v5 text exports (contrast: .lnk IDList bytes).

## Claim ledger

| Claim | Status | Evidence | Falsifier | Confidence |
| ----- | ------ | -------- | --------- | ---------- |
| Emitters byte-identical on all probes | OBSERVED | 14/14 sha256 equal | any divergent probe | high (scope) |
| 77-column hex wrap rule | OBSERVED | K05/K07/K12/K13 widths | a probe breaking 77 | high (scope) |
| Subkeys sorted, values in creation order | OBSERVED | K10/K11 | counter-ordered probe | high (scope) |
| Round-trips byte-identical incl. edges | OBSERVED | 14/14 | any lossy probe | high (scope) |
| Empty MULTI_SZ preserved | OBSERVED | K06 bytes + round-trip | dropped element | high |
| Rules generalize beyond build 26200 | NOT CLAIMED | — | other-build matrix | — |

## Limitations

- One Windows build; one hive branch (HKCU synthetic).
- Prefix >77 columns untested; mixed-case subkey sort untested;
  exotic `hex(N)` only inventoried; deletion markers parse-only.
- `reg.exe add` input parsing explicitly out of scope.

## Privacy handling

- All key/value names synthetic (`REStudyTmp`, single letters).
- `matrix.json` contains no user paths, no SIDs, no machine data
  (machine-scanned before commit).
- No binary artifacts committed; corpus regenerates via
  `reg_matrix.py` on Windows.
