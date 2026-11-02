# RDRS - One-Page Write-up

**Project:** Ransomware Detection and Response System (defensive, rules-based) - *Team: Habebur Rahman and Aleena K Mani*

## Design choices
- **Rules over ML.** A weighted rule engine is transparent: every point of the 0-100 score can be explained, needs no
  training data, and is easy to tune from `config.yaml`. The dashboard and every alert show the breakdown
  (e.g. `rapid_encryption +40 | mass_rename +30 = 70/100`).
- **Layered, modular architecture.** `core` (pure logic: entropy, scoring) -> `detectors` (monitoring, engine, response) ->
  `database` -> `api` -> `dashboard/reports`. Pure functions (`evaluate_signals`, `compute_score`) are unit-tested in isolation.
- **Sliding window + liveness gating.** Signals are computed over a 60 s window. CPU and unknown-program points only count
  while file activity is still happening, so a finished attack decays cleanly to Normal instead of leaving stale alerts.
- **Safe by design.** Simulation mode is the default; evidence is copied (never moved), hashed with SHA-256, and process
  termination is never executed. Dashboard output is rendered with `textContent` and reports use autoescaping,
  so hostile file names cannot inject scripts.
- **One incident per attack.** A cooldown prevents 100 duplicate incidents; the single incident keeps growing (affected files,
  evidence) while the attack continues.

## How it was tested
- 51 automated tests (pytest), ~98% line coverage: unit tests (entropy, scoring, signals), integration tests (burst of fake
  events -> Critical incident + evidence + untouched originals), API tests, report tests (all four formats), monitor tests
  (real watchdog observer), and CLI/main tests.
- Live scenarios with the safe sandbox script: **attack -> Critical** (score 80-100, MTTD about 2 s), **normal edits -> Normal**,
  **random `.zip` backups -> Normal**.

## False-positive case considered
Backup and archive tools (`.zip`, `.7z`, `.jpg`, `.mp4`, Office files) produce high-entropy data that looks encrypted.
RDRS excludes these known types from entropy and rename signals, and a dedicated test (`zip` scenario) proves a burst of 50
random `.zip` files stays Normal. Remaining risk: an unknown extension, or a backup tool that renames files to a custom extension.

## Limitations (honest)
- Suspect-process attribution is heuristic; very short-lived processes can be missed between 2-second snapshots.
- Fixed thresholds may need per-environment tuning; entropy samples only the first 64 KB.
- Evidence copying happens after detection, so files encrypted before the Critical threshold are not preserved pre-encryption.

## What I would improve next
1. Open-file-handle / ETW tracing for reliable process attribution. 2. A learned per-folder baseline (adaptive thresholds).
3. Canary/honeyfile detection. 4. Map alerts to MITRE ATT&CK T1486 and export to a SIEM. 5. Authentication on the API.
