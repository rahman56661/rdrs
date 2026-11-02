"""SAFE test trigger (build guide, Section 15). Touches ONLY data/sandbox.

  python scripts/simulate_attack.py            # attack: random bytes + .locked rename
  python scripts/simulate_attack.py normal     # normal edits   -> must stay Normal
  python scripts/simulate_attack.py zip        # random .zip    -> must stay Normal (false-positive test)
"""
import os
import pathlib
import sys
import time

SANDBOX = pathlib.Path("data/sandbox")
SANDBOX.mkdir(parents=True, exist_ok=True)
mode = sys.argv[1] if len(sys.argv) > 1 else "attack"
N, DELAY = 50, 0.1

if mode == "zip":                      # backups / archives look random but are harmless
    for i in range(N):
        (SANDBOX / f"backup_{i}.zip").write_bytes(os.urandom(20000))
        time.sleep(DELAY)
else:
    for i in range(N):
        (SANDBOX / f"file_{i}.txt").write_text("normal document content " * 20)
    time.sleep(2)
    if mode == "attack":
        for f in list(SANDBOX.glob("*.txt")):
            f.write_bytes(os.urandom(20000))      # high entropy, looks encrypted
            f.rename(f.with_suffix(".locked"))    # mass extension change
            time.sleep(DELAY)
    else:
        for f in list(SANDBOX.glob("*.txt")):
            f.write_text("edited text content " * 20)
            time.sleep(DELAY)
print(f"Simulation '{mode}' finished (sandbox only).")
