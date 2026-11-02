from app.core.scoring import CRITICAL, NORMAL, WARNING, Signal, compute_score, level_for

W = {"rapid_encryption": 40, "mass_rename": 30, "high_entropy": 25, "cpu_spike": 15, "unknown_program": 10}
L = {"warning": 40, "critical": 70}


def sig(*fired):
    return [Signal(n, n in fired, f"why {n}") for n in W]


def test_no_signals_is_normal():
    r = compute_score(sig(), W, L)
    assert (r.score, r.level) == (0, NORMAL)


def test_single_signal_warning():
    assert compute_score(sig("rapid_encryption"), W, L).level == WARNING


def test_two_signals_critical_and_explained():
    r = compute_score(sig("rapid_encryption", "mass_rename"), W, L)
    assert r.score == 70 and r.level == CRITICAL
    assert "rapid_encryption +40" in r.explain()


def test_score_capped_at_100():
    assert compute_score(sig(*W), W, L).score == 100


def test_level_boundaries():
    assert level_for(39, L) == NORMAL and level_for(40, L) == WARNING
    assert level_for(69, L) == WARNING and level_for(70, L) == CRITICAL
