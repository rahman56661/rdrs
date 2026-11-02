import os

from app.core.entropy import file_entropy, is_expected_high_entropy, shannon_entropy


def test_empty_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_text_is_low():
    assert shannon_entropy(b"normal document content " * 100) < 5


def test_random_is_high():
    assert shannon_entropy(os.urandom(20000)) > 7.9


def test_file_entropy_missing_file():
    assert file_entropy("does_not_exist.bin") is None


def test_expected_high_entropy_ext():
    assert is_expected_high_entropy("a.ZIP", [".zip"])
    assert not is_expected_high_entropy("a.txt", [".zip"])
