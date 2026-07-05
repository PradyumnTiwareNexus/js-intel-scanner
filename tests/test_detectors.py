from backend.detectors import patterns, entropy


def test_aws_key_detected():
    text = 'const key = "AKIAABCDEFGHIJKLMNOP";'
    findings = patterns.scan_text(text, source="test.js")
    types = [f["type"] for f in findings]
    assert "AWS Access Key ID" in types


def test_redaction_hides_full_secret():
    text = 'const key = "AKIAABCDEFGHIJKLMNOP";'
    findings = patterns.scan_text(text, source="test.js")
    for f in findings:
        assert "AKIAABCDEFGHIJKLMNOP" not in f["match"]


def test_no_false_positive_on_plain_text():
    text = "hello world this is just normal javascript code"
    findings = patterns.scan_text(text, source="test.js")
    assert len(findings) == 0


def test_entropy_flags_random_token():
    text = 'const token = "aZ8x92LpQm4Rt7VbNc1WdEfGh3Jk5";'
    findings = entropy.scan_entropy(text, source="test.js", threshold=3.5)
    assert len(findings) >= 1


def test_shannon_entropy_low_for_repeated_chars():
    assert entropy.shannon_entropy("aaaaaaaaaa") < 1.0
