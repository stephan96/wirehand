"""One-time approval codes: the part a model must not be able to fake."""
import time

from app.approval import (STEP_SECONDS, Approver, ConfigError, hotp, new_secret,
                          normalize_secret, provisioning_uri)


def test_rfc6238_vectors():
    """RFC 6238 Appendix B (SHA-1). If this breaks, no authenticator app agrees
    with us and every approval fails."""
    key = b"12345678901234567890"
    for t, expect in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                      (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]:
        assert hotp(key, t // 30, digits=8) == expect, t


def _fixture():
    secret = new_secret()
    now = time.time()
    counter = int(now // STEP_SECONDS)
    return secret, now, hotp(normalize_secret(secret), counter)


def test_valid_code_once_and_only_once():
    secret, now, code = _fixture()
    a = Approver(secret=secret, mode="totp")
    assert a.verify(code, now).ok
    # a second staged change cannot ride on the same number the user read out once
    again = a.verify(code, now)
    assert not again.ok and "already used" in again.reason


def test_model_guesses_are_refused_and_lock_out():
    secret, now, code = _fixture()
    a = Approver(secret=secret, mode="totp", max_failures=3, lockout=60)
    for guess in ["123456", "000000", "654321"]:
        assert not a.verify(guess, now).ok, guess
    locked = a.verify(code, now)                      # even the RIGHT code now waits
    assert not locked.ok and locked.retry_after > 0 and "locked" in locked.reason


def test_shapes_that_are_not_a_code():
    secret, now, _ = _fixture()
    a = Approver(secret=secret, mode="totp")
    for junk in ["", "   ", "abcdef", "12345", "1234567", "12 34 56 78"]:
        assert not a.verify(junk, now).ok, junk


def test_clock_skew_window():
    secret, now, _ = _fixture()
    a = Approver(secret=secret, mode="totp")
    prev = hotp(normalize_secret(secret), int(now // STEP_SECONDS) - 1)
    assert a.verify(prev, now).ok          # user needed a few seconds to read it out
    b = Approver(secret=secret, mode="totp")
    stale = hotp(normalize_secret(secret), int(now // STEP_SECONDS) - 5)
    assert not b.verify(stale, now).ok     # but not a code from two minutes ago


def test_modes_and_per_device_override():
    a = Approver(secret=new_secret(), mode="totp")
    assert a.requires_approval(None) and a.requires_approval("totp")
    assert not a.requires_approval("off")          # disposable lab node
    b = Approver(secret="", mode="off")
    assert not b.requires_approval(None)
    assert b.requires_approval("totp")             # ... but a device may still demand it
    c = Approver(secret=new_secret(), mode="nonsense")
    assert c.mode == "totp" and c.mode_invalid     # unknown value fails safe


def test_unusable_config_fails_closed():
    a = Approver(secret="", mode="totp")
    assert not a.configured
    try:
        a.verify("123456")
        assert False, "must not silently accept when no secret is configured"
    except ConfigError as exc:
        assert "WIREHAND_TOTP_SECRET" in str(exc)
    for bad in ["not-base32!!", "AAAA"]:
        assert not Approver(secret=bad, mode="totp").configured, bad


def test_secret_and_uri_shape():
    s = new_secret()
    assert len(s) >= 32 and s.isupper()
    assert normalize_secret(s.lower()) == normalize_secret(" ".join([s[:4], s[4:]]))
    uri = provisioning_uri(s)
    assert uri.startswith("otpauth://totp/") and f"secret={s}" in uri and "period=30" in uri
