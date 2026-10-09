# SPDX-FileCopyrightText: 2026 Stephan Baenisch
# SPDX-License-Identifier: Apache-2.0
"""Human approval for confirm_change.

The problem this solves: the confirmation code from propose_change travels back
to the model, so a model that decides to approve on the user's behalf just calls
confirm_change with the code it was handed a moment ago - which is exactly what
small local models do:

    Ask the user to approve. Then call confirm_change(code='65C02D').
    > Thought: Executing confirm_change...

No wording in the tool description or the system prompt can stop that. Anything
the model is told it can ignore, and anything the model is shown it can replay.
An approval is only worth something if it requires a secret the model never sees.

That secret is a TOTP (RFC 6238) from the operator's authenticator app: the model
has to ask a human for the number, it expires after a couple of minutes, and it is consumed
on first use so it cannot be replayed onto a second staged change. A *static*
passphrase in .env would not do - the first time a human types it into the chat,
the model has it in its context and can reuse it forever.

TOTP is HMAC-SHA1 over a time counter, so this needs no third-party dependency.

Modes (WIREHAND_CONFIRM_MODE, per-device override `confirm:` in inventory.yaml):
  totp - confirm_change additionally requires a current one-time code (default)
  off  - no approval required; the model may confirm its own proposal
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import threading
import time
from dataclasses import dataclass

MODES = ("totp", "off")
CONFIRM_MODE = (os.environ.get("WIREHAND_CONFIRM_MODE") or "totp").strip().lower()
TOTP_SECRET = (os.environ.get("WIREHAND_TOTP_SECRET") or "").strip()
STEP_SECONDS = 30
# How long a code is still accepted after the app stopped showing it. The user
# needs a moment to read the number out, and a local model may think for a minute
# or two before it calls confirm_change - a 30 s window loses that race. Codes stay
# single-use and guesses still lock out, so a longer window costs little.
MAX_AGE_SECONDS = int(os.environ.get("WIREHAND_APPROVAL_MAX_AGE", "120"))
# Codes from the *future* are only a clock-drift allowance (phone clock ahead).
SKEW_STEPS = int(os.environ.get("WIREHAND_APPROVAL_SKEW_STEPS", "1"))
MAX_FAILURES = int(os.environ.get("WIREHAND_APPROVAL_MAX_FAILURES", "5"))
LOCKOUT_SECONDS = int(os.environ.get("WIREHAND_APPROVAL_LOCKOUT", "120"))


class ConfigError(RuntimeError):
    """Approval is required but not usable - an operator has to fix the setup."""


@dataclass
class ApprovalResult:
    ok: bool
    reason: str = ""
    retry_after: int = 0


def normalize_secret(secret: str) -> bytes:
    """Base32 as authenticator apps print it: spaces and lower case tolerated,
    padding optional."""
    s = "".join(secret.split()).upper()
    if not s:
        raise ConfigError("TOTP secret is empty")
    s += "=" * (-len(s) % 8)
    try:
        raw = base64.b32decode(s, casefold=True)
    except Exception as exc:
        raise ConfigError(f"WIREHAND_TOTP_SECRET is not valid base32: {exc}") from None
    if len(raw) < 10:
        raise ConfigError("TOTP secret is too short (use at least 16 base32 chars)")
    return raw


def hotp(key: bytes, counter: int, digits: int = 6) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def new_secret(length: int = 20) -> str:
    """A fresh base32 secret (160 bit by default), as apps expect it."""
    return base64.b32encode(secrets.token_bytes(length)).decode().rstrip("=")


def provisioning_uri(secret: str, label: str = "wirehand", issuer: str = "wirehand") -> str:
    s = "".join(secret.split()).upper()
    return f"otpauth://totp/{issuer}:{label}?secret={s}&issuer={issuer}&algorithm=SHA1&digits=6&period={STEP_SECONDS}"


class Approver:
    """Verifies one-time codes, consumes them, and locks out after repeated
    failures (6 digits are brute-forceable if you may keep guessing)."""

    def __init__(self, secret: str = TOTP_SECRET, mode: str = CONFIRM_MODE,
                 max_failures: int = MAX_FAILURES, lockout: int = LOCKOUT_SECONDS,
                 max_age: int = MAX_AGE_SECONDS, skew_steps: int = SKEW_STEPS):
        self.mode = mode if mode in MODES else "totp"
        self.mode_invalid = mode not in MODES
        self._secret_raw = secret
        self._key: bytes | None = None
        self._key_error = ""
        if secret:
            try:
                self._key = normalize_secret(secret)
            except ConfigError as exc:
                self._key_error = str(exc)
        self._lock = threading.Lock()
        self._used: dict[int, float] = {}      # counter -> when it was consumed
        self._failures: list[float] = []
        self.max_failures = max_failures
        self.lockout = lockout
        self.max_age = max(max_age, 0)
        self.skew_steps = max(skew_steps, 0)

    # -- configuration -------------------------------------------------------
    @property
    def configured(self) -> bool:
        return self._key is not None

    def mode_for(self, device_confirm: str | None) -> str:
        """Per-device `confirm:` wins over the global mode."""
        m = (device_confirm or "").strip().lower()
        return m if m in MODES else self.mode

    def requires_approval(self, device_confirm: str | None = None) -> bool:
        return self.mode_for(device_confirm) == "totp"

    def setup_hint(self) -> str:
        why = self._key_error or "WIREHAND_TOTP_SECRET is not set"
        return (
            f"confirm_change requires one-time approval (WIREHAND_CONFIRM_MODE=totp) but it is "
            f"not usable: {why}. An operator has to fix this on the wirehand host - it cannot be "
            f"worked around from the chat. Generate a secret with "
            f"`docker exec wirehand python -m app.approval --new`, put it in .env as "
            f"WIREHAND_TOTP_SECRET, scan the printed URI into an authenticator app and run "
            f"`docker compose up -d`. To run without approval instead, set "
            f"WIREHAND_CONFIRM_MODE=off (the model can then apply its own proposals)."
        )

    # -- verification --------------------------------------------------------
    def _locked_for(self, now: float) -> int:
        recent = [t for t in self._failures if now - t < self.lockout]
        self._failures = recent
        if len(recent) >= self.max_failures:
            return int(self.lockout - (now - max(recent))) + 1
        return 0

    def verify(self, code: str, now: float | None = None) -> ApprovalResult:
        now = time.time() if now is None else now
        if self._key is None:
            raise ConfigError(self.setup_hint())
        digits = "".join((code or "").split())
        with self._lock:
            locked = self._locked_for(now)
            if locked:
                return ApprovalResult(False, f"too many wrong approval codes - locked for {locked}s", locked)
            if not digits.isdigit() or len(digits) != 6:
                self._failures.append(now)
                return ApprovalResult(False, "approval must be the current 6-digit code from the user's authenticator app")
            counter = int(now // STEP_SECONDS)
            oldest = counter - -(-self.max_age // STEP_SECONDS)      # ceil
            for c in range(oldest, counter + self.skew_steps + 1):
                # step c is shown until (c+1)*STEP; accept it max_age beyond that
                if (c + 1) * STEP_SECONDS + self.max_age <= now:
                    continue
                if hmac.compare_digest(hotp(self._key, c), digits):
                    if c in self._used:
                        self._failures.append(now)
                        return ApprovalResult(False, "this approval code was already used - each change needs a fresh one")
                    self._used[c] = now
                    horizon = self.max_age + STEP_SECONDS * (self.skew_steps + 2)
                    self._used = {k: t for k, t in self._used.items() if now - t < horizon}
                    self._failures.clear()
                    return ApprovalResult(True)
            self._failures.append(now)
            left = self.max_failures - len(self._failures)
            return ApprovalResult(False, (f"approval code is not valid - wrong, or expired (a code is accepted for {self.max_age}s "
                                         f"after the app stops showing it). Ask the user for the current code. "
                                         f"{max(left, 0)} attempt(s) left before lockout"))


if __name__ == "__main__":   # operator helper, never reachable from the API
    import sys
    if "--new" in sys.argv:
        s = new_secret()
        print(f"WIREHAND_TOTP_SECRET={s}\n")
        print("Put that line in .env (chmod 600), then `docker compose up -d`.")
        print("Add it to an authenticator app (Aegis, FreeOTP, Google Authenticator, ...)")
        print("by typing the secret, or by scanning this URI as a QR code:\n")
        print(f"  {provisioning_uri(s)}\n")
        print("  qrencode -t ANSIUTF8 '<the URI above>'    # if you want a QR in the terminal")
    else:
        a = Approver()
        print(f"mode={a.mode} configured={a.configured}")
        if a.configured:
            print(f"current code = {hotp(a._key, int(time.time() // STEP_SECONDS))}")
        else:
            print(a.setup_hint())
        print("\nUse --new to generate a secret.")
