"""SSH transport: one persistent Netmiko session per device, serialized with a
lock, reaped after idle timeout. Keeps multi-step analysis from paying a full
handshake on every tool call."""
from __future__ import annotations

import logging
import os
import threading
import time

import socket
from concurrent.futures import ThreadPoolExecutor

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException


class AuthError(RuntimeError):
    """Credentials rejected by the device.

    Terminal for the credentials that were used: repeating the same call cannot
    help and may lock the account. NOT terminal for the device - once the stored
    credentials have been corrected, the device is usable again and must be
    retried normally."""

from .inventory import Device, RESCAN_SECONDS

log = logging.getLogger("wirehand.transport")
IDLE_SECONDS = int(os.environ.get("WIREHAND_IDLE_SECONDS", "300"))
CMD_TIMEOUT = int(os.environ.get("WIREHAND_CMD_TIMEOUT", "60"))


class _Session:
    def __init__(self, device: Device):
        self.device = device
        self.lock = threading.Lock()
        self.conn = None
        self.last_used = 0.0

    def open(self):
        if self.conn is not None and self.conn.is_alive():
            return self.conn
        log.info("connecting to %s (%s)", self.device.name, self.device.device_type)
        self.conn = ConnectHandler(**self.device.netmiko_kwargs())
        if self.device.secret and self.device.family in ("ios", "nxos", "eos"):
            self.conn.enable()
        # Do NOT call disable_paging() here: Netmiko's session_preparation already
        # handles paging per platform. A second invocation re-runs config dialogs on
        # some platforms (FortiGate!) and leaves unread data in the channel, which
        # makes the FIRST real command time out. Instead, sync the channel:
        try:
            self.conn.find_prompt()
        except Exception:
            pass
        return self.conn

    def close(self):
        if self.conn is not None:
            try:
                self.conn.disconnect()
            except Exception:
                pass
            self.conn = None

    def matches(self, device: Device) -> bool:
        """True if `device` would connect exactly like this session does.
        Covers host, port, username, password, key and secret."""
        return self.device.netmiko_kwargs() == device.netmiko_kwargs()


class Pool:
    def __init__(self):
        self._sessions: dict[str, _Session] = {}
        self._guard = threading.Lock()
        t = threading.Thread(target=self._reaper, daemon=True, name="wirehand-reaper")
        t.start()

    def _get(self, device: Device) -> _Session:
        stale = None
        with self._guard:
            s = self._sessions.get(device.name)
            if s is not None and not s.matches(device):
                # Credentials or connection parameters were corrected in the
                # inventory: retire the pooled session so the next open uses the
                # new ones instead of re-failing with the old ones.
                log.info("%s: connection parameters changed, dropping pooled session", device.name)
                stale, s = s, None
            if s is None:
                s = _Session(device)
                self._sessions[device.name] = s
        if stale is not None:
            self._close_async(stale)
        return s

    @staticmethod
    def _close_async(s: _Session) -> None:
        """Close a retired session without making the caller wait for a command
        that may still be running on it."""
        def _worker():
            with s.lock:
                s.close()
        threading.Thread(target=_worker, daemon=True, name="wirehand-close").start()

    def run(self, device: Device, commands: list[str], timeout: int = CMD_TIMEOUT) -> list[tuple[str, str]]:
        """Run exec-mode commands sequentially. Returns [(cmd, output)]."""
        s = self._get(device)
        with s.lock:
            conn = self._open_or_raise(s)
            results = []
            for cmd in commands:
                try:
                    out = conn.send_command(cmd, read_timeout=timeout, strip_command=True)
                except AuthError:
                    raise          # wrong credentials: an immediate retry cannot fix that
                except Exception as first_exc:
                    # Pooled sessions can be half-dead (device-side idle timeout kills the
                    # TCP session, is_alive() does not notice). Reconnect and retry ONCE -
                    # read commands are idempotent, so this is safe.
                    log.warning("%s: '%s' failed (%s), reconnecting and retrying once",
                                device.name, cmd, type(first_exc).__name__)
                    s.close()
                    conn = self._open_or_raise(s)
                    try:
                        out = conn.send_command(cmd, read_timeout=timeout, strip_command=True)
                    except Exception as exc:
                        out = (f"[error running command (after reconnect+retry): "
                               f"{type(exc).__name__}: {exc}]")
                        s.close()
                        conn = self._open_or_raise(s)
                results.append((cmd, out or ""))
            s.last_used = time.time()
            return results

    def configure(self, device: Device, lines: list[str], commit: bool) -> str:
        """Apply configuration lines. Platform specifics:
        - linux: lines are shell commands run sequentially in exec mode
        - xr/vrpv8: send_config_set + commit
        - ios/eos/nxos: send_config_set + save_config
        - fortinet/vrp/junos: send_config_set (fortinet persists immediately)
        """
        s = self._get(device)
        with s.lock:
            conn = self._open_or_raise(s)
            fam = device.family
            try:
                if fam == "linux":
                    chunks = []
                    for ln in lines:
                        chunks.append(f"$ {ln}\n" + (conn.send_command(ln, read_timeout=CMD_TIMEOUT) or ""))
                    out = "\n".join(chunks)
                else:
                    out = conn.send_config_set(lines, read_timeout=CMD_TIMEOUT, exit_config_mode=False)
                    if fam in ("xr", "vrpv8", "junos"):
                        out += "\n" + (conn.commit() if commit else "")
                        conn.exit_config_mode()
                    elif fam in ("ios", "eos", "nxos"):
                        conn.exit_config_mode()
                        if commit:
                            out += "\n" + conn.save_config()
                    elif fam == "vrp":
                        conn.exit_config_mode()
                        if commit:
                            out += "\n" + conn.save_config()
                    else:  # fortinet: blocks carry their own 'end'; nothing to exit
                        pass
            finally:
                s.last_used = time.time()
            return out

    def _open_or_raise(self, s: _Session):
        try:
            return s.open()
        except NetmikoAuthenticationException as exc:
            s.close()
            raise AuthError(
                f"AUTHENTICATION FAILED for '{s.device.name}' ({s.device.device_type}, user "
                f"'{s.device.username}'). The device rejected the stored credentials.\n"
                f"Do NOT repeat this call with the same credentials: it will fail again and may "
                f"lock the account. Stop working on '{s.device.name}' for now and continue with "
                f"the other devices if the task involves several.\n"
                f"Tell the user that the credentials for '{s.device.name}' must be corrected "
                f"server-side, in config/inventory.yaml or in the containerlab credential "
                f"override for that kind. Changes to inventory.yaml are picked up automatically "
                f"within ~{RESCAN_SECONDS}s; list_devices(refresh=true) applies them immediately. "
                f"Credentials that come from an environment variable ('env:NAME') need "
                f"`docker compose up -d`.\n"
                f"This failure is NOT permanent: as soon as the user says the credentials have "
                f"been corrected, retry '{s.device.name}' normally - the corrected credentials "
                f"are used automatically, and no restart of this session is needed."
            ) from exc
        except NetmikoTimeoutException as exc:
            s.close()
            raise RuntimeError(f"connection timeout to {s.device.name}") from exc

    def _reaper(self):
        while True:
            time.sleep(30)
            now = time.time()
            with self._guard:
                sessions = list(self._sessions.values())
            for s in sessions:
                if s.conn is not None and now - s.last_used > IDLE_SECONDS and s.lock.acquire(blocking=False):
                    try:
                        log.info("closing idle session to %s", s.device.name)
                        s.close()
                    finally:
                        s.lock.release()

    def close_all(self):
        for s in list(self._sessions.values()):
            with s.lock:
                s.close()


CHECK_TIMEOUT = float(os.environ.get("WIREHAND_CHECK_TIMEOUT", "2"))


def tcp_reachable(host: str, port: int, timeout: float = CHECK_TIMEOUT) -> bool:
    """True if a TCP connection to host:port succeeds within timeout."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_devices(devices: list[Device]) -> dict[str, bool]:
    """Concurrent SSH-port reachability check from the wirehand host.
    Verifies network path + listening sshd, NOT credentials."""
    with ThreadPoolExecutor(max_workers=min(32, max(1, len(devices)))) as ex:
        results = ex.map(lambda d: (d.name, tcp_reachable(d.host, d.port)), devices)
        return dict(results)
