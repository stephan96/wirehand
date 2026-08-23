"""SSH transport: one persistent Netmiko session per device, serialized with a
lock, reaped after idle timeout. Keeps multi-step analysis from paying a full
handshake on every tool call."""
from __future__ import annotations

import logging
import os
import threading
import time

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

from .inventory import Device

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
        if self.device.family != "linux":
            try:
                self.conn.disable_paging()
            except Exception:  # some platforms do this in session_preparation
                pass
        return self.conn

    def close(self):
        if self.conn is not None:
            try:
                self.conn.disconnect()
            except Exception:
                pass
            self.conn = None


class Pool:
    def __init__(self):
        self._sessions: dict[str, _Session] = {}
        self._guard = threading.Lock()
        t = threading.Thread(target=self._reaper, daemon=True, name="wirehand-reaper")
        t.start()

    def _get(self, device: Device) -> _Session:
        with self._guard:
            s = self._sessions.get(device.name)
            if s is None or s.device is not device:
                s = _Session(device)
                self._sessions[device.name] = s
            return s

    def run(self, device: Device, commands: list[str], timeout: int = CMD_TIMEOUT) -> list[tuple[str, str]]:
        """Run exec-mode commands sequentially. Returns [(cmd, output)]."""
        s = self._get(device)
        with s.lock:
            conn = self._open_or_raise(s)
            results = []
            for cmd in commands:
                try:
                    out = conn.send_command(cmd, read_timeout=timeout, strip_command=True)
                except Exception as exc:  # timeout, prompt issues -> report and keep going
                    out = f"[error running command: {type(exc).__name__}: {exc}]"
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
                    else:  # fortinet etc.
                        try:
                            conn.exit_config_mode()
                        except Exception:
                            pass
            finally:
                s.last_used = time.time()
            return out

    def _open_or_raise(self, s: _Session):
        try:
            return s.open()
        except NetmikoAuthenticationException as exc:
            s.close()
            raise RuntimeError(f"authentication failed for {s.device.name}") from exc
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
