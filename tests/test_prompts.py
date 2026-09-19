"""Devices that ask before they act.

Netmiko's send_command returns as soon as the output looks like a prompt, and
the ']' in '[Y/N]' is enough - so the command has not run, the session waits at
the question, and wirehand used to report success anyway. Observed on Huawei
VRPv8: rollback_change said "ROLLED BACK" while the device was still asking.
"""
from app.platforms import CONFIRM_PROMPTS_RX, SESSION_PREP, pending_prompt

# Verbatim device output (VRPv8 NE40E V800R023, IOS-XR 24.2.2 from the lab).
VRP_ROLLBACK = ("Warning: This operation will revert configuration changes to the previous status. "
                "During the rollback configuration process, some configurations involving differences "
                "may be temporarily invalid. Continue? [Y/N]:")
XR_ROLLBACK_OK = ("Loading Rollback Changes.\nLoaded Rollback Changes in 1 sec\nCommitting.\n"
                  "3 items committed in 1 sec (2)items/sec\nUpdating.\n"
                  "Configuration successfully rolled back 1 commits.")
IOS_CLEAR = 'Clear "show interface" counters on all interfaces [confirm]'
JUNOS_COMMIT = "Commit? [yes,no] (yes)"


def test_detects_real_device_questions():
    for text, answer in [(VRP_ROLLBACK, "Y"), (IOS_CLEAR, "y"), (JUNOS_COMMIT, "yes"),
                         ("Are you sure? (y/n)[n]:", "y"), ("Do you want to continue? (y/n)", "y")]:
        hit = pending_prompt(text)
        assert hit is not None, text
        assert hit[1] == answer, (text, hit)


def test_output_that_is_not_a_question():
    for text in [XR_ROLLBACK_OK, "", "interface Loopback0\n ipv4 address 1.1.1.1/32",
                 "Configuration rollback succeeded.", "% No such configuration item(s)"]:
        assert pending_prompt(text) is None, text


def test_only_the_tail_counts():
    """A config that merely mentions a question is not a pending prompt."""
    cfg = "interface Gi0/0\n description uplink - continue? [Y/N] see ticket 42\n!\ninterface Gi0/1\n"
    assert pending_prompt(cfg + "x" * 300) is None


def test_vrp_gets_mmi_mode_on_session_open():
    """Huawei's own switch for 'a machine is typing' - it stops the questions."""
    assert SESSION_PREP["vrpv8"] == ["mmi-mode enable"] == SESSION_PREP["vrp"]
    assert "ios" not in SESSION_PREP and "xr" not in SESSION_PREP


# The rest needs netmiko (app.transport imports it). Skipped where it is absent,
# so the dependency-free part of the suite still runs.
try:
    from app.transport import MAX_PROMPT_ANSWERS, Pool
    HAVE_NETMIKO = True
except ImportError:                      # pragma: no cover
    HAVE_NETMIKO = False


class FakeConn:
    """Answers with a question until it has been answered `asks` times."""
    def __init__(self, asks=1, question=VRP_ROLLBACK):
        self.asks, self.question, self.sent = asks, question, []

    def send_command(self, cmd, **kw):
        self.sent.append(cmd)
        return self.question if self.asks else "done"

    def send_command_timing(self, cmd, **kw):
        self.sent.append(cmd)
        self.asks -= 1
        return self.question if self.asks else "Configuration rollback succeeded."


class _Dev:
    name, family = "vrp1", "vrpv8"


def test_settle_answers_yes_for_an_approved_change():
    if not HAVE_NETMIKO:
        return
    conn = FakeConn(asks=1)
    out = Pool.__new__(Pool)._settle(conn, _Dev(), VRP_ROLLBACK, 60, "yes")
    assert conn.sent == ["Y"], conn.sent
    assert "rollback succeeded" in out and pending_prompt(out) is None


def test_settle_backs_out_on_the_read_path():
    """A read must never answer 'yes' to a question it did not expect."""
    if not HAVE_NETMIKO:
        return
    conn = FakeConn(asks=1)
    Pool.__new__(Pool)._settle(conn, _Dev(), VRP_ROLLBACK, 60, "no")
    assert conn.sent == ["N"], conn.sent


def test_settle_gives_up_instead_of_looping():
    if not HAVE_NETMIKO:
        return
    conn = FakeConn(asks=99)
    out = Pool.__new__(Pool)._settle(conn, _Dev(), VRP_ROLLBACK, 60, "yes")
    assert len(conn.sent) == MAX_PROMPT_ANSWERS
    assert pending_prompt(out) is not None     # still stuck -> caller must not claim success


def test_settle_does_nothing_when_there_is_no_question():
    if not HAVE_NETMIKO:
        return
    conn = FakeConn(asks=0)
    assert Pool.__new__(Pool)._settle(conn, _Dev(), XR_ROLLBACK_OK, 60, "yes") == XR_ROLLBACK_OK
    assert conn.sent == []
