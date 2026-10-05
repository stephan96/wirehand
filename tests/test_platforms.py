"""config/platforms/ must describe exactly what the Python tables did."""
from app import clab, platforms
from app.inventory import PLATFORMS


def test_yaml_matches_the_python_tables():
    reg = platforms.load_platforms()
    assert set(reg.platforms) == set(PLATFORMS)
    for dt, fam in PLATFORMS.items():
        p = reg.platforms[dt]
        assert list(p.facts) == platforms.FACTS[fam], dt
        assert p.snapshot == platforms.SNAPSHOT[fam], dt
        assert (list(p.rollback_last) if p.rollback_last else None) == platforms.ROLLBACK_LAST[fam], dt
        assert p.commits == platforms.COMMITS[fam], dt
        assert list(p.prep) == platforms.SESSION_PREP.get(fam, []), dt
        assert p.enable == (fam in ("ios", "nxos", "eos")), dt
        assert p.shell == (fam == "linux"), dt
        assert p.balance_end == (fam == "fortinet"), dt
        assert [(x.rx.pattern, x.proceed, x.abort) for x in p.prompts] == \
               [(rx.pattern, y, n) for rx, y, n in platforms.CONFIRM_PROMPTS_RX], dt
        assert p.comment_prefixes == ("#", "!"), dt
    assert reg.kinds == clab.KIND_MAP
    creds = {k: c for p in reg.platforms.values() for k, c in p.kinds.items() if c}
    assert creds == clab.DEFAULT_CREDS


def test_guards_match_the_old_verb_lists():
    reg = platforms.load_platforms()
    old_cfg = ("commit", "end", "configure", "conf", "write", "reload", "reboot")
    old_fgt = ("execute", "reload", "reboot")
    words = set(old_cfg + old_fgt) | {"config", "interface", "set", "edit", "next", "commit-x", "endx"}
    for dt, p in reg.platforms.items():
        if p.shell:
            assert not p.refuse
            continue
        verbs = old_fgt if dt == "fortinet" else old_cfg
        for w in words:
            for line in (w, f"{w} x", f"  {w.upper()}"):
                assert bool(p.refused_lines([line])) == (w in verbs), (dt, line)
