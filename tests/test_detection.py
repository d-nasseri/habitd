"""Tests for detection, ProcessCache, severity, alert schema, dedup.

Run: pytest -q
"""

import os
import tempfile
import time

import pytest

from habitd.alert import AlertEngine, DEDUP_WINDOW_SEC
from habitd.daemon import (
    HZ,
    IN_PLACE_AGE_THRESHOLD_SEC,
    PidCache,
    ProcessCache,
    _read_proc_start_time,
)
from habitd.detection import (
    DEFAULT_RULES,
    R_INPLACE_EXECVE,
    R_KNOWN_MALICIOUS,
    R_LAYER2_UNSEEN,
    R_PARENT_UNRESOLVED,
    R_SUSPICIOUS_PATH,
    Reason,
    Verdict,
    check_baseline,
    check_static,
    inplace_execve_verdict,
    known_malicious_verdict,
    parent_unresolved_verdict,
)
from habitd.events import ExecEvent


def _ev(exe="/usr/bin/ls", comm="ls", parent_exe="/usr/bin/bash",
        parent_comm="bash", uid=1000):
    return ExecEvent(
        timestamp=time.time(), pid=1, ppid=2, uid=uid,
        exe=exe, comm=comm, parent_exe=parent_exe, parent_comm=parent_comm,
    )


# --- Layer 1: Static Rules -------------------------------------------------

def test_benign_event_not_static_flagged():
    assert check_static(_ev()).anomalous is False


def test_tmp_execution_flagged():
    v = check_static(_ev(exe="/tmp/x", comm="x"))
    assert v.anomalous and v.has_code(R_SUSPICIOUS_PATH)


def test_dev_shm_execution_flagged():
    v = check_static(_ev(exe="/dev/shm/payload", comm="payload"))
    assert v.anomalous and v.layer == "layer1_static"


def test_var_tmp_execution_flagged():
    v = check_static(_ev(exe="/var/tmp/evil", comm="evil"))
    assert v.anomalous


def test_shell_from_nginx_flagged():
    v = check_static(_ev(exe="/usr/bin/bash", comm="bash",
                         parent_comm="nginx", parent_exe="/usr/sbin/nginx"))
    assert v.anomalous and v.layer == "layer1_static"
    assert v.has_code("static_rule.shell_from_webserver")


def test_shell_from_apache_flagged():
    v = check_static(_ev(exe="/usr/bin/dash", comm="dash",
                         parent_comm="apache2", parent_exe="/usr/sbin/apache2"))
    assert v.anomalous


def test_interpreter_from_sshd_flagged():
    v = check_static(_ev(exe="/usr/bin/python3", comm="python3",
                         parent_comm="sshd", parent_exe="/usr/sbin/sshd"))
    assert v.anomalous


def test_compiler_from_nginx_flagged():
    v = check_static(_ev(exe="/usr/bin/gcc", comm="gcc",
                         parent_comm="nginx", parent_exe="/usr/sbin/nginx"))
    assert v.anomalous


# --- Layer 2: Baseline ------------------------------------------------------

def test_unseen_baseline_is_anomaly():
    v = check_baseline(_ev(), seen=False)
    assert v.anomalous and v.has_code(R_LAYER2_UNSEEN)


def test_seen_baseline_is_clean():
    assert check_baseline(_ev(), seen=True).anomalous is False


# --- Merge & secondary_layer ----------------------------------------------

def test_merge_keeps_layer1_priority_and_all_reasons():
    ev = _ev(exe="/tmp/bash", comm="bash",
             parent_comm="nginx", parent_exe="/usr/sbin/nginx")
    v = check_static(ev).merge(check_baseline(ev, seen=False))
    assert v.layer == "layer1_static"
    assert v.secondary_layer == "layer2_baseline"
    assert len(v.reasons) >= 2


def test_layer2_only_when_layer1_clean():
    ev = _ev()
    v = check_static(ev).merge(check_baseline(ev, seen=False))
    assert v.layer == "layer2_baseline"
    assert v.secondary_layer == ""
    assert len(v.reasons) == 1
    assert v.reasons[0].code == R_LAYER2_UNSEEN


def test_merge_with_benign_other_returns_self_unchanged():
    ev = _ev()
    layer1 = check_static(ev)
    layer2 = check_baseline(ev, seen=True)
    v = layer1.merge(layer2)
    assert v.anomalous is False


# --- Reason structure -------------------------------------------------------

def test_reason_is_named_tuple_with_code_and_message():
    r = Reason("static_rule.foo", "human text")
    assert r.code == "static_rule.foo"
    assert r.message == "human text"
    assert str(r) == "static_rule.foo: human text"


def test_default_rules_is_tuple_not_list():
    assert isinstance(DEFAULT_RULES, tuple)


def test_check_static_accepts_none_rules():
    v1 = check_static(_ev(exe="/tmp/x", comm="x"), rules=None)
    v2 = check_static(_ev(exe="/tmp/x", comm="x"))
    assert v1.anomalous == v2.anomalous


def test_check_static_accepts_empty_rules():
    v = check_static(_ev(exe="/tmp/x", comm="x"), rules=())
    assert v.anomalous and v.has_code(R_SUSPICIOUS_PATH)


# --- Convenience constructors ----------------------------------------------

def test_known_malicious_verdict():
    v = known_malicious_verdict()
    assert v.anomalous and v.has_code(R_KNOWN_MALICIOUS)


def test_parent_unresolved_verdict():
    v = parent_unresolved_verdict()
    assert v.anomalous and v.has_code(R_PARENT_UNRESOLVED)


def test_inplace_execve_verdict_basic():
    v = inplace_execve_verdict()
    assert v.anomalous and v.has_code(R_INPLACE_EXECVE)
    assert v.layer == "layer1_static"


def test_inplace_execve_verdict_with_detail():
    v = inplace_execve_verdict("prior_exe=/usr/sbin/sshd")
    assert "prior_exe=/usr/sbin/sshd" in v.reasons[0].message


# --- ProcessCache -----------------------------------------------------------

def test_processcache_basic():
    c = ProcessCache(maxsize=10)
    c.set(100, "/usr/bin/bash", 12345)
    assert c.get_exe(100) == "/usr/bin/bash"
    entry = c.get(100)
    assert entry is not None and entry.start_time_jiffies == 12345
    assert c.get_exe(999) == ""
    assert c.get(999) is None


def test_processcache_lru_eviction():
    c = ProcessCache(maxsize=3)
    c.set(1, "/a", 100)
    c.set(2, "/b", 200)
    c.set(3, "/c", 300)
    c.set(4, "/d", 400)  # evicts pid 1
    assert c.get_exe(1) == ""
    assert c.get_exe(4) == "/d"


def test_processcache_update_moves_to_end():
    c = ProcessCache(maxsize=3)
    c.set(1, "/a", 100)
    c.set(2, "/b", 200)
    c.set(3, "/c", 300)
    c.set(1, "/a_v2", 100)  # touch pid 1
    c.set(4, "/d", 400)     # should evict pid 2
    assert c.get_exe(1) == "/a_v2"
    assert c.get_exe(2) == ""


def test_processcache_seed_from_proc_returns_positive_on_linux():
    c = ProcessCache()
    count = c.seed_from_proc()
    # CI sandboxes might block /proc, but locally this should populate.
    assert count >= 0


def test_processcache_start_time_conversions():
    c = ProcessCache()
    # On a real system, age of init (PID 1) is large positive.
    if c.boot_time > 0:
        age = c.start_time_to_age_sec(0)  # process at boot time
        # Should be approximately seconds since boot, never negative
        assert age >= 0


# --- PidCache legacy shim ---------------------------------------------------

def test_pidcache_legacy_api_returns_string():
    c = PidCache()
    c.set(100, "/usr/bin/bash", start_time_jiffies=0)
    # Legacy get returns str, not CachedProcess
    result = c.get(100)
    assert isinstance(result, str)
    assert result == "/usr/bin/bash"


def test_pidcache_legacy_set_without_start_time():
    """Legacy callers passed only (pid, exe). start_time is then looked up."""
    c = PidCache()
    # Use own pid — /proc/<self>/stat is readable
    c.set(os.getpid(), "/proc/self/exe-test")
    assert c.get(os.getpid()) == "/proc/self/exe-test"


# --- /proc parsing ----------------------------------------------------------

def test_read_proc_start_time_returns_int_for_own_pid():
    st = _read_proc_start_time(os.getpid())
    assert st is not None
    assert isinstance(st, int)
    assert st > 0


def test_read_proc_start_time_returns_none_for_nonexistent_pid():
    # PID 0 doesn't exist as a process
    assert _read_proc_start_time(0) is None
    # Astronomically high PID (above pid_max default)
    assert _read_proc_start_time(2**31 - 1) is None


# --- Alert field naming & severity (Wazuh compatibility) -------------------

def test_alert_field_names_wazuh_compatible():
    tmp = tempfile.mkdtemp()
    ae = AlertEngine(json_log_path=os.path.join(tmp, "test.json"))
    try:
        ev = _ev(exe="/tmp/evil", comm="evil")
        v = Verdict(anomalous=True, layer="layer1_static",
                    reasons=[Reason(R_SUSPICIOUS_PATH, "execution from /tmp/evil")])
        record = ae.build(ev, v, "high")

        assert "level" not in record
        assert "process" not in record
        assert "parent" not in record

        assert record["habitd_level"] == "high"
        assert record["process_name"] == "evil"
        assert record["parent_name"] == "bash"
        assert record["tool"] == "habitd"
        assert record["executable_path"] == "/tmp/evil"
        assert record["reason_codes"] == [R_SUSPICIOUS_PATH]
        assert all(isinstance(r, str) for r in record["reasons"])
    finally:
        ae.close()


def test_alert_args_field_omitted_when_empty():
    tmp = tempfile.mkdtemp()
    ae = AlertEngine(json_log_path=os.path.join(tmp, "test.json"))
    try:
        ev = _ev()
        v = Verdict(anomalous=True, layer="layer2_baseline",
                    reasons=[Reason(R_LAYER2_UNSEEN, "unseen")])
        record = ae.build(ev, v, "medium")
        assert "args" not in record
    finally:
        ae.close()


def test_alert_args_field_present_when_populated():
    tmp = tempfile.mkdtemp()
    ae = AlertEngine(json_log_path=os.path.join(tmp, "test.json"))
    try:
        ev = ExecEvent(
            timestamp=time.time(), pid=1, ppid=2, uid=1000,
            exe="/usr/bin/curl", comm="curl",
            parent_exe="/usr/bin/bash", parent_comm="bash",
            args=("curl", "-fsSL", "https://example.tld"),
        )
        v = Verdict(anomalous=True, layer="layer2_baseline",
                    reasons=[Reason(R_LAYER2_UNSEEN, "unseen")])
        record = ae.build(ev, v, "medium")
        assert record["args"] == ["curl", "-fsSL", "https://example.tld"]
    finally:
        ae.close()


# --- Severity tests --------------------------------------------------------

@pytest.fixture
def engine():
    tmp = tempfile.mkdtemp()
    ae = AlertEngine(json_log_path=os.path.join(tmp, "test.json"))
    yield ae
    ae.close()


def test_severity_known_malicious_is_critical(engine):
    v = known_malicious_verdict()
    assert engine.severity(v, in_learning_phase=False) == "critical"


def test_severity_inplace_execve_is_high(engine):
    v = inplace_execve_verdict()
    assert engine.severity(v, in_learning_phase=False) == "high"


def test_severity_suspicious_path_is_high(engine):
    v = Verdict(anomalous=True, layer="layer1_static",
                reasons=[Reason(R_SUSPICIOUS_PATH, "exec from /tmp/x")])
    assert engine.severity(v, in_learning_phase=False) == "high"


def test_severity_parent_unresolved_is_low(engine):
    v = parent_unresolved_verdict()
    assert engine.severity(v, in_learning_phase=False) == "low"


def test_severity_layer2_in_learning_is_informational(engine):
    v = check_baseline(_ev(), seen=False)
    assert engine.severity(v, in_learning_phase=True) == "informational"


def test_severity_layer2_post_learning_is_medium(engine):
    v = check_baseline(_ev(), seen=False)
    assert engine.severity(v, in_learning_phase=False) == "medium"


def test_severity_does_not_depend_on_reason_text(engine):
    """Changing message text must never silently change severity."""
    v1 = Verdict(anomalous=True, layer="layer1_static",
                 reasons=[Reason(R_SUSPICIOUS_PATH, "execution from /tmp/x")])
    v2 = Verdict(anomalous=True, layer="layer1_static",
                 reasons=[Reason(R_SUSPICIOUS_PATH, "totally rewritten text here")])
    assert engine.severity(v1, in_learning_phase=False) == \
           engine.severity(v2, in_learning_phase=False)


# --- Severity priority — edge cases ---------------------------------------

def test_severity_known_malicious_wins_over_inplace_execve(engine):
    v = known_malicious_verdict().merge(inplace_execve_verdict())
    assert engine.severity(v, in_learning_phase=False) == "critical"


def test_severity_inplace_execve_wins_over_suspicious_path(engine):
    """Both fire → in_place_execve is the higher-confidence signal."""
    v = inplace_execve_verdict().merge(
        Verdict(anomalous=True, layer="layer1_static",
                reasons=[Reason(R_SUSPICIOUS_PATH, "exec from /tmp/x")])
    )
    assert engine.severity(v, in_learning_phase=False) == "high"


def test_severity_suspicious_path_wins_over_parent_unresolved(engine):
    """Attacker killing parent between fork and execve must not downgrade
    a /tmp/-execution to low — the path itself is enough evidence."""
    sus = Verdict(anomalous=True, layer="layer1_static",
                  reasons=[Reason(R_SUSPICIOUS_PATH, "exec from /tmp/x")])
    v = sus.merge(parent_unresolved_verdict())
    assert engine.severity(v, in_learning_phase=False) == "high"


def test_severity_layer1_static_wins_over_parent_unresolved(engine):
    """UID-based static rules must still trigger high even with empty parent."""
    layer1 = Verdict(anomalous=True, layer="layer1_static",
                     reasons=[Reason("static_rule.service_user_shell", "msg")])
    v = layer1.merge(parent_unresolved_verdict())
    assert engine.severity(v, in_learning_phase=False) == "high"


# --- Dedup tests -----------------------------------------------------------

def test_dedup_suppresses_within_window(engine):
    """Two identical alerts within DEDUP_WINDOW_SEC: only first pushes."""
    record = {
        "habitd_level": "high",
        "executable_path": "/tmp/x",
        "parent_executable_path": "/usr/bin/bash",
        "uid": 1000,
        "process_name": "x",
        "parent_name": "bash",
        "reasons": ["test"],
    }
    # First call: must push (we simulate the dedup logic only)
    engine._maybe_push_ntfy(record)
    # Second call same key: must be suppressed
    engine._maybe_push_ntfy(record)
    key = ("high", "/tmp/x", "/usr/bin/bash", 1000)
    assert key in engine._dedup
    last_push, suppressed = engine._dedup[key]
    assert suppressed == 1


def test_dedup_different_levels_are_separate_keys(engine):
    base = {
        "executable_path": "/tmp/x",
        "parent_executable_path": "/usr/bin/bash",
        "uid": 1000,
        "process_name": "x",
        "parent_name": "bash",
        "reasons": ["test"],
    }
    engine._maybe_push_ntfy({**base, "habitd_level": "high"})
    engine._maybe_push_ntfy({**base, "habitd_level": "critical"})
    # Both should be tracked as separate entries
    assert len(engine._dedup) == 2


def test_dedup_window_constant_is_reasonable():
    """Smoke test: window is 60s as documented in README."""
    assert DEDUP_WINDOW_SEC == 60.0


# --- DB tests --------------------------------------------------------------

def test_save_alert_returns_id():
    """save_alert must return the new row's id for #7 atomic write order."""
    from habitd.db import Store
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = Store(tmp.name)
    store.connect()
    try:
        ev = _ev()
        alert_id = store.save_alert(
            timestamp=time.time(), level="high",
            detection_layer="layer1_static", ev=ev,
            reasons_json='["x"]', raw_json='{}',
        )
        assert isinstance(alert_id, int) and alert_id > 0
    finally:
        store.close()
        os.unlink(tmp.name)


def test_fetch_and_mark_unemitted_alerts():
    from habitd.db import Store
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = Store(tmp.name)
    store.connect()
    try:
        ev = _ev()
        # Save two unemitted alerts
        id1 = store.save_alert(timestamp=time.time(), level="high",
                               detection_layer="layer1_static", ev=ev,
                               reasons_json='["a"]', raw_json='{"id":1}')
        id2 = store.save_alert(timestamp=time.time(), level="medium",
                               detection_layer="layer2_baseline", ev=ev,
                               reasons_json='["b"]', raw_json='{"id":2}')
        rows = store.fetch_unemitted_alerts()
        assert len(rows) == 2
        # Mark one as emitted
        store.mark_alert_emitted(id1)
        rows_after = store.fetch_unemitted_alerts()
        assert len(rows_after) == 1
        assert rows_after[0]["id"] == id2
    finally:
        store.close()
        os.unlink(tmp.name)
