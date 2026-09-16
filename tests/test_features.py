from vigil.features import FEATURE_NAMES, FEATURES, FeatureExtractor, display_value, suspicious_process
from vigil.schema import Event

IDX = {name: i for i, name in enumerate(FEATURE_NAMES)}


def shown(row, name):
    return display_value(FEATURES[IDX[name]], row[IDX[name]])


def extractor(env):
    return FeatureExtractor(env.role_of, frozenset({env.dc.ip}))


def test_vector_matches_spec(env):
    row = extractor(env).update(Event(0.0, "network", "flow", "10.20.0.10", "8.8.8.8", 443, 100, 200, 0.1))
    assert len(row) == len(FEATURES)
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)


def test_failed_logins_accumulate_and_expire(env):
    fx = extractor(env)
    src = "10.20.0.10"
    for i in range(10):
        row = fx.update(Event(float(i), "endpoint", "auth", src, env.dc.ip, 88, user=f"u{i}", outcome="failure"))
    assert shown(row, "w_auth_failures") == "10"
    assert shown(row, "w_uniq_users") == "10"
    # Ten minutes later the 5-minute window is empty again; the 1-hour one is not.
    row = fx.update(Event(610.0, "endpoint", "auth", src, env.dc.ip, 88, user="u0", outcome="success"))
    assert shown(row, "w_auth_failures") == "0"
    assert shown(row, "h_auth_failures") == "10"


def test_periodic_connections_have_low_timing_cv(env):
    fx = extractor(env)
    for i in range(12):
        periodic = fx.update(Event(i * 60.0, "network", "flow", "10.20.0.10", "185.1.2.3", 443, 300, 300, 0.2))
    for t in (0, 3, 50, 52, 200, 420, 425, 700, 1100, 1105, 1300, 1700):
        jittery = fx.update(Event(float(t), "network", "flow", "10.20.0.11", "185.1.2.4", 443, 300, 300, 0.2))
    assert periodic[IDX["p_interval_cv"]] < 0.05
    assert jittery[IDX["p_interval_cv"]] > 0.5


def test_prevalence_counts_distinct_internal_sources(env):
    fx = extractor(env)
    for i in range(5):
        row = fx.update(Event(float(i), "network", "flow", f"10.20.0.{i + 10}", "52.1.1.1", 443, 10, 10))
    assert shown(row, "dst_prevalence") == "5"


def test_suspicious_process_tokens():
    assert suspicious_process("powershell.exe -nop -w hidden -enc AAA")
    assert suspicious_process("PsExeSvc.exe")
    assert not suspicious_process("chrome.exe")
    assert not suspicious_process(None)
