import random

from vigil.detection import DetectionEngine
from vigil.simulator import SCENARIOS, Background

START = 10 * 3600.0


def run(detector, env, *campaign_specs, seed=11, minutes=90):
    rng = random.Random(seed)
    bg = Background(env, seed)
    engine = DetectionEngine(detector, env)
    engine.warmup(bg.generate(START - 1800, START))
    events = bg.generate(START, START + minutes * 60)
    campaigns = []
    for name, offset in campaign_specs:
        c = SCENARIOS[name](env, rng, START + offset)
        campaigns.append(c)
        events += c.events
    events.sort(key=lambda e: e.ts)
    for i in range(0, len(events), 500):
        engine.process(events[i:i + 500])
    return engine, campaigns


def alerts_of(engine, campaign):
    return [a for a in engine.alerts.alerts.values() if campaign.id in a.campaigns]


def test_kill_chain_becomes_one_multi_stage_incident(detector, env):
    engine, [c] = run(detector, env, ("intrusion_chain", 300))
    own = alerts_of(engine, c)
    assert own, "the attack raised no alerts"
    incidents = {a.incident_id for a in own if a.incident_id}
    assert incidents
    biggest = max((engine.correlator.incidents[i] for i in incidents), key=lambda i: len(i.alert_ids))
    assert len(biggest.data["tactics"]) >= 3
    assert biggest.data["severity"] == "critical"


def test_benign_lookalikes_raise_few_alerts(detector, env):
    engine, [c] = run(detector, env, ("benign_noise", 300), minutes=60)
    assert len(alerts_of(engine, c)) <= 2


def test_independent_attacks_on_one_server_stay_separate(detector, env):
    # Two unrelated botnets hours apart must not merge just because they hit the same web server.
    engine, (a, b) = run(detector, env, ("credential_stuffing", 60), ("credential_stuffing", 4 * 3600), minutes=300)
    inc_a = {x.incident_id for x in alerts_of(engine, a) if x.incident_id}
    inc_b = {x.incident_id for x in alerts_of(engine, b) if x.incident_id}
    assert inc_a and inc_b
    assert not inc_a & inc_b


def test_explanations_name_real_features(detector, env):
    engine, _ = run(detector, env, ("credential_stuffing", 60), minutes=20)
    alert = next(a for a in engine.alerts.alerts.values() if a.threat == "brute_force")
    assert 1 <= len(alert.explanation) <= 6
    assert all(item["label"] and item["method"] == "shap" for item in alert.explanation)
    playbook = alert.to_dict()["playbook"]
    assert alert.entity in " ".join(playbook["contain"])
