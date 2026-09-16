import random

import pytest

from vigil.simulator import SCENARIOS, Background


def test_background_is_benign_and_sorted(env):
    events = Background(env, 1).generate(9 * 3600, 9 * 3600 + 600)
    assert len(events) > 1000
    assert all(e.label == "benign" for e in events)
    assert all(a.ts <= b.ts for a, b in zip(events, events[1:]))
    assert {e.layer for e in events} == {"network", "endpoint", "application"}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_scenarios_are_reproducible(env, name):
    a = SCENARIOS[name](env, random.Random(3), 1000.0)
    b = SCENARIOS[name](env, random.Random(3), 1000.0)
    assert [e.to_dict() for e in a.events] == [e.to_dict() for e in b.events]
    assert a.events and all(e.campaign == a.id for e in a.events)


def test_attack_scenarios_carry_stage_labels(env):
    c = SCENARIOS["intrusion_chain"](env, random.Random(1), 0.0)
    assert {"recon", "brute_force", "lateral_movement", "c2_beacon", "exfiltration"} <= set(c.stages)


def test_benign_noise_is_labelled_benign(env):
    c = SCENARIOS["benign_noise"](env, random.Random(1), 0.0)
    assert all(e.label == "benign" and e.lookalike for e in c.events)
    assert c.stages == {}


def test_telemetry_hides_ground_truth(env):
    c = SCENARIOS["c2_exfil"](env, random.Random(1), 0.0)
    record = c.events[-1].telemetry()
    assert not {"label", "campaign", "lookalike"} & set(record)
