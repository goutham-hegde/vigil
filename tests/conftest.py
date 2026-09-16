import os
import subprocess
import sys
from pathlib import Path

import pytest

from vigil.environment import Environment
from vigil.model import Detector


@pytest.fixture(scope="session")
def env() -> Environment:
    return Environment()


@pytest.fixture(scope="session")
def model_dir(tmp_path_factory) -> Path:
    """A small model trained once per test session (about a minute).

    Set VIGIL_TEST_MODEL_DIR to reuse an existing model and skip training.
    """
    existing = os.environ.get("VIGIL_TEST_MODEL_DIR")
    if existing:
        return Path(existing)
    out = tmp_path_factory.mktemp("model")
    subprocess.run([sys.executable, "-m", "vigil.train", "--quick", "--out", str(out)], check=True,
                   stdout=subprocess.DEVNULL)
    return out


@pytest.fixture(scope="session")
def detector(model_dir) -> Detector:
    return Detector.load(model_dir)
