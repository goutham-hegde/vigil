import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from vigil.data import lanl
from vigil.data.fixture import write_fixture
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


def build_lanl(root: Path, raw: Path) -> dict:
    """Ingest and build a LANL-format dataset under `root`; returns a benchmark config for it."""
    c = yaml.safe_load((lanl.REPO / "configs" / "fixture.yaml").read_text())
    c["data"].update(raw=str(raw), parquet=str(root / "parquet"), derived=str(root / "derived"))
    lanl.ingest(lanl.TABLES, raw, root / "parquet", log=lambda m: None)
    lanl.build_derived(lanl.connect(root / "parquet"), root / "derived", log=lambda m: None)
    return c


@pytest.fixture(scope="session")
def lanl_fixture(tmp_path_factory) -> tuple[Path, dict]:
    """The generated LANL-format dataset, ingested and built once per session."""
    root = tmp_path_factory.mktemp("lanl")
    return root, build_lanl(root, write_fixture(root / "raw"))
