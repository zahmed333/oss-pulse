import pytest

from oss_pulse.config import PROJECT_ROOT, Settings


@pytest.fixture
def settings(tmp_path, monkeypatch) -> Settings:
    monkeypatch.setenv("OSS_PULSE_DATA_DIR", str(tmp_path / "data"))
    return Settings(data_dir=tmp_path / "data", projects_file=PROJECT_ROOT / "tracked_projects.yml")
