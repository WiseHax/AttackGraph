import pytest
import os
import json
import hashlib
from unittest import mock
from pathlib import Path
from app.analytics.engine_identity import EngineIdentityService, EngineMetadata, SubstrateMetadata
import platform
import stat

# --- Engine Identity Digest Rules ---
def test_dependency_pep503_normalization(tmp_path):
    from scripts.generate_metadata import get_dependency_info

    # Create a mock lockfile
    lockfile_path = tmp_path / "requirements.lock"
    content1 = """
Flask-AppBuilder==4.1.4 \\
    --hash=sha256:abc
    """
    lockfile_path.write_text(content1)

    info1 = get_dependency_info(str(lockfile_path))
    assert "flask-appbuilder==4.1.4" in info1["metadata"]

    content2 = """
# A comment here
flask_appbuilder==4.1.4 \\
    --hash=sha256:def
    """
    lockfile_path.write_text(content2)
    info2 = get_dependency_info(str(lockfile_path))
    assert "flask-appbuilder==4.1.4" in info2["metadata"]

    # The hashes and comments change the lockfile digest, but dependency digest must be the same
    assert info1["digest"] == info2["digest"]
    assert info1["lockfile_digest"] != info2["lockfile_digest"]

def test_dependency_version_changes_digest(tmp_path):
    from scripts.generate_metadata import get_dependency_info
    p = tmp_path / "req.lock"
    p.write_text("package==1.0.0")
    d1 = get_dependency_info(str(p))["digest"]
    p.write_text("package==1.0.1")
    d2 = get_dependency_info(str(p))["digest"]
    assert d1 != d2

def test_source_tree_digest_changes_on_file_change(tmp_path):
    from scripts.generate_metadata import get_source_tree_info
    (tmp_path / "test.py").write_text("print('hello')")
    d1 = get_source_tree_info(str(tmp_path))["digest"]

    (tmp_path / "test.py").write_text("print('world')")
    d2 = get_source_tree_info(str(tmp_path))["digest"]
    assert d1 != d2

def test_gitignored_but_docker_delivered_changes_digest(tmp_path):
    from scripts.generate_metadata import get_source_tree_info
    (tmp_path / "secret.env").write_text("PASSWORD=123")
    d1 = get_source_tree_info(str(tmp_path))["digest"]

    (tmp_path / ".dockerignore").write_text("secret.env\\n")
    d2 = get_source_tree_info(str(tmp_path))["digest"]

    assert d1 != d2

def test_dirty_trees_at_same_commit_differ(tmp_path):
    from scripts.generate_metadata import get_source_tree_info
    # Since source tree digest hashes all non-ignored files, two different dirty states
    # (untracked files or tracked modifications) will hash differently.
    (tmp_path / "file1.py").write_text("A")
    d1 = get_source_tree_info(str(tmp_path))["digest"]

    (tmp_path / "file1.py").write_text("B")
    d2 = get_source_tree_info(str(tmp_path))["digest"]
    assert d1 != d2

def test_substrate_digest_changes(monkeypatch):
    from scripts.generate_metadata import get_substrate_info

    monkeypatch.setattr(platform, "python_version", lambda: "3.12.0")
    d1 = get_substrate_info()["digest"]

    monkeypatch.setattr(platform, "python_version", lambda: "3.12.1")
    d2 = get_substrate_info()["digest"]
    assert d1 != d2

def test_incomplete_substrate_explicitly_detected(monkeypatch):
    from scripts.generate_metadata import get_substrate_info
    import scripts.generate_metadata as gen_meta

    # Mock get_libc_info to return unknown
    monkeypatch.setattr(gen_meta, "get_libc_info", lambda: ("unknown", "unknown"))
    info = get_substrate_info()
    assert info["metadata"]["substrate_completeness"] == "INCOMPLETE"

# --- ART-25 and J-19 Runtime Immuntability Checks ---

@pytest.fixture
def mock_metadata_file(tmp_path):
    metadata = {
        "engine_digest": "abc",
        "source_version": "123",
        "dirty": False,
        "source_tree_digest": "def",
        "dependency_digest": "ghi",
        "substrate_digest": "jkl",
        "lockfile_digest": "mno",
        "substrate_metadata": {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(), # Match runtime to avoid mismatch error
            "platform_system": platform.system(),
            "machine": platform.machine(),
            "libc_name": "glibc",
            "libc_version": "2.31",
            "substrate_completeness": "COMPLETE"
        },
        "dependency_metadata": []
    }
    file_path = tmp_path / "engine_metadata.json"
    file_path.write_text(json.dumps(metadata))
    return file_path

def test_missing_metadata(tmp_path):
    svc = EngineIdentityService(str(tmp_path / "nonexistent.json"))
    assert svc.check_immutability() == "ENGINE_UNVERIFIABLE(missing_metadata)"
    assert not svc.authorize_persistence()

def test_python_version_mismatch(mock_metadata_file, monkeypatch):
    svc = EngineIdentityService(str(mock_metadata_file))
    # Fake runtime python version
    monkeypatch.setattr(platform, "python_version", lambda: "3.9.9")
    # Must bypass permissions check for this unit test if running on windows/local
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(os, "access", lambda path, mode: False, raising=False)

    # We also need to mock stat perms to 0444 and uid to 0
    original_stat = os.stat
    def mock_stat(path, *args, **kwargs):
        st = original_stat(path, *args, **kwargs)
        # return a mock stat result
        class MockStat:
            st_mode = stat.S_IFREG | 0o444
            st_uid = 0
        return MockStat()
    monkeypatch.setattr(Path, "stat", mock_stat)
    monkeypatch.setattr(Path, "lstat", mock_stat)

    assert svc.check_immutability() == "ENGINE_UNVERIFIABLE(python_version_mismatch)"

def mock_stat_factory(mode):
    def mock_stat(self, *args, **kwargs):
        if self.name == "engine_metadata.json":
            class MockStat:
                st_mode = stat.S_IFREG | mode
                st_uid = 0
            return MockStat()
        else:
            return Path._original_stat(self, *args, **kwargs)
    return mock_stat

def test_writable_metadata(mock_metadata_file, monkeypatch):
    svc = EngineIdentityService(str(mock_metadata_file))
    Path._original_stat = Path.stat
    monkeypatch.setattr(Path, "stat", mock_stat_factory(0o644))
    monkeypatch.setattr(Path, "lstat", mock_stat_factory(0o644))

    assert svc.check_immutability() == "ENGINE_UNVERIFIABLE(metadata_not_0444)"

def test_root_bypass(mock_metadata_file, monkeypatch):
    svc = EngineIdentityService(str(mock_metadata_file))
    Path._original_stat = Path.stat
    monkeypatch.setattr(Path, "stat", mock_stat_factory(0o444))
    monkeypatch.setattr(Path, "lstat", mock_stat_factory(0o444))

    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert svc.check_immutability() == "ENGINE_UNVERIFIABLE(runtime_is_root)"

def test_writable_parent(mock_metadata_file, monkeypatch):
    svc = EngineIdentityService(str(mock_metadata_file))
    Path._original_stat = Path.stat
    monkeypatch.setattr(Path, "stat", mock_stat_factory(0o444))
    monkeypatch.setattr(Path, "lstat", mock_stat_factory(0o444))


    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)

    def mock_access(path, mode):
        # Writable parent
        if str(path) == str(mock_metadata_file.parent):
            return True
        return False
    monkeypatch.setattr(os, "access", mock_access, raising=False)

    assert svc.check_immutability() == "ENGINE_UNVERIFIABLE(parent_directory_writable)"

def test_symlink_metadata(mock_metadata_file, monkeypatch):
    svc = EngineIdentityService(str(mock_metadata_file))
    Path._original_stat = Path.stat
    def mock_lstat(self, *args, **kwargs):
        if self.name == "engine_metadata.json":
            class MockStat:
                st_mode = stat.S_IFLNK | 0o444
                st_uid = 0
            return MockStat()
        return Path._original_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", mock_lstat)
    monkeypatch.setattr(Path, "stat", mock_stat_factory(0o444))

    assert svc.check_immutability() == "ENGINE_UNVERIFIABLE(metadata_is_symlink)"

def test_hardened_configuration_succeeds(mock_metadata_file, monkeypatch):
    svc = EngineIdentityService(str(mock_metadata_file))
    Path._original_stat = Path.stat
    monkeypatch.setattr(Path, "stat", mock_stat_factory(0o444))
    monkeypatch.setattr(Path, "lstat", mock_stat_factory(0o444))

    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(os, "access", lambda path, mode: False, raising=False)

    assert svc.check_immutability() == "VERIFIED"
    assert svc.authorize_persistence() is True
