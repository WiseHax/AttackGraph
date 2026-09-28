"""Fail-closed engine identity verification (C5, SEC-29, SEC-30).

Categories:
- Negative: untraceable source versions, unknown dirty state and malformed or
  incomplete metadata are ENGINE_UNVERIFIABLE (never VERIFIED, never an
  exception), so they cannot authorise persistence.
- Invariant: a hardened runtime with complete metadata and a 40-hex source SHA
  is VERIFIED; dirty state is trusted only when asserted as "true"/"false".
"""

import json
import os
import platform
import stat
from pathlib import Path

import pytest

import scripts.generate_metadata as gen_meta
from app.analytics.engine_identity import EngineIdentityService
from scripts.generate_metadata import get_git_info, parse_dirty_state

VALID_SHA = "0123456789abcdef0123456789abcdef01234567"


def _metadata(**overrides) -> dict:
    metadata = {
        "engine_digest": "a" * 64,
        "source_version": VALID_SHA,
        "dirty": False,
        "source_tree_digest": "b" * 64,
        "dependency_digest": "c" * 64,
        "substrate_digest": "d" * 64,
        "lockfile_digest": "e" * 64,
        "substrate_metadata": {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "platform_system": platform.system(),
            "machine": platform.machine(),
            "libc_name": "glibc",
            "libc_version": "2.36",
            "substrate_completeness": "COMPLETE",
        },
        "dependency_metadata": ["package==1.0.0"],
    }
    metadata.update(overrides)
    return metadata


@pytest.fixture
def hardened_service(tmp_path, monkeypatch):
    """A service whose metadata file passes all runtime hardening checks (0444, root, non-root runtime)."""
    path = tmp_path / "engine_metadata.json"
    original_stat = Path.stat

    def fake_stat(self, *args, **kwargs):
        if self.name == "engine_metadata.json":
            class HardenedStat:
                st_mode = stat.S_IFREG | 0o444
                st_uid = 0
            return HardenedStat()
        return original_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(Path, "lstat", fake_stat)
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(os, "access", lambda p, mode: False, raising=False)

    def write(content) -> EngineIdentityService:
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content if isinstance(content, str) else json.dumps(content))
        return EngineIdentityService(str(path))

    return write


def test_valid_hardened_metadata_with_40_hex_sha_is_verified(hardened_service):
    service = hardened_service(_metadata())
    assert service.check_immutability() == "VERIFIED"
    assert service.authorize_persistence() is True


@pytest.mark.parametrize(
    "source_version",
    [
        "UNKNOWN",
        "",
        "123",
        VALID_SHA[:-1],                  # 39 hex characters
        VALID_SHA + "0",                 # 41 hex characters
        VALID_SHA.upper(),               # git emits lowercase SHAs
        " " + VALID_SHA,
        "g" * 40,
    ],
)
def test_untraceable_source_version_is_unverifiable(hardened_service, source_version):
    service = hardened_service(_metadata(source_version=source_version))
    assert service.check_immutability() == "ENGINE_UNVERIFIABLE(source_version_unverifiable)"
    assert service.authorize_persistence() is False


def test_missing_source_version_is_unverifiable(hardened_service):
    metadata = _metadata()
    del metadata["source_version"]
    service = hardened_service(metadata)
    assert service.check_immutability() == "ENGINE_UNVERIFIABLE(malformed_metadata)"
    assert service.authorize_persistence() is False


def test_dirty_source_is_unverifiable(hardened_service):
    service = hardened_service(_metadata(dirty=True))
    assert service.check_immutability() == "ENGINE_UNVERIFIABLE(dirty_source)"


@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        "[]",
        json.dumps([_metadata()]),
        b"\xff\xfe\x00 not utf-8",
        _metadata(engine_digest="abc"),
        _metadata(source_tree_digest="B" * 64),
        _metadata(dependency_digest="c" * 63),
        _metadata(dependency_metadata=[]),
        _metadata(dirty="false"),
        _metadata(dirty=None),
        _metadata(substrate_metadata={"python_version": platform.python_version()}),
    ],
)
def test_malformed_metadata_is_unverifiable_not_an_exception(hardened_service, content):
    service = hardened_service(content)
    assert service.check_immutability() == "ENGINE_UNVERIFIABLE(malformed_metadata)"
    assert service.authorize_persistence() is False


@pytest.mark.parametrize(
    "value, expected_dirty",
    [
        (None, True),       # missing
        ("", True),         # empty (unset Docker build ARG passed through ENV)
        ("   ", True),
        ("maybe", True),    # ambiguous
        ("0", True),
        ("no", True),
        ("true", True),
        ("TRUE", True),
        ("false", False),
        (" False ", False),
    ],
)
def test_dirty_state_is_trusted_only_when_explicit(value, expected_dirty):
    assert parse_dirty_state(value) is expected_dirty


def _no_git(*args, **kwargs):
    raise FileNotFoundError("git")


@pytest.mark.parametrize("dirty_env", [None, "", "maybe"])
def test_unknown_dirty_env_is_recorded_as_dirty(monkeypatch, dirty_env):
    monkeypatch.setenv("APP_GIT_COMMIT", VALID_SHA)
    if dirty_env is None:
        monkeypatch.delenv("APP_GIT_DIRTY", raising=False)
    else:
        monkeypatch.setenv("APP_GIT_DIRTY", dirty_env)
    monkeypatch.setattr(gen_meta.subprocess, "check_output", _no_git)
    assert get_git_info() == (VALID_SHA, True)


def test_explicit_clean_dirty_env_is_trusted(monkeypatch):
    monkeypatch.setenv("APP_GIT_COMMIT", VALID_SHA)
    monkeypatch.setenv("APP_GIT_DIRTY", "false")
    assert get_git_info() == (VALID_SHA, False)


def test_default_docker_build_without_args_is_unverifiable(monkeypatch, hardened_service):
    """The default compose build passes no build args: both ENV values are empty and git is absent."""
    monkeypatch.setenv("APP_GIT_COMMIT", "")
    monkeypatch.setenv("APP_GIT_DIRTY", "")
    monkeypatch.setattr(gen_meta.subprocess, "check_output", _no_git)

    source_version, dirty = get_git_info()
    assert (source_version, dirty) == ("UNKNOWN", True)

    service = hardened_service(_metadata(source_version=source_version, dirty=dirty))
    assert service.check_immutability().startswith("ENGINE_UNVERIFIABLE(")
    assert service.authorize_persistence() is False

    # Even if the dirty flag were (wrongly) asserted clean, UNKNOWN source still fails closed.
    service = hardened_service(_metadata(source_version=source_version, dirty=False))
    assert service.check_immutability() == "ENGINE_UNVERIFIABLE(source_version_unverifiable)"
