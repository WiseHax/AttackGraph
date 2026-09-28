"""Tests for source digest v2 and delivery control (C6, SEC-28).

Categories:
- Invariant: the source digest covers every delivered file (at any depth)
  except the root-level engine_metadata.json; .dockerignore excludes nested
  cache and secret files using recursive patterns.
- Determinism: the digest is independent of file creation order and is pinned
  for a fixed tree; the engine digest follows the source digest.

The Docker delivery behaviour itself was verified empirically with a scratch
`FROM scratch` build (documented in SEC-28); no test here requires Docker.
"""

import hashlib
import os

import pytest

from scripts.generate_metadata import (
    METADATA_FILENAME,
    compute_engine_digest,
    get_source_tree_info,
)

DOCKERIGNORE = os.path.join(os.path.dirname(__file__), "..", ".dockerignore")

# Digest of _write_tree() under source digest v2. A change means the source
# digest semantics changed and requires a new source digest version.
PINNED_V2_DIGEST = "25a8fb60fd8e7863d12f827a8bd62f3514312be9c6e7c8f3a21481c697737b44"


def _write(root, rel, content: bytes) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _write_tree(root, order=None) -> None:
    files = {
        "app/main.py": b"print('main')\n",
        "app/graph/store.py": b"class Store: ...\n",
        "requirements.lock": b"package==1.0.0\n",
        "Dockerfile": b"FROM python:3.12-slim\n",
    }
    for rel in (order or sorted(files)):
        _write(root, rel, files[rel])


def _digest(root) -> str:
    return get_source_tree_info(str(root))["digest"]


def test_delivered_nested_file_changes_digest(tmp_path):
    """Anything Docker delivers is part of the identity, including nested caches."""
    _write_tree(tmp_path)
    before = _digest(tmp_path)
    _write(tmp_path, "app/__pycache__/main.cpython-312.pyc", b"\x00bytecode")
    assert _digest(tmp_path) != before


def test_non_ignored_nested_source_change_changes_digest(tmp_path):
    _write_tree(tmp_path)
    before = _digest(tmp_path)
    _write(tmp_path, "app/graph/store.py", b"class Store: pass\n")
    assert _digest(tmp_path) != before


def test_root_engine_metadata_is_excluded(tmp_path):
    _write_tree(tmp_path)
    before = _digest(tmp_path)
    _write(tmp_path, METADATA_FILENAME, b'{"engine_digest": "first"}')
    assert _digest(tmp_path) == before
    _write(tmp_path, METADATA_FILENAME, b'{"engine_digest": "second"}')
    assert _digest(tmp_path) == before


def test_only_the_root_engine_metadata_is_excluded(tmp_path):
    _write_tree(tmp_path)
    before = _digest(tmp_path)
    _write(tmp_path, "app/" + METADATA_FILENAME, b"{}")
    assert _digest(tmp_path) != before


def test_source_digest_is_independent_of_creation_order(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    _write_tree(a)
    _write_tree(b, order=["requirements.lock", "app/graph/store.py", "Dockerfile", "app/main.py"])
    assert _digest(a) == _digest(b)
    assert _digest(a) == _digest(a)


def test_source_digest_v2_is_pinned(tmp_path):
    _write_tree(tmp_path)
    assert _digest(tmp_path) == PINNED_V2_DIGEST


def test_source_digest_uses_v2_domain_separator(tmp_path):
    _write(tmp_path, "a.py", b"x")
    file_hash = hashlib.sha256(b"x").hexdigest()
    expected = hashlib.sha256(
        b"attackgraph.source.v2" + f"4:a.py|{len(file_hash)}:{file_hash}".encode("utf-8")
    ).hexdigest()
    assert _digest(tmp_path) == expected


def test_engine_digest_follows_source_digest():
    base = compute_engine_digest("a" * 40, "1" * 64, "2" * 64, "3" * 64)
    assert compute_engine_digest("a" * 40, "1" * 64, "2" * 64, "3" * 64) == base
    assert compute_engine_digest("a" * 40, "4" * 64, "2" * 64, "3" * 64) != base
    assert base == hashlib.sha256(
        ("attackgraph.engine.v1" + "a" * 40 + "1" * 64 + "2" * 64 + "3" * 64).encode("utf-8")
    ).hexdigest()


def _dockerignore_patterns() -> list[str]:
    with open(DOCKERIGNORE, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]


@pytest.mark.parametrize(
    "pattern",
    [
        "**/.env", "**/.venv", "**/credentials", "**/private_keys", "**/*.pem", "**/*.key",
        "**/__pycache__", "**/*.py[cod]", "**/.pytest_cache", "**/.mypy_cache",
    ],
)
def test_dockerignore_excludes_nested_cache_and_secret_patterns(pattern):
    """Docker anchors bare patterns at the context root; nested exclusion needs `**/`."""
    assert pattern in _dockerignore_patterns()


def test_dockerignore_has_no_root_only_cache_or_secret_patterns():
    root_only = {".env", "__pycache__", "__pycache__/", "*.py[cod]", ".pytest_cache", ".pytest_cache/",
                 "*.pem", "*.key", "credentials", "private_keys/", ".venv/"}
    assert not root_only & set(_dockerignore_patterns())


def test_dockerignore_does_not_exclude_nested_env_or_venv_packages():
    """Nested `env` / `venv` directories may be legitimate source; only the root ones are excluded."""
    patterns = _dockerignore_patterns()
    assert "venv/" in patterns and "env/" in patterns
    assert "**/env" not in patterns and "**/venv" not in patterns
