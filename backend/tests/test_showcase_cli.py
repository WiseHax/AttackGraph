"""Command-line safety of `python -m app.showcase` (no database needed).

Categories:
- Negative / security (SEC-11): a missing, malformed or unreachable database
  URL fails with a generic message and never echoes the URL or credentials,
  and nothing is written.
"""

import pytest

from app.showcase.__main__ import main

SECRET = "SuperSecret-9f3c"


@pytest.mark.parametrize(
    "url",
    [
        f"postgresql+asyncpg://user:{SECRET}@@@:bad:url",
        f"{SECRET}-not-a-url",
        f"postgresql+nodriver://user:{SECRET}@localhost/db",
        f"postgresql://user:{SECRET}@localhost/db",
        f"postgresql+asyncpg://user:{SECRET}@localhost",
    ],
)
def test_malformed_database_url_is_rejected_without_echoing_it(url, monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("DATABASE_URL", url)
    assert main(["--output-dir", str(tmp_path / "out")]) == 2
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    assert "value not shown" in captured.err
    assert not (tmp_path / "out").exists()


def test_missing_database_url_is_reported(monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert main(["--output-dir", str(tmp_path / "out")]) == 2
    assert "set DATABASE_URL" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_unreachable_database_fails_without_echoing_credentials(monkeypatch, capsys, tmp_path):
    # Port 1 on loopback refuses immediately; no external host is contacted.
    monkeypatch.setenv("DATABASE_URL", f"postgresql+asyncpg://user:{SECRET}@127.0.0.1:1/db")
    assert main(["--output-dir", str(tmp_path / "out")]) == 1
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    assert "could not connect to the database" in captured.err
    assert not (tmp_path / "out").exists()
