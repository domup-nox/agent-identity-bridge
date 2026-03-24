"""Tests for the AIB CLI."""

import json
import subprocess
import sys
import pytest
from pathlib import Path


@pytest.fixture
def aib_home(tmp_path):
    return str(tmp_path / "aib-test")


def run_cli(*args, aib_home=None, input_data=None):
    env = {"AIB_HOME": aib_home} if aib_home else {}
    env["PATH"] = "/usr/bin:/bin"
    result = subprocess.run(
        [sys.executable, "-m", "aib.cli", *args],
        capture_output=True, text=True, env={**dict(__import__("os").environ), **env},
        input=input_data, cwd=str(Path(__file__).parent.parent),
    )
    return result


class TestCLI:

    def test_help(self, aib_home):
        r = run_cli("--help", aib_home=aib_home)
        assert r.returncode == 0
        assert "Agent Identity Bridge" in r.stdout

    def test_version(self, aib_home):
        r = run_cli("--version", aib_home=aib_home)
        assert r.returncode == 0
        assert "0.2.0" in r.stdout

    def test_create_and_list(self, aib_home):
        r = run_cli("create", "--org", "test", "--agent", "bot1",
                     "--protocols", "mcp,a2a", aib_home=aib_home)
        assert r.returncode == 0
        assert "urn:aib:agent:test:bot1" in r.stdout

        r2 = run_cli("list", aib_home=aib_home)
        assert r2.returncode == 0
        assert "bot1" in r2.stdout
        assert "ACTIVE" in r2.stdout

    def test_create_with_capabilities(self, aib_home):
        r = run_cli("create", "--org", "test", "--agent", "smart",
                     "--protocols", "mcp", "--capabilities", "search,booking",
                     aib_home=aib_home)
        assert r.returncode == 0
        assert "search" in r.stdout
        assert "booking" in r.stdout

    def test_inspect(self, aib_home):
        run_cli("create", "--org", "test", "--agent", "insp",
                "--protocols", "a2a", aib_home=aib_home)
        r = run_cli("inspect", "--id", "urn:aib:agent:test:insp", aib_home=aib_home)
        assert r.returncode == 0
        assert "passport_id" in r.stdout
        assert "VALID" in r.stdout

    def test_revoke_and_verify(self, aib_home):
        run_cli("create", "--org", "test", "--agent", "rev",
                "--protocols", "mcp", "--show-token", aib_home=aib_home)

        r = run_cli("revoke", "--id", "urn:aib:agent:test:rev", aib_home=aib_home)
        assert r.returncode == 0
        assert "revoked" in r.stdout.lower()

        r2 = run_cli("list", aib_home=aib_home)
        assert "REVOKED" in r2.stdout

    def test_translate_a2a_to_mcp(self, aib_home, tmp_path):
        card = {"name": "CLI Test", "url": "https://test.com",
                "skills": [{"id": "s1", "name": "Skill1", "description": "D"}],
                "authentication": {"schemes": ["bearer"]}}
        src = tmp_path / "card.json"
        src.write_text(json.dumps(card))

        r = run_cli("translate", "--from", "a2a", "--to", "mcp",
                     "--file", str(src), aib_home=aib_home)
        assert r.returncode == 0
        assert "tools" in r.stdout
        assert "CLI Test" in r.stdout

    def test_translate_to_did(self, aib_home, tmp_path):
        card = {"name": "DID Test", "url": "https://test.com",
                "skills": [{"id": "s1", "name": "S1"}],
                "authentication": {"schemes": ["bearer"]}}
        src = tmp_path / "card.json"
        src.write_text(json.dumps(card))

        r = run_cli("translate", "--from", "a2a", "--to", "did",
                     "--file", str(src), "--domain", "test.com",
                     "--slug", "didagent", aib_home=aib_home)
        assert r.returncode == 0
        assert "did:web:test.com:agents:didagent" in r.stdout

    def test_keygen(self, aib_home):
        r = run_cli("keygen", aib_home=aib_home)
        assert r.returncode == 0
        assert "RS256" in r.stdout

    def test_keygen_rotate(self, aib_home):
        run_cli("keygen", aib_home=aib_home)  # init
        r = run_cli("keygen", "--rotate", aib_home=aib_home)
        assert r.returncode == 0
        assert "rotated" in r.stdout.lower()
