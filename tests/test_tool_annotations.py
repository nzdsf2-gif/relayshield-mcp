"""MCPB packaging validation for the RelayShield free MCP server.

Validates the requirements for Anthropic's connector directory / Claude
Marketplace desktop-extension (MCPB) submission:
  - tool names <= 64 chars
  - every tool carries a title and readOnlyHint: true
  - descriptions are narrow and functional (no promotional language,
    no instructions to call other tools, no third-party attribution)
  - check_wallet is unmistakably read-only

Run: PYTHONPATH=src pytest tests/ -q
"""

import asyncio
import json

import pytest

from relayshield_free import server as free_server

EXPECTED_TOOLS = ["check_link", "check_wallet", "check_email", "check_breach"]

BANNED_PHRASES = [
    "free and keyless",
    "no signup",
    "no payment",
    "best-in-class",
    "cutting-edge",
    "powerful",
    "seamlessly",
    "call check_",
    "use the check_",
]


def _tools():
    return asyncio.run(free_server.list_tools())


def test_tool_names():
    tools = _tools()
    names = [t.name for t in tools]
    assert names == EXPECTED_TOOLS
    for t in tools:
        assert len(t.name) <= 64, f"tool name too long: {t.name}"


def test_titles_and_read_only_annotations():
    for t in _tools():
        assert t.title, f"{t.name} has no title"
        assert t.annotations is not None, f"{t.name} has no annotations"
        assert t.annotations.readOnlyHint is True, f"{t.name} missing readOnlyHint"


def test_descriptions_functional_not_promotional():
    for t in _tools():
        low = t.description.lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in low, f"{t.name} description contains {phrase!r}"
        # every description must state the never-safe semantics: either the
        # 'unknown' verdict framing or an explicit negation of safety
        assert ("unknown" in low) or ("not" in low and "safe" in low), (
            f"{t.name} description missing never-safe semantics"
        )


def test_wallet_unmistakably_read_only():
    tools = {t.name: t for t in _tools()}
    desc = tools["check_wallet"].description.lower()
    assert "never moves funds" in desc
    assert "initiates transactions" in desc


def test_manifest_valid():
    with open("manifest.json") as f:
        manifest = json.load(f)
    assert manifest["manifest_version"] in ("0.2", "0.3")
    assert manifest["privacy_policies"], "privacy_policies array required"
    for url in manifest["privacy_policies"]:
        assert url.startswith("https://"), f"privacy URL must be HTTPS: {url}"
    assert manifest["server"]["type"] == "python"
    assert manifest["server"]["mcp_config"]["command"] == "python"
    names = [t["name"] for t in manifest["tools"]]
    assert names == EXPECTED_TOOLS


def test_breach_without_key_returns_setup_instructions():
    # No RELAYSHIELD_API_KEY in this environment -> must short-circuit
    # with setup instructions and make no network call.
    assert not free_server.API_KEY
    result = asyncio.run(free_server.call_tool("check_breach", {"email": "a@b.com"}))
    text = result[0].text
    assert "RELAYSHIELD_API_KEY" in text
    assert "check_breach needs" in text
