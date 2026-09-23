#!/usr/bin/env python3
"""
RelayShield Free Identity & Scam Checks — MCP Server

Exposes RelayShield's keyless, free threat-intelligence checks as callable
tools for Claude and other MCP-compatible AI agents. No API key, no signup,
no payment: every tool calls a free endpoint.

Live tools:
  check_link    — screen URL(s) for phishing/malware (POST /v1/link-check)
  check_wallet  — screen a crypto wallet before paying it (POST /v1/wallet-risk)

Queued for the next merge (endpoints already verified in the OpenAPI spec):
  check_email   — score a parsed phishing email (POST /v1/email-check, keyless)
  check_breach  — email vs 13B+ breached accounts (POST /v1/metered/breach,
                  needs RELAYSHIELD_API_KEY — first calls free per developers page)

Configuration (environment variables, all optional):
  RELAYSHIELD_API_URL — override the API base (default https://api.relayshield.net)
  RELAYSHIELD_API_KEY — accepted by the free endpoints to lift the per-IP
                        daily allowance; required only by check_breach.
"""

import asyncio
import base64
import json
import os

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

API_BASE = os.environ.get("RELAYSHIELD_API_URL", "https://api.relayshield.net").rstrip("/")
API_KEY = os.environ.get("RELAYSHIELD_API_KEY", "")
SOURCE_TAG = "mcp-free"  # recorded by the API so the channel can be measured

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

app = Server("relayshield-free")


def _error(text: str) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=text)]


def _summarise_link(data: dict) -> str:
    """One-line-per-link human summary of a /v1/link-check response."""
    lines = []
    if "results" in data:  # batch form
        counts = data.get("counts", {})
        lines.append(
            "Checked {c} link(s): {f} flagged, {i} incomplete.".format(
                c=counts.get("checked", "?"),
                f=counts.get("flagged", "?"),
                i=counts.get("incomplete", "?"),
            )
        )
        for r in data.get("results", []):
            flag = "FLAGGED" if r.get("flagged") else r.get("level", "unknown").upper()
            reasons = "; ".join(r.get("reasons", []))
            lines.append(f"- [{flag}] {r.get('target')}" + (f" — {reasons}" if reasons else ""))
        for u in data.get("incomplete_urls", []) or []:
            lines.append(f"- [NOT CHECKED — retry] {u}")
    else:  # single-link form
        flag = "FLAGGED" if data.get("flagged") else data.get("level", "unknown").upper()
        lines.append(f"[{flag}] {data.get('target')}")
        for reason in data.get("reasons", []):
            lines.append(f"- {reason}")
        sig = data.get("signals", {})
        lines.append(
            "Signals: IOC corpus={} | Safe Browsing={} | domain age={}d".format(
                sig.get("ioc_corpus"), sig.get("safe_browsing"), sig.get("domain_age_days")
            )
        )
    lines.append("Note: the best verdict this check returns is 'unknown' — absence of evidence is not evidence of absence.")
    return "\n".join(lines)


def _summarise_wallet(data: dict) -> str:
    flags = data.get("risk_flags") or []
    lines = [
        "Address: {}".format(data.get("address")),
        "Chain: {} | Risk: {}".format(data.get("chain"), data.get("risk_level")),
    ]
    for f in flags:
        lines.append(f"- {f}")
    if not flags:
        lines.append("- No flags: nothing known against this address (verdict 'unknown', not 'safe').")
    return "\n".join(lines)


# Tool registry: adding tomorrow's check_email / check_breach is one entry here
# plus a summary function. `body` maps tool arguments to the API request body.
TOOLS: dict[str, dict] = {
    "check_link": {
        "path": "/v1/link-check",
        "summary": _summarise_link,
        "description": (
            "Check one link — or up to 25 at once — for known phishing, malware and scam abuse. "
            "Free and keyless: no API key, no signup, no payment. Signals: RelayShield's criminal "
            "IOC corpus, Google Safe Browsing, and domain registration age. "
            "It never answers 'safe'; the best verdict is 'unknown' (nothing known against the domain). "
            "Use before clicking, forwarding, or quoting a link, and to screen links inside a suspicious message."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "A single link starting with http:// or https://. Omit when sending urls.",
                },
                "urls": {
                    "type": "array",
                    "maxItems": 25,
                    "items": {"type": "string"},
                    "description": "Up to 25 links to check in one call. Omit when sending url.",
                },
            },
        },
        "body": lambda a: {k: v for k, v in {"url": a.get("url"), "urls": a.get("urls")}.items() if v}
        | {"source": SOURCE_TAG},
    },
    "check_wallet": {
        "path": "/v1/wallet-risk",
        "summary": _summarise_wallet,
        "description": (
            "Screen a crypto wallet address BEFORE sending funds to it. Free and keyless: no API key, "
            "no signup, no payment. The chain (EVM, Solana, TON, Bitcoin) is detected from the address "
            "format automatically. Returns a risk level (CRITICAL/HIGH/MEDIUM/LOW/unknown) with the "
            "specific sanctions, scam, drainer and phishing flags behind it. "
            "'unknown' means nothing is known against the address, not that it is safe. "
            "Use whenever a user is about to pay an address they were given."
        ),
        "schema": {
            "type": "object",
            "required": ["address"],
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Wallet address to screen. Chain is auto-detected.",
                },
            },
        },
        "body": lambda a: {"address": a["address"], "source": SOURCE_TAG},
    },
}


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name=name, description=spec["description"], inputSchema=spec["schema"])
        for name, spec in TOOLS.items()
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent] | types.CallToolResult:
    spec = TOOLS.get(name)
    if spec is None:
        return _error(f"Unknown tool: {name}")

    body = spec["body"](arguments or {})
    if name == "check_link" and not body.get("url") and not body.get("urls"):
        return _error("Send either `url` (one link) or `urls` (up to 25), not neither.")

    headers = {"Content-Type": "application/json"}
    if API_KEY:
        # Accepted by the free endpoints; lifts the per-IP daily allowance.
        headers["X-RS-API-KEY"] = API_KEY

    try:
        async with httpx.AsyncClient(timeout=28.0) as client:
            r = await client.post(API_BASE + spec["path"], json=body, headers=headers)
    except httpx.TimeoutException:
        return _error("Request timed out — upstream API did not respond within 28 seconds.")
    except httpx.RequestError as exc:
        return _error(f"Network error: {exc}")

    if not (200 <= r.status_code < 300):
        return types.CallToolResult(
            content=[types.TextContent(
                type="text",
                text=json.dumps({"ok": False, "status_code": r.status_code, "body": r.text[:2000]}),
            )],
            isError=True,
        )

    try:
        payload = r.json()
    except ValueError:
        return _error(f"Upstream returned non-JSON: {r.text[:500]}")

    if not payload.get("ok"):
        return _error(f"Upstream error: {payload.get('error', 'unknown')}")

    text = spec["summary"](payload.get("data", {}))
    text += "\n\nRaw response:\n" + json.dumps(payload, indent=2)[:4000]
    return [types.TextContent(type="text", text=text)]


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main_sync() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main_sync()
