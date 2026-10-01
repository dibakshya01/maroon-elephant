"""Orchestrator (prioritization + hash-chained log) and MCP server handler."""
import os

from maroon.mcpserver import server as mcp
from maroon.orchestrator import Orchestrator, prioritize

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "benchmarks", "fixtures")


def test_prioritize_crown_jewels_first():
    q = prioritize(["a/payments", "b/marketing", "c/docs"], "the payments service")
    assert q[0]["target"] == "a/payments" and q[0]["priority"] == "P0"
    assert any(x["priority"] == "P2" and "docs" in x["target"] for x in q)


def test_orchestrator_runs_and_log_verifies():
    orch = Orchestrator(crown_jewels="vuln_app", with_subscanners=False)
    events = []
    out = orch.run([os.path.join(FIX, "vuln_app"), os.path.join(FIX, "clean_app")],
                   on_event=events.append)
    assert out["log_verified"] is True
    assert len(out["results"]) == 2
    kinds = [e["kind"] for e in events]
    assert "plan" in kinds and "complete" in kinds
    # vuln_app (crown jewel) scanned before clean_app
    order = [e["target"] for e in events if e["kind"] == "scan_start"]
    assert order[0].endswith("vuln_app")


def test_hash_chain_tamper_detected():
    orch = Orchestrator(with_subscanners=False)
    orch.run([os.path.join(FIX, "clean_app")])
    assert orch.log.verify() is True
    orch.log.entries[0]["kind"] = "tampered"
    assert orch.log.verify() is False


def test_mcp_initialize_and_tools():
    init = mcp._handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18"}})
    assert init["result"]["protocolVersion"] == "2025-06-18"
    assert init["result"]["serverInfo"]["name"] == "maroon-elephant"
    tools = mcp._handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in tools["result"]["tools"]}
    assert "maroon_scan_path" in names and "maroon_explain_risk" in names


def test_mcp_explain_risk():
    resp = mcp._handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "maroon_explain_risk", "arguments": {"control_id": "LLM01"}}})
    text = resp["result"]["content"][0]["text"]
    assert "Prompt Injection" in text


def test_mcp_unknown_tool_is_error_not_crash():
    resp = mcp._handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                        "params": {"name": "nope", "arguments": {}}})
    assert resp["result"]["isError"] is True
