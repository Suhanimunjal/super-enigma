import json
import os
import tempfile
import pytest

from jocky.declarative import DeclarativeInvestigation, run_declarative_script


def test_declarative_investigation_hash_chain():
    inv = DeclarativeInvestigation(case_id="TEST-CHAIN-001")
    rec1 = inv.record_evidence("system_info", {"os": "windows", "host": "test-box"})
    assert rec1["evidence_id"] == "EV-00001"
    assert len(rec1["raw_sha256"]) == 64
    assert len(rec1["chain_head"]) == 64
    assert inv.chain_head == rec1["chain_head"]

    rec2 = inv.record_evidence("process_table", [{"pid": 100, "name": "explorer.exe"}])
    assert rec2["evidence_id"] == "EV-00002"
    assert rec2["chain_head"] != rec1["chain_head"]
    assert inv.chain_head == rec2["chain_head"]

    # Verification must pass
    assert inv.verify_evidence() is True


def test_declarative_script_execution(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    script = """
    case "INC-TEST-999"
    target all
    collect {
        system
        processes
        network
    }
    analyze {
        suspicious_processes
    }
    timeline
    verify evidence
    report html "custom_report.html"
    """
    success = run_declarative_script(script)
    assert success is True

    # Check that preserved evidence JSON was created
    ev_file = tmp_path / "evidence" / "inc-test-999_preserved.json"
    assert ev_file.exists()
    with open(ev_file, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["case_id"] == "INC-TEST-999"
    assert len(data["records"]) >= 3
    assert len(data["chain_head"]) == 64

    # Check report was created
    rep_file = tmp_path / "custom_report.html"
    assert rep_file.exists()
    content = rep_file.read_text(encoding="utf-8")
    assert "INC-TEST-999" in content
    assert "Evidence Chain &amp; Forensic Hashes" in content or "Evidence Chain & Forensic Hashes" in content
