"""
Unit tests for multi-format log parser.
"""

from app.parser.log_parser import LogParser

def test_parse_empty_content():
    events, warnings = LogParser.parse_content("")
    assert len(events) == 0
    assert len(warnings) > 0

def test_parse_bracketed_log():
    raw = "2026-10-01 10:31:02 [WARN] [192.168.1.20] [admin] LOGIN_FAILED: Failed SSH login from 192.168.1.20"
    events, warnings = LogParser.parse_content(raw, "test.log")
    assert len(events) == 1
    ev = events[0]
    assert ev["timestamp"] == "2026-10-01T10:31:02"
    assert ev["source_ip"] == "192.168.1.20"
    assert ev["username"] == "admin"
    assert ev["event_type"] == "LOGIN_FAILED"

def test_parse_syslog_format():
    raw = (
        "Oct 01 10:31:02 server sshd[102]: Failed password for invalid user admin from 192.168.1.20 port 22 ssh2\n"
        "Oct 01 10:31:10 server sshd[102]: Accepted password for admin from 192.168.1.20 port 22 ssh2\n"
        "Oct 01 10:31:15 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash"
    )
    events, warnings = LogParser.parse_content(raw, "auth.log")
    assert len(events) == 3
    assert events[0]["event_type"] == "LOGIN_FAILED"
    assert events[0]["source_ip"] == "192.168.1.20"
    assert events[1]["event_type"] == "LOGIN_SUCCESS"
    assert events[2]["event_type"] == "PRIVILEGE_ESCALATION"

def test_parse_csv_content():
    csv_text = (
        "timestamp,source_ip,username,event_type,severity,message\n"
        "2026-10-01 10:00:00,10.0.0.5,alice,LOGIN_SUCCESS,LOW,Successful portal login\n"
        "2026-10-01 10:05:00,10.0.0.5,alice,LOGOUT,LOW,User logged out\n"
    )
    events, warnings = LogParser.parse_content(csv_text, "audit.csv")
    assert len(events) == 2
    assert events[0]["source_ip"] == "10.0.0.5"
    assert events[0]["username"] == "alice"
    assert events[0]["event_type"] == "LOGIN_SUCCESS"
    assert events[1]["event_type"] == "LOGOUT"

def test_parse_json_array():
    json_text = """[
        {"timestamp": "2026-10-01T12:00:00", "source_ip": "172.16.0.2", "username": "bob", "event_type": "LOGIN_SUCCESS", "message": "API key auth"},
        {"timestamp": "2026-10-01T12:05:00", "source_ip": "172.16.0.2", "username": "bob", "event_type": "FILE_CREATED", "message": "Uploaded report.pdf"}
    ]"""
    events, warnings = LogParser.parse_content(json_text, "events.json")
    assert len(events) == 2
    assert events[0]["username"] == "bob"
    assert events[1]["event_type"] == "FILE_CREATED"

def test_parse_malformed_lines_graceful():
    malformed = (
        "CORRUPT GARBAGE LINE WITHOUT MEANING\n"
        "2026-10-01 10:00:00 [INFO] [10.0.0.1] [valid] LOGIN_SUCCESS: Good line\n"
        "Another random text line !!!\n"
    )
    events, warnings = LogParser.parse_content(malformed, "sample_malformed.log")
    # Parser should never crash; all 3 lines safely ingested
    assert len(events) == 3
    assert events[1]["event_type"] == "LOGIN_SUCCESS"
    assert events[0]["event_type"] == "OTHER"
