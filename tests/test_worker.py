import pytest
from worker import LogHandler, GeoResolver, should_ignore_ip, AccessLog
import json
import os
from sqlalchemy.orm import Session
from datetime import datetime

class MockGeo:
    def resolve(self, ip):
        return {
            "country_code": "DE", 
            "country_name": "Germany", 
            "city": "Berlin", 
            "asn": "AS1234"
        }

class MockCrowdSec:
    def __init__(self):
        self.blocked = []
    def block_ip(self, ip, duration="24h", reason=None):
        self.blocked.append((ip, reason))
        return True

@pytest.fixture
def mock_geo():
    return MockGeo()

@pytest.fixture
def mock_crowdsec():
    return MockCrowdSec()

def test_should_ignore_ip():
    # Test local/private IPs
    assert should_ignore_ip("127.0.0.1") is True
    assert should_ignore_ip("192.168.1.1") is True
    assert should_ignore_ip("10.0.0.1") is True
    assert should_ignore_ip("172.16.0.1") is True
    
    # Test public IPs
    assert should_ignore_ip("8.8.8.8") is False
    assert should_ignore_ip("1.1.1.1") is False
    
    # Test specific ignored IP
    assert should_ignore_ip("92.106.189.142") is True
    
    # Test via mock of global networks
    import worker
    import ipaddress
    worker.IGNORED_NETWORKS = [ipaddress.ip_network("1.2.3.4", strict=False), ipaddress.ip_network("5.6.7.8", strict=False)]
    assert should_ignore_ip("1.2.3.4") is True
    assert should_ignore_ip("5.6.7.8") is True
    assert should_ignore_ip("92.106.189.142") is False # Overridden by env
    # Restore defaults
    worker.IGNORED_NETWORKS = [ipaddress.ip_network("92.106.189.142", strict=False)]

def test_attack_detection(mock_geo):
    handler = LogHandler(mock_geo)
    
    # Test safe paths
    assert not handler.is_attack("/")
    assert not handler.is_attack("/index.html")
    assert not handler.is_attack("/api/v1/data")
    
    # Test attack patterns
    assert handler.is_attack("/etc/passwd")
    assert handler.is_attack("/wp-login.php")
    assert handler.is_attack("/.env")
    assert handler.is_attack("/cgi-bin/test.cgi")
    assert handler.is_attack("/.git/config")
    # Test case insensitivity
    assert handler.is_attack("/ETC/PASSWD")

def test_ip_cleaning(mock_geo):
    handler = LogHandler(mock_geo)
    
    assert handler.clean_ip("192.168.1.1:12345") == "192.168.1.1"
    assert handler.clean_ip("[2001:db8::1]:80") == "2001:db8::1"
    assert handler.clean_ip("1.1.1.1") == "1.1.1.1"
    assert handler.clean_ip("") == ""
    assert handler.clean_ip(None) == ""

def test_process_log_line_to_db(session, mock_geo, mock_crowdsec, tmp_path):
    # Setup mock log file
    log_file = tmp_path / "access.log"
    log_data = {
        "StartLocal": datetime.now().isoformat(),
        "ClientAddr": "8.8.8.8:443",
        "RequestUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "RequestPath": "/safe-path",
        "RequestHost": "example.com",
        "RequestMethod": "GET",
        "RequestProtocol": "HTTP/2.0",
        "DownstreamStatus": 200,
        "Duration": 500000,
        "DownstreamContentSize": 1024
    }
    log_file.write_text(json.dumps(log_data) + "\n")
    
    # Patch LOG_FILE in worker module
    import worker
    original_log_file = worker.LOG_FILE
    worker.LOG_FILE = str(log_file)
    
    # Patch SessionLocal to use our test session
    from worker import SessionLocal
    worker.SessionLocal = lambda: session
    
    handler = LogHandler(mock_geo, mock_crowdsec)
    handler.process_new_lines()
    
    # Verify DB entry
    entry = session.query(AccessLog).filter_by(client_addr="8.8.8.8").first()
    assert entry is not None
    assert entry.request_path == "/safe-path"
    assert entry.is_attack is False
    assert entry.country_code == "DE"
    
    # Cleanup
    worker.LOG_FILE = original_log_file

def test_process_attack_log_line(session, mock_geo, mock_crowdsec, tmp_path):
    # Setup mock log file with attack
    log_file = tmp_path / "attack.log"
    log_data = {
        "StartLocal": datetime.now().isoformat(),
        "ClientAddr": "9.9.9.9:443",
        "RequestUserAgent": "EvilBot/1.0",
        "RequestPath": "/.env",
        "RequestHost": "example.com",
        "RequestMethod": "GET",
        "DownstreamStatus": 404
    }
    log_file.write_text(json.dumps(log_data) + "\n")
    
    import worker
    original_log_file = worker.LOG_FILE
    worker.LOG_FILE = str(log_file)
    worker.SessionLocal = lambda: session
    
    handler = LogHandler(mock_geo, mock_crowdsec)
    handler.process_new_lines()
    
    # Verify DB entry
    entry = session.query(AccessLog).filter_by(client_addr="9.9.9.9").first()
    assert entry is not None
    assert entry.is_attack is True
    
    # Verify CrowdSec block
    assert len(mock_crowdsec.blocked) == 1
    assert mock_crowdsec.blocked[0][0] == "9.9.9.9"
    assert "Attack pattern" in mock_crowdsec.blocked[0][1]
    
    worker.LOG_FILE = original_log_file

def test_skips_ignored_ip(session, mock_geo, mock_crowdsec, tmp_path):
    # Setup mock log file with ignored IP
    log_file = tmp_path / "ignored.log"
    log_data = {
        "StartLocal": datetime.now().isoformat(),
        "ClientAddr": "127.0.0.1:443",
        "RequestPath": "/",
        "RequestHost": "localhost"
    }
    log_file.write_text(json.dumps(log_data) + "\n")
    
    import worker
    original_log_file = worker.LOG_FILE
    worker.LOG_FILE = str(log_file)
    worker.SessionLocal = lambda: session
    
    handler = LogHandler(mock_geo, mock_crowdsec)
    handler.process_new_lines()
    
    # Verify NO DB entry
    entry = session.query(AccessLog).filter_by(client_addr="127.0.0.1").first()
    assert entry is None
    
    worker.LOG_FILE = original_log_file
