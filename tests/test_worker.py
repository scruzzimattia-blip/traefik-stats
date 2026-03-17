import pytest
import json
import os
from datetime import datetime
import worker

class MockGeo:
    def resolve(self, ip):
        return {"country_code": "DE", "country_name": "Germany", "city": "Berlin", "asn": "AS1234"}

class MockCrowdSec:
    def __init__(self): self.blocked = []
    def block_ip(self, ip, duration="24h", reason=None):
        self.blocked.append((ip, reason))
        return True

@pytest.fixture
def mock_geo(): return MockGeo()
@pytest.fixture
def mock_crowdsec(): return MockCrowdSec()

def test_worker_ip_utilities():
    from worker import should_ignore_ip, ATTACK_PATTERNS_COMPILED, LOGIN_PATTERNS_COMPILED
    import ipaddress
    
    assert should_ignore_ip("127.0.0.1") is True
    assert should_ignore_ip("192.168.1.1") is True
    assert should_ignore_ip("10.0.0.1") is True
    assert should_ignore_ip("172.16.0.1") is True
    assert should_ignore_ip("8.8.8.8") is False
    assert should_ignore_ip("1.1.1.1") is False
    assert should_ignore_ip("92.106.189.142") is True
    
    worker.IGNORED_NETWORKS = [ipaddress.ip_network("1.2.3.4", strict=False)]
    assert should_ignore_ip("1.2.3.4") is True
    worker.IGNORED_NETWORKS = [ipaddress.ip_network("92.106.189.142", strict=False)]

    is_attack = lambda p: any(r.search(p) for r in ATTACK_PATTERNS_COMPILED)
    assert not is_attack("/")
    assert not is_attack("/index.html")
    assert not is_attack("/api/v1/data")
    assert is_attack("/etc/passwd")
    assert is_attack("/wp-login.php")
    assert is_attack("/.env")
    assert is_attack("/cgi-bin/test.cgi")
    assert is_attack("/.git/config")
    assert is_attack("/ETC/PASSWD")
    
    is_login = lambda p: any(r.search(p) for r in LOGIN_PATTERNS_COMPILED)
    assert is_login("/wp-login")
    assert is_login("/admin")
    assert is_login("/login")
    assert not is_login("/")

def test_log_handler_ip_cleaning(mock_geo):
    handler = worker.LogHandler(mock_geo)
    
    assert handler.clean_ip("192.168.1.1:12345") == "192.168.1.1"
    assert handler.clean_ip("[2001:db8::1]:80") == "2001:db8::1"
    assert handler.clean_ip("1.1.1.1") == "1.1.1.1"
    assert handler.clean_ip("") == ""
    assert handler.clean_ip("") == ""

def test_log_processing(session, mock_geo, mock_crowdsec, tmp_path):
    safe_log = tmp_path / "access.log"
    safe_log.write_text(json.dumps({
        "StartLocal": datetime.now().isoformat(),
        "ClientAddr": "8.8.8.8:443",
        "RequestUserAgent": "Mozilla/5.0",
        "RequestPath": "/safe-path",
        "RequestHost": "example.com",
        "RequestMethod": "GET",
        "RequestProtocol": "HTTP/2.0",
        "DownstreamStatus": 200,
        "Duration": 500000,
        "DownstreamContentSize": 1024
    }) + "\n")
    
    attack_log = tmp_path / "attack.log"
    attack_log.write_text(json.dumps({
        "StartLocal": datetime.now().isoformat(),
        "ClientAddr": "9.9.9.9:443",
        "RequestUserAgent": "EvilBot/1.0",
        "RequestPath": "/.env",
        "RequestHost": "example.com",
        "RequestMethod": "GET",
        "DownstreamStatus": 404
    }) + "\n")
    
    ignored_log = tmp_path / "ignored.log"
    ignored_log.write_text(json.dumps({
        "StartLocal": datetime.now().isoformat(),
        "ClientAddr": "127.0.0.1:443",
        "RequestPath": "/",
        "RequestHost": "localhost"
    }) + "\n")
    
    original_file = worker.LOG_FILE
    worker.LOG_FILE = str(safe_log)
    worker.SessionLocal = lambda: session
    
    handler = worker.LogHandler(mock_geo, mock_crowdsec)
    handler.process_new_lines()
    
    entry = session.query(worker.AccessLog).filter_by(client_addr="8.8.8.8").first()
    assert entry is not None
    assert entry.request_path == "/safe-path"
    assert entry.is_attack is False
    assert entry.country_code == "DE"
    session.commit()
    
    worker.LOG_FILE = str(attack_log)
    handler.last_pos = 0
    handler.process_new_lines()
    
    entry = session.query(worker.AccessLog).filter_by(client_addr="9.9.9.9").first()
    assert entry is not None
    assert entry.is_attack is True
    assert len(mock_crowdsec.blocked) == 1
    assert mock_crowdsec.blocked[0][0] == "9.9.9.9"
    session.commit()
    
    worker.LOG_FILE = str(ignored_log)
    handler.last_pos = 0
    handler.process_new_lines()
    
    entry = session.query(worker.AccessLog).filter_by(client_addr="127.0.0.1").first()
    assert entry is None
    
    worker.LOG_FILE = original_file