import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.core.scanner import Scanner


def test_scan_single():
    s = Scanner(threads=2, timeout=5)
    res = s.scan(["example.com"])
    assert len(res) == 1
    assert res[0]["host"] == "example.com"
