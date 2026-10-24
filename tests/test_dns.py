import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.core.dns_resolver import resolve_cname


def test_resolve_example():
    cname, chain, ips = resolve_cname("example.com")
    # example.com has no CNAME; should return ips
    assert isinstance(ips, list)


def test_resolve_cname_host():
    cname, chain, ips = resolve_cname("www.heroku.com")
    assert cname is not None
    assert "heroku" in cname.lower() or "vip" in cname.lower()
