import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.core.fingerprint_db import match_service


def test_match_github_pages():
    svc = match_service("foo.github.io", "There isn't a GitHub Pages site here", 404)
    assert svc is not None
    assert svc["service"] == "GitHub Pages"
    assert svc["confidence"] == "high"


def test_no_match():
    svc = match_service("example.com", "hello", 200)
    assert svc is None


def test_medium_confidence():
    svc = match_service("foo.herokuapp.com", "nothing", 404)
    assert svc is not None
    assert svc["confidence"] == "medium"
