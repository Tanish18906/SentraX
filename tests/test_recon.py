"""Tests for ReconAgent (Phase 2)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import requests

from sentrax.agents.recon import ReconAgent, TargetUnreachableError
from sentrax.utils.schema import ReconFolderResult, ReconURLResult


SAMPLE_HTML_PAGE_1 = """<!DOCTYPE html>
<html>
<head><title>Test Store</title></head>
<body>
  <h1>Welcome to Store</h1>
  <a href="/login">Login</a>
  <a href="/reviews">Reviews</a>
  <a href="https://external.example.com">External</a>
  <form action="/api/search" method="GET">
    <input type="text" name="q" placeholder="Search products...">
    <button type="submit">Search</button>
  </form>
  <script>
    fetch('/api/products').then(res => res.json());
  </script>
</body>
</html>
"""

SAMPLE_HTML_PAGE_2 = """<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <h2>User Login</h2>
  <form action="/api/login" method="POST">
    <input type="email" name="email" required>
    <input type="password" name="password" required>
    <input type="submit" value="Submit">
  </form>
</body>
</html>
"""

SAMPLE_HTML_PAGE_3 = """<!DOCTYPE html>
<html>
<head><title>Reviews</title></head>
<body>
  <h2>Product Reviews</h2>
  <form action="/api/reviews" method="POST">
    <input type="number" name="rating" min="1" max="5">
    <textarea name="comment"></textarea>
    <button type="submit">Post Review</button>
  </form>
  <div id="reviews-list"></div>
  <script src="/js/reviews.js"></script>
</body>
</html>
"""


def test_recon_dast_mock_crawl():
    def mock_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        if url.rstrip("/").endswith("testtarget.local"):
            resp.url = "http://testtarget.local/"
            resp.text = SAMPLE_HTML_PAGE_1
        elif url.endswith("/login"):
            resp.url = "http://testtarget.local/login"
            resp.text = SAMPLE_HTML_PAGE_2
        elif url.endswith("/reviews"):
            resp.url = "http://testtarget.local/reviews"
            resp.text = SAMPLE_HTML_PAGE_3
        else:
            resp.status_code = 404
            resp.text = "Not Found"
        return resp

    session = MagicMock()
    session.get.side_effect = mock_get
    session.headers = {}

    agent = ReconAgent(session=session)
    result = agent.scan_url("http://testtarget.local", max_depth=2)

    # Validate with Pydantic model
    validated = ReconURLResult(**result)
    assert validated.mode == "url"
    assert validated.target == "http://testtarget.local"
    assert len(validated.pages) >= 3

    # Check login form extraction
    login_page = next((p for p in validated.pages if "/login" in p.url), None)
    assert login_page is not None
    assert len(login_page.forms) == 1
    assert login_page.forms[0].action == "/api/login"
    assert login_page.forms[0].method == "POST"
    assert "email" in login_page.forms[0].fields
    assert "password" in login_page.forms[0].fields

    # Check endpoints observed on home page
    home_page = next((p for p in validated.pages if p.url.rstrip("/").endswith("testtarget.local")), None)
    assert home_page is not None
    assert "/api/products" in home_page.endpoints_observed


def test_recon_dast_unreachable_target():
    agent = ReconAgent()
    with pytest.raises(TargetUnreachableError):
        agent.scan_url("http://127.0.0.1:59999", timeout=0.5)


def test_recon_sast_scan_folder(tmp_path: Path):
    agent = ReconAgent()

    # Create dummy source files
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    login_file = src_dir / "login.js"
    login_file.write_text(
        'const email = req.body.email;\n'
        'const query = "SELECT * FROM users WHERE email=\'" + email + "\'";\n'
        'db.query(query);\n'
    )

    review_file = src_dir / "reviews.js"
    review_file.write_text(
        'function renderReview(review) {\n'
        '  container.innerHTML = review.text;\n'
        '}\n'
    )

    auth_file = src_dir / "auth.py"
    auth_file.write_text(
        '# configuration file\n'
        'JWT_SECRET = "supersecret12345"\n'
    )

    order_file = src_dir / "orders.js"
    order_file.write_text(
        'app.get("/api/order/:id", async (req, res) => {\n'
        '  const order = await Order.findById(req.params.id);\n'
        '  res.json(order);\n'
        '});\n'
    )

    result = agent.scan_folder(str(src_dir))

    validated = ReconFolderResult(**result)
    assert validated.mode == "folder"
    assert len(validated.findings_raw) == 4

    patterns_found = {f.pattern for f in validated.findings_raw}
    assert "sqli_concat" in patterns_found
    assert "xss_innerhtml" in patterns_found
    assert "hardcoded_secret" in patterns_found
    assert "idor_missing_authz" in patterns_found


def test_recon_sast_nonexistent_folder():
    agent = ReconAgent()
    with pytest.raises(FileNotFoundError):
        agent.scan_folder("/path/that/definitely/does/not/exist/sentrax123")


def test_recon_fixtures_schema_conformity():
    fixture_url_path = Path("fixtures/sample_recon_url.json")
    if fixture_url_path.exists():
        with open(fixture_url_path) as f:
            data = json.load(f)
            validated = ReconURLResult(**data)
            assert validated.mode == "url"

    fixture_folder_path = Path("fixtures/sample_recon_folder.json")
    if fixture_folder_path.exists():
        with open(fixture_folder_path) as f:
            data = json.load(f)
            validated = ReconFolderResult(**data)
            assert validated.mode == "folder"


def test_recon_run_dispatcher():
    agent = ReconAgent()
    with patch.object(agent, "scan_url", return_value={"mode": "url"}) as mock_url:
        res = agent.run("http://localhost:3000", mode="url")
        assert res["mode"] == "url"
        mock_url.assert_called_once_with("http://localhost:3000")

    with patch.object(agent, "scan_folder", return_value={"mode": "folder"}) as mock_folder:
        res = agent.run("./sentrax", mode="folder")
        assert res["mode"] == "folder"
        mock_folder.assert_called_once_with("./sentrax")

    with pytest.raises(ValueError):
        agent.run("target", mode="invalid_mode")
