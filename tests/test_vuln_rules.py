"""Tests for vuln_rules/* confirm() logic (Phase 4).

Every vuln type gets both a positive (confirmed) and negative (ruled-out)
case — a rule that always says "confirmed" is worse than useless, per
Docs/implementation-plan.md Phase 4.
"""

from unittest.mock import MagicMock

from sentrax.vuln_rules import broken_auth, idor, sqli, xss


# --- SQLi ---


def test_sqli_dast_confirmed_on_auth_bypass():
    session = MagicMock()
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"success": True, "token": "eyJ..."}
    session.post.return_value = resp

    confirmed, evidence = sqli.confirm_dast(session, "http://localhost:4000", "/api/login")

    assert confirmed is True
    assert evidence["request_sent"]
    assert evidence["why_confirmed"]


def test_sqli_dast_not_confirmed_on_normal_failure():
    session = MagicMock()
    resp = MagicMock(status_code=401)
    resp.text = '{"error": "invalid credentials"}'
    resp.json.return_value = {"error": "invalid credentials"}
    session.post.return_value = resp

    confirmed, _evidence = sqli.confirm_dast(session, "http://localhost:4000", "/api/login")

    assert confirmed is False


def test_sqli_sast_confirmed_on_string_concat():
    snippet = "\"SELECT * FROM users WHERE email='\" + email + \"'\""
    confirmed, evidence = sqli.confirm_sast(snippet, "routes/login.js", 42)
    assert confirmed is True
    assert evidence["response_snippet"] == snippet


def test_sqli_sast_not_confirmed_on_parameterized_query():
    snippet = 'db.query("SELECT * FROM users WHERE email = ?", [email])'
    confirmed, _evidence = sqli.confirm_sast(snippet, "routes/login.js", 42)
    assert confirmed is False


def test_sqli_sast_confirmed_on_js_template_literal_concat():
    # Real VulnMart bug shape (server.js:197) — backtick template literal
    # interpolating raw user input directly into a SQL keyword clause.
    snippet = "const query = `SELECT * FROM users WHERE email='${email}' AND password='${password}'`;"
    confirmed, evidence = sqli.confirm_sast(snippet, "server.js", 197)
    assert confirmed is True
    assert evidence["response_snippet"] == snippet


def test_sqli_sast_not_confirmed_on_parameterized_template_literal():
    snippet = "const query = `SELECT * FROM orders WHERE id = ?`;"
    confirmed, _evidence = sqli.confirm_sast(snippet, "server.js", 390)
    assert confirmed is False


# --- XSS ---


def test_xss_dast_confirmed_on_unescaped_reflection():
    posted = {}

    def mock_post(url, json=None, **kwargs):
        posted["comment"] = json["comment"]
        return MagicMock(status_code=201)

    def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.text = f"<div class='review'>{posted['comment']}</div>"
        return resp

    session = MagicMock()
    session.post.side_effect = mock_post
    session.get.side_effect = mock_get

    confirmed, evidence = xss.confirm_dast(session, "http://localhost:4000", "/api/reviews")

    assert confirmed is True
    assert "<script>" in evidence["response_snippet"]


def test_xss_dast_not_confirmed_when_escaped():
    import html as html_mod

    posted = {}

    def mock_post(url, json=None, **kwargs):
        posted["comment"] = json["comment"]
        return MagicMock(status_code=201)

    def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.text = f"<div class='review'>{html_mod.escape(posted['comment'])}</div>"
        return resp

    session = MagicMock()
    session.post.side_effect = mock_post
    session.get.side_effect = mock_get

    confirmed, _evidence = xss.confirm_dast(session, "http://localhost:4000", "/api/reviews")

    assert confirmed is False


def test_xss_dast_not_confirmed_when_stripped():
    session = MagicMock()
    session.post.return_value = MagicMock(status_code=201)
    session.get.return_value = MagicMock(text="<div class='review'>[filtered]</div>")

    confirmed, _evidence = xss.confirm_dast(session, "http://localhost:4000", "/api/reviews")

    assert confirmed is False


def test_xss_sast_confirmed_on_innerhtml_sink():
    snippet = "reviewContainer.innerHTML = userReview"
    confirmed, _evidence = xss.confirm_sast(snippet, "views/reviews.js", 18)
    assert confirmed is True


def test_xss_sast_not_confirmed_when_sanitized():
    snippet = "reviewContainer.innerHTML = DOMPurify.sanitize(userReview)"
    confirmed, _evidence = xss.confirm_sast(snippet, "views/reviews.js", 18)
    assert confirmed is False


def test_xss_sast_confirmed_on_template_literal_interpolation_into_markup():
    # Real VulnMart bug shape (server.js:251) — template literal interpolating
    # a review field straight into HTML markup with no escaping.
    snippet = '<div class="review-comment">${r.comment}</div>'
    confirmed, evidence = xss.confirm_sast(snippet, "server.js", 251)
    assert confirmed is True
    assert evidence["response_snippet"] == snippet


def test_xss_sast_not_confirmed_when_template_interpolation_sanitized():
    snippet = '<div class="review-comment">${DOMPurify.sanitize(r.comment)}</div>'
    confirmed, _evidence = xss.confirm_sast(snippet, "server.js", 251)
    assert confirmed is False


# --- IDOR ---


def _mock_idor_session(login_json, order_status, order_json):
    session = MagicMock()

    def mock_post(url, json=None, **kwargs):
        resp = MagicMock(status_code=200)
        resp.json.return_value = login_json
        return resp

    def mock_get(url, **kwargs):
        resp = MagicMock(status_code=order_status)
        resp.text = str(order_json)
        resp.json.return_value = order_json
        return resp

    session.post.side_effect = mock_post
    session.get.side_effect = mock_get
    return session


def test_idor_dast_confirmed_on_cross_user_access():
    session = _mock_idor_session(
        login_json={"token": "abc", "user": {"email": "alice@vulnmart.test"}},
        order_status=200,
        order_json={"order_id": 2, "owner": "bob@vulnmart.test"},
    )

    confirmed, evidence = idor.confirm_dast(session, "http://localhost:4000", "/api/order/2")

    assert confirmed is True
    assert "bob@vulnmart.test" in evidence["why_confirmed"]


def test_idor_dast_not_confirmed_on_access_denied():
    session = _mock_idor_session(
        login_json={"token": "abc", "user": {"email": "alice@vulnmart.test"}},
        order_status=403,
        order_json={"error": "forbidden"},
    )

    confirmed, _evidence = idor.confirm_dast(session, "http://localhost:4000", "/api/order/2")

    assert confirmed is False


def test_idor_dast_not_confirmed_when_own_data_returned():
    session = _mock_idor_session(
        login_json={"token": "abc", "user": {"email": "alice@vulnmart.test"}},
        order_status=200,
        order_json={"order_id": 1, "owner": "alice@vulnmart.test"},
    )

    confirmed, _evidence = idor.confirm_dast(session, "http://localhost:4000", "/api/order/2")

    assert confirmed is False


def test_idor_sast_confirmed_on_direct_lookup():
    snippet = "const order = await Order.findById(req.params.id)"
    confirmed, _evidence = idor.confirm_sast(snippet, "routes/orders.js", 25)
    assert confirmed is True


def test_idor_sast_not_confirmed_with_ownership_check():
    snippet = "if (order.owner_id === req.user.id) { const order = await Order.findById(req.params.id) }"
    confirmed, _evidence = idor.confirm_sast(snippet, "routes/orders.js", 25)
    assert confirmed is False


def test_idor_sast_confirmed_on_raw_prepared_statement_lookup():
    # Real VulnMart bug shape (server.js:462) — parameterized against SQLi,
    # but still a direct-by-id lookup with no ownership check on this line.
    snippet = "const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);"
    confirmed, evidence = idor.confirm_sast(snippet, "server.js", 462)
    assert confirmed is True
    assert evidence["response_snippet"] == snippet


def test_idor_sast_not_confirmed_on_prepared_statement_with_no_id_argument():
    snippet = "const count = db.prepare('SELECT COUNT(*) as count FROM orders').get();"
    confirmed, _evidence = idor.confirm_sast(snippet, "server.js", 500)
    assert confirmed is False


# --- Broken Auth ---


def test_broken_auth_dast_confirmed_no_rate_limiting():
    session = MagicMock()
    session.post.return_value = MagicMock(status_code=401, text='{"error":"invalid"}')

    confirmed, evidence = broken_auth.confirm_dast(session, "http://localhost:4000", "/api/login")

    assert confirmed is True
    assert session.post.call_count == broken_auth.ATTEMPT_COUNT
    assert str(broken_auth.ATTEMPT_COUNT) in evidence["why_confirmed"]


def test_broken_auth_dast_not_confirmed_when_throttled():
    responses = [MagicMock(status_code=401, text="") for _ in range(5)]
    responses += [MagicMock(status_code=429, text="Too many requests") for _ in range(broken_auth.ATTEMPT_COUNT - 5)]

    session = MagicMock()
    session.post.side_effect = responses

    confirmed, _evidence = broken_auth.confirm_dast(session, "http://localhost:4000", "/api/login")

    assert confirmed is False


def test_broken_auth_sast_never_confirmed():
    confirmed, evidence = broken_auth.confirm_sast("some line of code", "routes/auth.js", 5)
    assert confirmed is False
    assert "static" in evidence["why_confirmed"].lower()
