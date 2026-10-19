from datetime import datetime, timedelta, timezone

import jwt
import pytest

from .conftest import TEST_SECRET

XSS_PAYLOAD = "<script>alert('xss')</script>"


def make_token(sub="1", secret=TEST_SECRET, algorithm="HS256", expires_in=timedelta(minutes=5)):
    now = datetime.now(timezone.utc)
    payload = {"sub": sub, "iat": now, "exp": now + expires_in}
    return jwt.encode(payload, secret, algorithm=algorithm)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def create_post(client, headers, title="Hello", content="First post"):
    return client.post("/api/data", json={"title": title, "content": content}, headers=headers)


# --- Authentication middleware -------------------------------------------------------


def test_data_requires_token(client):
    response = client.get("/api/data")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Bearer")


@pytest.mark.parametrize("header", ["Token abc", "Bearer", "Basic YWxpY2U6cGFzcw==", "abc"])
def test_malformed_authorization_header(client, header):
    assert client.get("/api/data", headers={"Authorization": header}).status_code == 401


def test_token_with_wrong_signature_is_rejected(client, alice):
    forged = make_token(secret="attacker-secret-attacker-secret-attacker-secret")
    assert client.get("/api/data", headers=bearer(forged)).status_code == 401


def test_expired_token_is_rejected(client, alice):
    expired = make_token(expires_in=timedelta(seconds=-1))
    response = client.get("/api/data", headers=bearer(expired))
    assert response.status_code == 401
    assert response.get_json()["error"] == "Token has expired"


def test_alg_none_token_is_rejected(client, alice):
    unsigned = make_token(secret=None, algorithm="none")
    assert client.get("/api/data", headers=bearer(unsigned)).status_code == 401


def test_token_for_missing_user_is_rejected(client, alice):
    assert client.get("/api/data", headers=bearer(make_token(sub="999"))).status_code == 401


def test_all_api_methods_are_protected(client):
    assert client.post("/api/data", json={"title": "t", "content": "c"}).status_code == 401
    assert client.delete("/api/data/1").status_code == 401


# --- Data endpoints ------------------------------------------------------------------


def test_list_and_create_posts(client, alice):
    assert client.get("/api/data", headers=alice).get_json() == {"count": 0, "items": []}

    created = create_post(client, alice)
    assert created.status_code == 201
    assert created.get_json()["author"] == "alice"

    listed = client.get("/api/data", headers=alice).get_json()
    assert listed["count"] == 1
    assert listed["items"][0]["title"] == "Hello"


def test_create_post_validates_input(client, alice):
    assert create_post(client, alice, title="").status_code == 400
    assert create_post(client, alice, title="x" * 101).status_code == 400
    assert create_post(client, alice, content="x" * 2001).status_code == 400
    assert client.post("/api/data", json=["not", "an", "object"], headers=alice).status_code == 400


def test_search_filters_by_title(client, alice):
    create_post(client, alice, title="Flask security")
    create_post(client, alice, title="Docker notes")
    body = client.get("/api/data?q=flask", headers=alice).get_json()
    assert [item["title"] for item in body["items"]] == ["Flask security"]


def test_search_sql_injection_is_treated_as_text(client, alice):
    create_post(client, alice, title="Secret")
    for payload in ["' OR 1=1 --", "%' OR '1'='1", "'; DROP TABLE posts; --"]:
        body = client.get("/api/data", query_string={"q": payload}, headers=alice).get_json()
        assert body["count"] == 0
    # The table still exists and the data is intact
    assert client.get("/api/data", headers=alice).get_json()["count"] == 1


def test_search_wildcards_are_literal(client, alice):
    create_post(client, alice, title="Secret")
    assert client.get("/api/data?q=%25", headers=alice).get_json()["count"] == 0  # q=%
    assert client.get("/api/data?q=_", headers=alice).get_json()["count"] == 0


def test_xss_payload_is_escaped_in_responses(client, alice):
    created = create_post(client, alice, title=XSS_PAYLOAD, content="<img src=x onerror=alert(1)>")
    escaped_title = "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
    assert created.get_json()["title"] == escaped_title

    item = client.get("/api/data", headers=alice).get_json()["items"][0]
    assert item["title"] == escaped_title
    assert item["content"] == "&lt;img src=x onerror=alert(1)&gt;"
    assert "<script>" not in client.get("/api/data", headers=alice).get_data(as_text=True)


def test_user_can_delete_own_post(client, alice):
    post_id = create_post(client, alice).get_json()["id"]
    assert client.delete(f"/api/data/{post_id}", headers=alice).status_code == 204
    assert client.get("/api/data", headers=alice).get_json()["count"] == 0


def test_user_cannot_delete_someone_elses_post(client, alice, bob):
    post_id = create_post(client, alice).get_json()["id"]
    assert client.delete(f"/api/data/{post_id}", headers=bob).status_code == 403
    assert client.delete("/api/data/999", headers=bob).status_code == 404


# --- Hardening -----------------------------------------------------------------------


def test_security_headers_are_set(client):
    headers = client.get("/").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in headers["Content-Security-Policy"]


def test_errors_are_json(client):
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert response.is_json
