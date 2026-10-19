import jwt

from app import create_app
from app.extensions import db
from app.models import User

from .conftest import PASSWORD, TEST_SECRET, login, register


def test_register_creates_user(client):
    response = register(client, "alice")
    assert response.status_code == 201
    assert response.get_json() == {"id": 1, "username": "alice"}


def test_password_is_stored_as_bcrypt_hash(app, client):
    register(client, "alice")
    with app.app_context():
        user = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
        assert user.password_hash != PASSWORD
        assert user.password_hash.startswith("$2b$")


def test_register_duplicate_username(client):
    register(client, "alice")
    assert register(client, "alice").status_code == 409


def test_register_rejects_invalid_input(client):
    assert register(client, "a").status_code == 400  # username too short
    assert register(client, "<script>").status_code == 400  # illegal characters
    assert register(client, "alice", "short").status_code == 400  # password too short
    assert register(client, "alice", "ä" * 40).status_code == 400  # > 72 bytes for bcrypt
    assert client.post("/auth/register", data="not json").status_code == 400
    assert client.post("/auth/register", json={"username": 1, "password": []}).status_code == 400


def test_login_returns_valid_jwt(client):
    register(client, "alice")
    response = login(client, "alice")
    assert response.status_code == 200
    body = response.get_json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 30 * 60

    payload = jwt.decode(body["access_token"], TEST_SECRET, algorithms=["HS256"])
    assert payload["username"] == "alice"
    assert payload["exp"] > payload["iat"]


def test_login_wrong_password_and_unknown_user_look_the_same(client):
    register(client, "alice")
    wrong_password = login(client, "alice", "Wrong-Passw0rd!")
    unknown_user = login(client, "mallory")
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.get_json() == unknown_user.get_json()


def test_login_sql_injection_does_not_bypass_auth(client):
    register(client, "alice")
    for payload in ["alice' --", "' OR '1'='1", "' OR 1=1 --"]:
        assert login(client, payload, "anything").status_code == 401
        assert login(client, "alice", payload).status_code == 401


def test_login_is_rate_limited():
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "JWT_SECRET_KEY": TEST_SECRET,
            "BCRYPT_ROUNDS": 4,
            "LOGIN_RATE_LIMIT": "3 per minute",
        }
    )
    client = app.test_client()
    statuses = [login(client, "alice", "guess").status_code for _ in range(4)]
    assert statuses == [401, 401, 401, 429]
