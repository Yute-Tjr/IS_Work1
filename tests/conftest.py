import pytest

from app import create_app

TEST_SECRET = "test-secret-key-that-is-long-enough-for-hs256-0123456789"
PASSWORD = "Str0ng-Passw0rd!"


@pytest.fixture
def app():
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "JWT_SECRET_KEY": TEST_SECRET,
            "BCRYPT_ROUNDS": 4,  # fast hashing for tests only
            "RATELIMIT_ENABLED": False,
        }
    )
    yield app


@pytest.fixture
def client(app):
    return app.test_client()


def register(client, username, password=PASSWORD):
    return client.post("/auth/register", json={"username": username, "password": password})


def login(client, username, password=PASSWORD):
    return client.post("/auth/login", json={"username": username, "password": password})


def auth_headers_for(client, username):
    register(client, username)
    token = login(client, username).get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def alice(client):
    return auth_headers_for(client, "alice")


@pytest.fixture
def bob(client):
    return auth_headers_for(client, "bob")
