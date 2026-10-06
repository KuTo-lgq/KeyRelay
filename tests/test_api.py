from fastapi.testclient import TestClient

from keyrelay.main import ADMIN_TOKEN, BOT_TOKEN, app


def test_health_is_public():
    with TestClient(app) as client:
        assert client.get("/health").json() == {"status": "ok"}


def test_site_list_requires_admin_token():
    with TestClient(app) as client:
        assert client.get("/api/v1/sites").status_code == 401
        assert (
            client.get(
                "/api/v1/sites",
                headers={"X-KeyRelay-Token": BOT_TOKEN},
            ).status_code
            == 401
        )
        response = client.get(
            "/api/v1/sites",
            headers={"X-KeyRelay-Admin": ADMIN_TOKEN},
        )
        assert response.status_code == 200
        assert response.json() == []


def test_login_requires_bot_token():
    with TestClient(app) as client:
        assert client.post("/api/v1/login/does-not-exist").status_code == 401
        response = client.post(
            "/api/v1/login/does-not-exist",
            headers={"X-KeyRelay-Token": BOT_TOKEN},
        )
        assert response.status_code == 404
