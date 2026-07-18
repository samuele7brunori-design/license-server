import importlib
import sys

from license_server.license_v2 import pepper_fingerprint


def test_health_identifies_service_and_pepper(tmp_path, monkeypatch):
    pepper = "health-contract-pepper-0123456789abcdef"
    monkeypatch.setenv("LICENSE_DB_PATH", str(tmp_path / "licenses.db"))
    monkeypatch.setenv("LICENSE_UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("LICENSE_KEY_PEPPER", pepper)
    sys.modules.pop("license_server.server", None)
    server = importlib.import_module("license_server.server")
    server.app.config.update(TESTING=True)

    with server.app.test_client() as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {
        "ok": True,
        "protocol": 2,
        "service": "tapesense-licensing",
        "pepper_fingerprint": pepper_fingerprint(pepper),
    }


def test_health_fails_closed_when_pepper_is_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("LICENSE_DB_PATH", str(tmp_path / "licenses.db"))
    monkeypatch.setenv("LICENSE_UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.delenv("LICENSE_KEY_PEPPER", raising=False)
    sys.modules.pop("license_server.server", None)
    server = importlib.import_module("license_server.server")
    server.app.config.update(TESTING=True)

    with server.app.test_client() as client:
        response = client.get("/health")

    assert response.status_code == 503
    assert response.get_json() == {"ok": False}
