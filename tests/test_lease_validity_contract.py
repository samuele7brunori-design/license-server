"""Signed leases stay within their subscription and refresh boundaries."""
from datetime import datetime, timedelta, timezone

import pytest

from license_protocol import (
    LicenseProtocolError, decode_and_verify_lease, generate_device_keypair,
    public_key_sha256,
)
from license_server import license_v2


@pytest.fixture
def issue(monkeypatch):
    private, public = generate_device_keypair()
    _, device_public = generate_device_keypair()
    now = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
    monkeypatch.setenv("LICENSE_SIGNING_PRIVATE_KEY_B64", private)
    monkeypatch.setenv("LICENSE_SIGNING_KEY_ID", "boundary-test")
    monkeypatch.setenv("LICENSE_REFRESH_HOURS", "24")
    monkeypatch.setenv("LICENSE_LEASE_DAYS", "7")
    monkeypatch.setattr(license_v2, "_now", lambda: now)

    def create(expires_at=None):
        token = license_v2._issue_lease(
            None,
            {"id": "lic_test", "plan": "yearly", "features_json": '["journal"]',
             "expires_at": expires_at},
            {"id": "dev_test", "public_key_sha256": public_key_sha256(device_public)},
        )
        payload = decode_and_verify_lease(token, {"boundary-test": public}, now=now)
        return token, payload, public

    return now, create


def test_lifetime_default_retains_seven_day_offline_window(issue):
    now, create = issue
    _, payload, _ = create()

    assert datetime.fromisoformat(payload["lease_expires_at"]) == now + timedelta(days=7)
    assert datetime.fromisoformat(payload["refresh_after"]) == now + timedelta(days=1)


@pytest.mark.parametrize("hours_left", [1, 3, 24, 96])
def test_signed_offline_window_never_outlives_subscription(issue, hours_left):
    now, create = issue
    subscription_end = now + timedelta(hours=hours_left)
    token, payload, public = create(subscription_end.isoformat())

    assert datetime.fromisoformat(payload["lease_expires_at"]) == subscription_end
    assert datetime.fromisoformat(payload["refresh_after"]) <= subscription_end
    with pytest.raises(LicenseProtocolError, match="scaduto"):
        decode_and_verify_lease(token, {"boundary-test": public}, now=subscription_end)


def test_configured_refresh_after_offline_window_is_clamped(issue, monkeypatch):
    now, create = issue
    monkeypatch.setenv("LICENSE_REFRESH_HOURS", "168")
    monkeypatch.setenv("LICENSE_LEASE_DAYS", "1")
    _, payload, _ = create()

    assert payload["refresh_after"] == payload["lease_expires_at"]
    assert datetime.fromisoformat(payload["lease_expires_at"]) == now + timedelta(days=1)


def test_timezone_aware_subscription_end_is_normalized_to_utc(issue):
    now, create = issue
    end = (now + timedelta(hours=6)).astimezone(timezone(timedelta(hours=2)))
    _, payload, _ = create(end.isoformat())

    assert datetime.fromisoformat(payload["lease_expires_at"]) == now + timedelta(hours=6)


def test_legacy_naive_subscription_end_is_interpreted_as_utc(issue):
    now, create = issue
    end = (now + timedelta(hours=6)).replace(tzinfo=None)
    _, payload, _ = create(end.isoformat())

    assert datetime.fromisoformat(payload["lease_expires_at"]) == now + timedelta(hours=6)
