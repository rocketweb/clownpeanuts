import base64
import hashlib
import hmac
import time

import pytest

from clownpeanuts.config.schema import parse_config
from clownpeanuts.core.orchestrator import Orchestrator
from clownpeanuts.dashboard.api import create_app


def _encode_ws_token(token: str) -> str:
    return base64.urlsafe_b64encode(token.encode("utf-8")).decode("ascii").rstrip("=")


def _websocket_ticket(secret: str, *, expires_at: int) -> str:
    nonce = "unit-test-nonce"
    unsigned = f"cpws1.{expires_at}.{nonce}"
    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode("utf-8"), unsigned.encode("utf-8"), hashlib.sha256).digest()
    ).decode("ascii").rstrip("=")
    return f"{unsigned}.{signature}"


def test_dashboard_websocket_subprotocol_token_auth_accepts_stream() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    viewer_token = "viewer-token-0123456789abcdef"
    config = parse_config(
        {
            "services": [],
            "api": {
                "auth_enabled": True,
                "auth_viewer_tokens": [viewer_token],
                "allow_unauthenticated_health": False,
            },
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    encoded = _encode_ws_token(viewer_token)
    with client.websocket_connect(
        "/ws/theater/live?limit=5&events_per_session=10&interval_ms=100",
        subprotocols=["cp-events-v1", f"cp-auth.{encoded}"],
    ) as websocket:
        payload = websocket.receive_json()
        assert payload["stream"] == "theater_live"
        assert "payload" in payload


def test_dashboard_websocket_subprotocol_rejects_invalid_token() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")
    websockets = pytest.importorskip("starlette.websockets")

    viewer_token = "viewer-token-0123456789abcdef"
    config = parse_config(
        {
            "services": [],
            "api": {
                "auth_enabled": True,
                "auth_viewer_tokens": [viewer_token],
                "allow_unauthenticated_health": False,
            },
        }
    )
    orchestrator = Orchestrator(config)
    app = create_app(orchestrator)
    client = testclient.TestClient(app)

    with client.websocket_connect(
        "/ws/theater/live?limit=5&events_per_session=10&interval_ms=100",
        subprotocols=["cp-events-v1", "cp-auth.invalidtoken"],
    ) as websocket:
        with pytest.raises(websockets.WebSocketDisconnect) as exc:
            websocket.receive_json()
        assert exc.value.code == 4401


def test_dashboard_websocket_accepts_short_lived_signed_ticket() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")

    ticket_secret = "dashboard-session-secret-0123456789abcdef"
    config = parse_config(
        {
            "services": [],
            "api": {
                "auth_enabled": True,
                "auth_operator_tokens": ["operator-token-0123456789abcdef"],
                "auth_websocket_ticket_secret": ticket_secret,
                "allow_unauthenticated_health": False,
            },
        }
    )
    client = testclient.TestClient(create_app(Orchestrator(config)))
    ticket = _websocket_ticket(ticket_secret, expires_at=int(time.time()) + 30)

    with client.websocket_connect(
        "/ws/theater/live?limit=5&events_per_session=10&interval_ms=100",
        subprotocols=["cp-events-v1", f"cp-auth.{_encode_ws_token(ticket)}"],
    ) as websocket:
        assert websocket.receive_json()["stream"] == "theater_live"


def test_dashboard_websocket_rejects_expired_signed_ticket() -> None:
    _ = pytest.importorskip("fastapi")
    testclient = pytest.importorskip("fastapi.testclient")
    websockets = pytest.importorskip("starlette.websockets")

    ticket_secret = "dashboard-session-secret-0123456789abcdef"
    config = parse_config(
        {
            "services": [],
            "api": {
                "auth_enabled": True,
                "auth_operator_tokens": ["operator-token-0123456789abcdef"],
                "auth_websocket_ticket_secret": ticket_secret,
                "allow_unauthenticated_health": False,
            },
        }
    )
    client = testclient.TestClient(create_app(Orchestrator(config)))
    ticket = _websocket_ticket(ticket_secret, expires_at=int(time.time()) - 1)

    with client.websocket_connect(
        "/ws/theater/live?limit=5&events_per_session=10&interval_ms=100",
        subprotocols=["cp-events-v1", f"cp-auth.{_encode_ws_token(ticket)}"],
    ) as websocket:
        with pytest.raises(websockets.WebSocketDisconnect) as exc:
            websocket.receive_json()
        assert exc.value.code == 4401
