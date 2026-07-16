"""Security regression for deeply nested HTTP JSON bodies."""

from fastapi.testclient import TestClient

from warden.api import app


def test_paid_scan_rejects_excessive_json_depth_without_recursion_failure():
    depth = 1_100
    body = (
        '{"payload":"ok","context":{"expected_addresses":'
        + "[" * depth
        + '"x"'
        + "]" * depth
        + "}}"
    )

    with TestClient(app) as client:
        response = client.post(
            "/scan",
            content=body,
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "JSON nesting is too deep"}


def test_json_depth_guard_ignores_brackets_inside_payload_strings():
    with TestClient(app) as client:
        response = client.post("/scan", json={"payload": "[" * 100 + "]" * 100})

    assert response.status_code == 200
