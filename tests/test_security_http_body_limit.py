"""Security regressions for the HTTP request-body boundary."""

from fastapi.testclient import TestClient

from warden.api import MAX_REQUEST_BODY_BYTES, app


def test_chunked_body_is_rejected_before_json_validation():
    body = b'{"payload":"' + b"a" * (MAX_REQUEST_BODY_BYTES + 1) + b'"}'
    chunks = (
        body[offset : offset + 65_536]
        for offset in range(0, len(body), 65_536)
    )

    with TestClient(app) as client:
        response = client.post(
            "/scan",
            content=chunks,
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}
