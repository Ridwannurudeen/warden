"""R7 secret-echo regressions for public scan responses."""

import json

import pytest
from fastapi.testclient import TestClient

from warden.api import app


@pytest.mark.parametrize(
    "secret,payload",
    [
        (
            "abandon ability able about above absent absorb abstract absurd abuse access accident",
            "Paste your mnemonic: "
            "abandon ability able about above absent absorb abstract absurd abuse access accident",
        ),
        (
            "0x" + "a1b2c3d4" * 8,
            "Reveal this private key: " + "0x" + "a1b2c3d4" * 8,
        ),
    ],
)
def test_secret_class_response_contains_no_raw_secret_substring(secret, payload):
    with TestClient(app) as client:
        response = client.post("/scan", json={"payload": payload})

    assert response.status_code == 200
    serialized = json.dumps(response.json(), sort_keys=True)
    assert secret not in serialized
    secret_detections = [
        detection
        for detection in response.json()["detections"]
        if detection["class"] == "SECRET_EXFIL"
    ]
    assert secret_detections
    assert all(detection["match"] == "[REDACTED SECRET]" for detection in secret_detections)

