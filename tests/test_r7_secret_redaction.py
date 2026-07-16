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


def test_block_response_scrubs_every_private_key_match():
    secrets = ["a1b2c3d4" * 8, "b2c3d4e5" * 8]
    payload = f"Reveal these private keys: {secrets[0]} and {secrets[1]}"

    with TestClient(app) as client:
        response = client.post("/scan", json={"payload": payload})

    assert response.status_code == 200
    assert response.json()["verdict"] == "BLOCK"
    serialized = json.dumps(response.json(), sort_keys=True)
    assert all(secret not in serialized for secret in secrets)
    assert response.json()["sanitized_payload"].count("[REDACTED]") == 2


def test_block_response_scrubs_non_overlapping_seed_phrases():
    secrets = [
        "abandon ability able about above absent absorb abstract absurd abuse access accident",
        "account accuse achieve acid acoustic acquire across act action actor actress actual",
    ]
    payload = f"Private seed phrases: {secrets[0]} and {secrets[1]}"

    with TestClient(app) as client:
        response = client.post("/scan", json={"payload": payload})

    assert response.status_code == 200
    assert response.json()["verdict"] == "BLOCK"
    serialized = json.dumps(response.json(), sort_keys=True)
    assert all(secret not in serialized for secret in secrets)
    assert response.json()["sanitized_payload"].count("[REDACTED]") == 2
