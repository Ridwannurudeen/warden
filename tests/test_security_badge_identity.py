from warden import badge_store
from warden.badges import issue_badge


def _badge(blocked, total):
    return issue_badge(
        target_host="api.example.org",
        score=50.0,
        grade="D",
        blocked=blocked,
        total=total,
        issued_at="2026-07-16",
        secret="test-badge-secret",
    )


def test_distinct_same_day_same_score_badges_have_distinct_ids():
    first = _badge(1, 2)
    second = _badge(2, 4)

    assert first["audit_id"] != second["audit_id"]


def test_record_badge_is_idempotent(tmp_path, monkeypatch):
    store_path = tmp_path / "issued.jsonl"
    monkeypatch.setattr(badge_store, "_STORE_PATH", store_path)
    badge = _badge(1, 2)

    badge_store.record_badge(badge)
    badge_store.record_badge(badge)

    assert len(store_path.read_text(encoding="utf-8").splitlines()) == 1
    assert badge_store.get_badge(str(badge["audit_id"])) == badge
