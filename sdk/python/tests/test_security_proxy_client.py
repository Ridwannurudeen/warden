import pytest

from warden_guard import AsyncWardenClient
from warden_guard.proxy import WardenReverseProxy


def test_reverse_proxy_requires_an_explicit_enforcement_client():
    with pytest.raises(ValueError, match="explicit enforcement client"):
        WardenReverseProxy("http://upstream.test")


def test_reverse_proxy_rejects_fail_closed_free_demo_client():
    client = AsyncWardenClient(fail_open=False)

    with pytest.raises(ValueError, match="free hosted demo"):
        WardenReverseProxy("http://upstream.test", client=client)


def test_reverse_proxy_accepts_explicit_protected_client():
    client = AsyncWardenClient(paid=True, fail_open=False)

    proxy = WardenReverseProxy("http://upstream.test", client=client)

    assert proxy.client is client
