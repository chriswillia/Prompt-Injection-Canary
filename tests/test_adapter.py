from prompt_injection_canary.adapter import (
    ADAPTER_REGISTRY,
    EchoAdapter,
    MockAdapter,
    build_adapter,
)


def test_mock_adapter_static_response():
    adapter = MockAdapter(response="nope")
    assert adapter.call("sys", "user") == "nope"


def test_mock_adapter_response_list_rotates():
    adapter = MockAdapter(responses=["a", "b"])
    assert adapter.call("s", "u") == "a"
    assert adapter.call("s", "u") == "b"
    assert adapter.call("s", "u") == "a"


def test_mock_adapter_responder_callable():
    adapter = MockAdapter(responder=lambda s, u: f"S={s[:3]};U={u[:3]}")
    assert adapter.call("system", "user") == "S=sys;U=use"


def test_mock_adapter_default_refusal():
    assert "can't" in MockAdapter().call("s", "u")


def test_echo_adapter():
    assert EchoAdapter().call("s", "hello") == "hello"


def test_build_adapter_registry_keys():
    assert "openai" in ADAPTER_REGISTRY
    assert "mock" in ADAPTER_REGISTRY
    assert "echo" in ADAPTER_REGISTRY


def test_build_adapter_filters_kwargs():
    # Passing openai-specific kwargs to the echo adapter must not raise.
    adapter = build_adapter("echo", model="ignored", api_key="ignored", base_url="ignored")
    assert isinstance(adapter, EchoAdapter)


def test_build_adapter_unknown_raises():
    import pytest

    with pytest.raises(ValueError):
        build_adapter("does-not-exist")
