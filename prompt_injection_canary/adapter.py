from __future__ import annotations

import inspect
import os
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional


class AgentAdapter(ABC):
    """Abstract agent adapter interface."""

    @abstractmethod
    def call(
        self,
        system_prompt: str,
        user_prompt: str,
        conversation: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        raise NotImplementedError


class OpenAIAdapter(AgentAdapter):
    """Adapter for the official OpenAI Python SDK (>=1.0)."""

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "The OpenAI adapter requires the 'openai' package (>=1.0)."
            ) from exc

        self._client = OpenAI(
            api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            base_url=base_url,
        )
        self.model = model
        self.temperature = temperature
        self.kwargs = kwargs

    def call(
        self,
        system_prompt: str,
        user_prompt: str,
        conversation: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        messages: List[Dict[str, str]] = [{"role": "system", "content": system_prompt}]
        if conversation:
            messages.extend(conversation)
        messages.append({"role": "user", "content": user_prompt})

        response = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            **self.kwargs,
        )
        content = response.choices[0].message.content or ""
        return content.strip()


class MockAdapter(AgentAdapter):
    """Deterministic adapter for offline tests."""

    def __init__(
        self,
        response: Optional[str] = None,
        responses: Optional[List[str]] = None,
        responder: Optional[Callable[[str, str], str]] = None,
    ) -> None:
        self._response = response
        self._responses = list(responses) if responses else None
        self._responder = responder
        self._index = 0

    def call(
        self,
        system_prompt: str,
        user_prompt: str,
        conversation: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        if self._responder is not None:
            return self._responder(system_prompt, user_prompt)
        if self._responses is not None:
            value = self._responses[self._index % len(self._responses)]
            self._index += 1
            return value
        if self._response is not None:
            return self._response
        return "I can't help with that request."


class EchoAdapter(AgentAdapter):
    """Returns the user prompt. Useful for smoke-testing the pipeline."""

    def call(
        self,
        system_prompt: str,
        user_prompt: str,
        conversation: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        return user_prompt


ADAPTER_REGISTRY: Dict[str, type[AgentAdapter]] = {
    "openai": OpenAIAdapter,
    "mock": MockAdapter,
    "echo": EchoAdapter,
}


def build_adapter(name: str, **kwargs: Any) -> AgentAdapter:
    """Instantiate a registered adapter by name, filtering irrelevant kwargs."""
    key = name.lower()
    if key not in ADAPTER_REGISTRY:
        raise ValueError(
            f"Unsupported adapter: {name!r}. Available: {sorted(ADAPTER_REGISTRY)}"
        )
    cls = ADAPTER_REGISTRY[key]
    # Only inspect parameters when the class defines its own __init__; otherwise
    # it inherits object.__init__ which takes no keyword arguments.
    if "__init__" in cls.__dict__:
        params = inspect.signature(cls.__init__).parameters
        accepts_var_kw = any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
        )
        filtered = (
            kwargs if accepts_var_kw else {k: v for k, v in kwargs.items() if k in params}
        )
    else:
        filtered = {}
    return cls(**filtered)
