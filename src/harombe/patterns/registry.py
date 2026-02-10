"""Self-registering pattern registry.

Usage::

    from harombe.patterns.registry import register_pattern, PatternRegistry

    @register_pattern("smart_escalation")
    class SmartEscalation(PatternBase):
        ...

    cls = PatternRegistry.get("smart_escalation")
"""

from typing import Any, ClassVar


class PatternRegistry:
    """Global lookup of registered collaboration patterns."""

    _patterns: ClassVar[dict[str, type]] = {}

    @classmethod
    def register(cls, name: str, pattern_cls: type) -> None:
        cls._patterns[name] = pattern_cls

    @classmethod
    def get(cls, name: str) -> type:
        if name not in cls._patterns:
            raise KeyError(f"Unknown pattern: {name!r}. Available: {cls.available()}")
        return cls._patterns[name]

    @classmethod
    def available(cls) -> list[str]:
        return sorted(cls._patterns.keys())


def register_pattern(name: str) -> Any:
    """Class decorator that registers a pattern under *name*."""

    def decorator(cls: type) -> type:
        PatternRegistry.register(name, cls)
        return cls

    return decorator
