"""Privacy Handshake pattern.

Replaces detected PII with *realistic fake data* (pseudonyms) rather than
obvious placeholders like ``[EMAIL_1]``.  The cloud model never sees the
originals and never knows the data was altered.  After the cloud responds,
the pseudonyms are swapped back for the real values.

Reuses the existing ``SensitivityClassifier`` for PII detection.
"""

import hashlib
import random
import string
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from harombe.llm.client import CompletionResponse, Message
from harombe.privacy.classifier import SensitivityClassifier
from harombe.privacy.models import PIIEntity, SensitivityLevel

from .base import PatternBase
from .registry import register_pattern


class PseudonymGenerator:
    """Generates deterministic, realistic fake values for PII types.

    The same input always produces the same pseudonym (within a session)
    so that multi-turn conversations remain consistent.
    """

    _FAKE_NAMES: ClassVar[list[str]] = [
        "Alice Johnson",
        "Bob Williams",
        "Carol Davis",
        "David Brown",
        "Eve Martinez",
        "Frank Wilson",
        "Grace Taylor",
        "Henry Anderson",
    ]

    _FAKE_DOMAINS: ClassVar[list[str]] = [
        "example.com",
        "test.org",
        "sample.net",
        "demo.io",
    ]

    def __init__(self, seed: int = 42) -> None:
        self._rng = random.Random(seed)
        self._cache: dict[str, str] = {}

    def generate(self, entity: PIIEntity) -> str:
        """Return a realistic pseudonym for *entity*.

        Deterministic per ``(type, value)`` pair.
        """
        cache_key = f"{entity.type}:{entity.value}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Seed sub-RNG from the entity value for determinism
        h = int(hashlib.sha256(cache_key.encode()).hexdigest(), 16)
        sub_rng = random.Random(h)

        base_type = entity.type.split(":")[-1]
        fake = self._generate_for_type(base_type, sub_rng)
        self._cache[cache_key] = fake
        return fake

    def _generate_for_type(self, pii_type: str, rng: random.Random) -> str:
        if pii_type == "email":
            name = rng.choice(self._FAKE_NAMES).split()[0].lower()
            domain = rng.choice(self._FAKE_DOMAINS)
            return f"{name}.{rng.randint(10, 99)}@{domain}"

        if pii_type == "phone":
            area = rng.randint(200, 999)
            return f"({area}) 555-{rng.randint(1000, 9999)}"

        if pii_type == "ssn":
            return f"{rng.randint(100, 999)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"

        if pii_type == "credit_card":
            groups = [str(rng.randint(1000, 9999)) for _ in range(4)]
            return "-".join(groups)

        if pii_type == "ip_address":
            return f"192.0.2.{rng.randint(1, 254)}"

        if pii_type == "address":
            return f"{rng.randint(100, 9999)} Elm Street"

        if pii_type in ("date_of_birth", "dob"):
            return f"DOB: {rng.randint(1, 12)}/{rng.randint(1, 28)}/{rng.randint(1950, 2000)}"

        # Credentials / unknown — generic token
        return "tok_" + "".join(rng.choices(string.ascii_lowercase + string.digits, k=16))

    def reset(self) -> None:
        self._cache.clear()


@register_pattern("privacy_handshake")
class PrivacyHandshake(PatternBase):
    """Pseudonymize PII before cloud, de-pseudonymize after."""

    def __init__(
        self,
        local_client: Any,
        cloud_client: Any,
        *,
        classifier: SensitivityClassifier | None = None,
        pseudonym_seed: int = 42,
    ) -> None:
        super().__init__(name="privacy_handshake")
        self.local_client = local_client
        self.cloud_client = cloud_client
        self.classifier = classifier or SensitivityClassifier()
        self.pseudonym_gen = PseudonymGenerator(seed=pseudonym_seed)

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CompletionResponse:
        start = self._start_timer()

        # Extract latest query for classification
        query = self._extract_latest_query(messages)
        result = self.classifier.classify(query, messages)

        # If restricted → local only
        if result.level == SensitivityLevel.RESTRICTED:
            local_resp: CompletionResponse = await self.local_client.complete(
                messages, tools, temperature, max_tokens
            )
            self.metrics.record_request(target="local", latency_ms=self._elapsed_ms(start))
            return local_resp

        # If no PII detected → send to cloud as-is
        if not result.detected_entities:
            cloud_resp: CompletionResponse = await self.cloud_client.complete(
                messages, tools, temperature, max_tokens
            )
            self.metrics.record_request(target="cloud", latency_ms=self._elapsed_ms(start))
            return cloud_resp

        # Pseudonymize and send to cloud
        replacement_map: dict[str, str] = {}  # fake → original
        for entity in result.detected_entities:
            fake = self.pseudonym_gen.generate(entity)
            replacement_map[fake] = entity.value

        # Replace originals with fakes in all messages
        pseudonymized = self._replace_in_messages(
            messages, result.detected_entities, replacement_map
        )

        cloud_response = await self.cloud_client.complete(
            pseudonymized, tools, temperature, max_tokens
        )

        # Restore originals in cloud response
        content = cloud_response.content
        for fake, original in sorted(
            replacement_map.items(), key=lambda kv: len(kv[0]), reverse=True
        ):
            content = content.replace(fake, original)

        self.metrics.record_request(target="cloud", latency_ms=self._elapsed_ms(start))
        return CompletionResponse(
            content=content,
            tool_calls=cloud_response.tool_calls,
            finish_reason=cloud_response.finish_reason,
        )

    async def stream_complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
    ) -> AsyncIterator[str]:
        # Can't de-pseudonymize mid-stream, fall back to local
        async for chunk in self.local_client.stream_complete(messages, tools, temperature):
            yield chunk

    # -- helpers --

    @staticmethod
    def _extract_latest_query(messages: list[Message]) -> str:
        for msg in reversed(messages):
            if msg.role == "user" and msg.content:
                return msg.content
        return ""

    @staticmethod
    def _replace_in_messages(
        messages: list[Message],
        entities: list[PIIEntity],
        replacement_map: dict[str, str],
    ) -> list[Message]:
        # Build original → fake map
        orig_to_fake = {v: k for k, v in replacement_map.items()}

        # Sort by length descending to avoid partial replacements
        sorted_originals = sorted(orig_to_fake.keys(), key=len, reverse=True)

        result = []
        for msg in messages:
            content = msg.content
            for original in sorted_originals:
                content = content.replace(original, orig_to_fake[original])
            result.append(
                Message(
                    role=msg.role,
                    content=content,
                    tool_calls=msg.tool_calls,
                    tool_call_id=msg.tool_call_id,
                    name=msg.name,
                )
            )
        return result
