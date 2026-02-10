"""Sensitivity classifier for privacy routing.

Classifies queries by sensitivity level using:
- SecretScanner (from security/secrets.py) for credential/token detection
- PII regex patterns (SSN, phone, email, IP, credit card, DOB, address)
- Keyword detection for restricted/confidential content
"""

import re
from typing import ClassVar

from harombe.llm.client import Message
from harombe.security.secrets import SecretScanner

from .models import PIIEntity, SensitivityLevel, SensitivityResult


class SensitivityClassifier:
    """Classifies text sensitivity for privacy-aware routing."""

    PII_PATTERNS: ClassVar[dict[str, re.Pattern[str]]] = {
        "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "phone": re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "ip_address": re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        "date_of_birth": re.compile(
            r"\b(?:DOB|date of birth|born on|birthday)[:\s]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
            re.IGNORECASE,
        ),
        "address": re.compile(
            r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s?){1,4}(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Rd|Road|Ln|Lane|Ct|Court|Way|Pl|Place)\b",
        ),
    }

    RESTRICTED_KEYWORDS: ClassVar[list[str]] = [
        "confidential",
        "restricted",
        "hipaa",
        "internal only",
        "do not share",
        "top secret",
        "classified",
        "proprietary",
        "attorney-client",
        "trade secret",
        "nda",
        "under embargo",
    ]

    def __init__(
        self,
        custom_patterns: dict[str, str] | None = None,
        custom_restricted_keywords: list[str] | None = None,
        secret_scanner: SecretScanner | None = None,
    ):
        """Initialize the sensitivity classifier.

        Args:
            custom_patterns: Additional regex patterns {name: pattern_str}
            custom_restricted_keywords: Additional restricted keywords
            secret_scanner: SecretScanner instance (creates default if None)
        """
        self.scanner = secret_scanner or SecretScanner(min_confidence=0.7)

        self._pii_patterns = dict(self.PII_PATTERNS)
        if custom_patterns:
            for name, pattern_str in custom_patterns.items():
                self._pii_patterns[name] = re.compile(pattern_str)

        self._restricted_keywords = list(self.RESTRICTED_KEYWORDS)
        if custom_restricted_keywords:
            self._restricted_keywords.extend(kw.lower() for kw in custom_restricted_keywords)

    def classify(
        self,
        query: str,
        messages: list[Message] | None = None,
    ) -> SensitivityResult:
        """Classify the sensitivity of a query and conversation context.

        Args:
            query: The latest user query
            messages: Full conversation history (optional)

        Returns:
            SensitivityResult with level, reasons, and detected entities
        """
        reasons: list[str] = []
        entities: list[PIIEntity] = []
        pii_locations: list[tuple[int, int]] = []

        # Combine query + recent messages for scanning
        text_to_scan = query
        if messages:
            recent_content = [m.content for m in messages[-5:] if m.role == "user" and m.content]
            text_to_scan = "\n".join([*recent_content, query])

        # 1. Check restricted keywords (highest priority)
        keyword_match = self._check_keywords(text_to_scan)
        if keyword_match:
            reasons.append(f"Restricted keyword detected: '{keyword_match}'")
            return SensitivityResult(
                level=SensitivityLevel.RESTRICTED,
                reasons=reasons,
                detected_entities=entities,
                confidence=0.95,
                pii_locations=pii_locations,
            )

        # 2. Scan for credentials/secrets
        secret_matches = self.scanner.scan(text_to_scan)
        for match in secret_matches:
            entities.append(
                PIIEntity(
                    type=f"credential:{match.type.value}",
                    value=match.value,
                    start=match.start,
                    end=match.end,
                    confidence=match.confidence,
                )
            )
            pii_locations.append((match.start, match.end))
            reasons.append(f"Credential detected: {match.type.value}")

        # 3. Scan for PII patterns
        for pii_type, pattern in self._pii_patterns.items():
            for pii_match in pattern.finditer(text_to_scan):
                entities.append(
                    PIIEntity(
                        type=pii_type,
                        value=pii_match.group(0),
                        start=pii_match.start(),
                        end=pii_match.end(),
                        confidence=0.9,
                    )
                )
                pii_locations.append((pii_match.start(), pii_match.end()))
                reasons.append(f"PII detected: {pii_type}")

        # Determine level based on findings
        if not entities:
            return SensitivityResult(
                level=SensitivityLevel.PUBLIC,
                reasons=["No sensitive data detected"],
                detected_entities=[],
                confidence=0.85,
                pii_locations=[],
            )

        has_credentials = any(e.type.startswith("credential:") for e in entities)
        has_pii = any(not e.type.startswith("credential:") for e in entities)

        if has_credentials:
            level = SensitivityLevel.CONFIDENTIAL
            confidence = max(e.confidence for e in entities)
        elif has_pii:
            level = SensitivityLevel.INTERNAL
            confidence = max(e.confidence for e in entities)
        else:
            level = SensitivityLevel.PUBLIC
            confidence = 0.85

        return SensitivityResult(
            level=level,
            reasons=reasons,
            detected_entities=entities,
            confidence=confidence,
            pii_locations=pii_locations,
        )

    def _check_keywords(self, text: str) -> str | None:
        """Check for restricted keywords.

        Args:
            text: Text to check

        Returns:
            Matched keyword or None
        """
        text_lower = text.lower()
        for keyword in self._restricted_keywords:
            if keyword in text_lower:
                return keyword
        return None
