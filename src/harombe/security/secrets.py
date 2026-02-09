"""Secret scanning and detection system.

Detects and redacts sensitive information before it reaches the LLM or logs.

Detection methods:
- Regex patterns for common secret formats
- Entropy-based detection for high-randomness strings
- Contextual analysis (key-value pairs)
- Known secret prefixes (sk-, ghp_, etc.)

Features:
- Fast scanning (<10ms for typical responses)
- Configurable sensitivity levels
- Alert system for credential leakage attempts
- Integration with audit logging
"""

import math
import re
from collections import Counter
from enum import Enum
from typing import ClassVar

from pydantic import BaseModel, Field


class SecretType(str, Enum):
    """Types of secrets that can be detected."""

    API_KEY = "api_key"
    AWS_KEY = "aws_key"
    AZURE_KEY = "azure_key"
    GCP_KEY = "gcp_key"
    GITHUB_TOKEN = "github_token"
    SLACK_TOKEN = "slack_token"
    STRIPE_KEY = "stripe_key"
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    JWT_TOKEN = "jwt_token"
    OAUTH_TOKEN = "oauth_token"
    DATABASE_URL = "database_url"
    GENERIC_SECRET = "generic_secret"


class SecretMatch(BaseModel):
    """A detected secret in text."""

    type: SecretType
    value: str
    start: int
    end: int
    confidence: float = Field(ge=0.0, le=1.0)
    context: str | None = None  # Surrounding text for context


class SecretScanner:
    """Scans text for secrets and credentials.

    Uses multiple detection methods:
    1. Regex patterns for known secret formats
    2. Entropy analysis for random-looking strings
    3. Contextual clues (variable names, key-value pairs)
    """

    # Known secret patterns with high confidence
    PATTERNS: ClassVar[dict[SecretType, list[re.Pattern]]] = {
        SecretType.AWS_KEY: [
            re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key ID
            re.compile(
                r"(?i)aws.{0,20}?(?:key|secret|token).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"
            ),
        ],
        SecretType.AZURE_KEY: [
            re.compile(r"(?i)azure.{0,20}?['\"]([a-z0-9]{32,})['\"]"),
        ],
        SecretType.GCP_KEY: [
            re.compile(r'"type": "service_account"'),  # GCP service account JSON
            re.compile(r"(?i)gcp.{0,20}?['\"]([A-Za-z0-9_-]{20,})['\"]"),
        ],
        SecretType.GITHUB_TOKEN: [
            re.compile(r"ghp_[a-zA-Z0-9]{36}"),  # GitHub Personal Access Token
            re.compile(r"gho_[a-zA-Z0-9]{36}"),  # GitHub OAuth token
            re.compile(r"ghu_[a-zA-Z0-9]{36}"),  # GitHub User-to-server token
            re.compile(r"ghs_[a-zA-Z0-9]{36}"),  # GitHub Server-to-server token
            re.compile(r"ghr_[a-zA-Z0-9]{36}"),  # GitHub Refresh token
        ],
        SecretType.SLACK_TOKEN: [
            re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,72}"),  # Slack tokens
        ],
        SecretType.STRIPE_KEY: [
            re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),  # Stripe secret key
            re.compile(r"rk_live_[0-9a-zA-Z]{24,}"),  # Stripe restricted key
        ],
        SecretType.PRIVATE_KEY: [
            re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        ],
        SecretType.JWT_TOKEN: [
            re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
        ],
        SecretType.DATABASE_URL: [
            re.compile(r"(?i)(postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s]+"),
        ],
        SecretType.PASSWORD: [
            re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?"),
        ],
        SecretType.API_KEY: [
            re.compile(
                r"(?i)(api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"
            ),
        ],
    }

    # Prefixes that indicate secrets
    SECRET_PREFIXES: ClassVar[list[str]] = [
        "sk-",  # OpenAI, Anthropic, generic secret keys
        "sk_",
        "pk_",  # Public key (less sensitive but still flag)
        "ghp_",  # GitHub
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "xoxb-",  # Slack
        "xoxa-",
        "xoxp-",
        "xoxr-",
        "xoxs-",
        "AKIA",  # AWS
        "ASIA",
    ]

    # Minimum entropy for high-confidence secret detection
    MIN_ENTROPY = 3.5  # bits per character

    def __init__(
        self,
        min_confidence: float = 0.7,
        min_length: int = 16,
        enable_entropy_detection: bool = True,
    ):
        """Initialize secret scanner.

        Args:
            min_confidence: Minimum confidence threshold (0.0-1.0)
            min_length: Minimum length for entropy-based detection
            enable_entropy_detection: Enable entropy analysis
        """
        self.min_confidence = min_confidence
        self.min_length = min_length
        self.enable_entropy_detection = enable_entropy_detection

    def scan(self, text: str) -> list[SecretMatch]:
        """Scan text for secrets.

        Args:
            text: Text to scan

        Returns:
            List of detected secrets
        """
        matches: list[SecretMatch] = []

        # 1. Pattern-based detection (high confidence)
        matches.extend(self._scan_patterns(text))

        # 2. Prefix-based detection (medium confidence)
        matches.extend(self._scan_prefixes(text))

        # 3. Entropy-based detection (lower confidence, optional)
        if self.enable_entropy_detection:
            matches.extend(self._scan_entropy(text))

        # Deduplicate overlapping matches (keep highest confidence)
        matches = self._deduplicate_matches(matches)

        # Filter by confidence threshold
        matches = [m for m in matches if m.confidence >= self.min_confidence]

        return matches

    def _scan_patterns(self, text: str) -> list[SecretMatch]:
        """Scan using regex patterns.

        Args:
            text: Text to scan

        Returns:
            List of pattern matches
        """
        matches: list[SecretMatch] = []

        for secret_type, patterns in self.PATTERNS.items():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    # Extract value (use first capture group if exists)
                    value = match.group(1) if match.groups() else match.group(0)

                    matches.append(
                        SecretMatch(
                            type=secret_type,
                            value=value,
                            start=match.start(),
                            end=match.end(),
                            confidence=0.95,  # High confidence for pattern matches
                            context=self._get_context(text, match.start(), match.end()),
                        )
                    )

        return matches

    def _scan_prefixes(self, text: str) -> list[SecretMatch]:
        """Scan for known secret prefixes.

        Args:
            text: Text to scan

        Returns:
            List of prefix matches
        """
        matches: list[SecretMatch] = []

        for prefix in self.SECRET_PREFIXES:
            # Find all occurrences of prefix
            start = 0
            while True:
                idx = text.find(prefix, start)
                if idx == -1:
                    break

                # Extract the full token (until whitespace or quote)
                end = idx + len(prefix)
                while end < len(text) and text[end] not in (
                    " ",
                    "\n",
                    "\t",
                    '"',
                    "'",
                    ",",
                    "}",
                    "]",
                ):
                    end += 1

                value = text[idx:end]

                # Only flag if long enough and has reasonable entropy
                if len(value) >= self.min_length:
                    entropy = self._calculate_entropy(value)
                    if entropy >= self.MIN_ENTROPY * 0.8:  # Slightly lower threshold
                        matches.append(
                            SecretMatch(
                                type=SecretType.GENERIC_SECRET,
                                value=value,
                                start=idx,
                                end=end,
                                confidence=0.85,  # Medium-high confidence
                                context=self._get_context(text, idx, end),
                            )
                        )

                start = end

        return matches

    def _scan_entropy(self, text: str) -> list[SecretMatch]:
        """Scan for high-entropy strings (potentially secrets).

        Args:
            text: Text to scan

        Returns:
            List of high-entropy matches
        """
        matches: list[SecretMatch] = []

        # Find all "words" (alphanumeric sequences)
        word_pattern = re.compile(r"[a-zA-Z0-9_\-+=/.]{16,}")

        for match in word_pattern.finditer(text):
            value = match.group(0)

            # Skip if too short
            if len(value) < self.min_length:
                continue

            # Calculate entropy
            entropy = self._calculate_entropy(value)

            # High entropy suggests randomness (potential secret)
            if entropy >= self.MIN_ENTROPY:
                # Check if it's in a suspicious context
                context = self._get_context(text, match.start(), match.end())
                confidence = self._calculate_confidence(value, context, entropy)

                if confidence >= self.min_confidence:
                    matches.append(
                        SecretMatch(
                            type=SecretType.GENERIC_SECRET,
                            value=value,
                            start=match.start(),
                            end=match.end(),
                            confidence=confidence,
                            context=context,
                        )
                    )

        return matches

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy (bits per character).

        Args:
            text: Text to analyze

        Returns:
            Entropy in bits per character
        """
        if not text:
            return 0.0

        # Count character frequencies
        counter = Counter(text)
        length = len(text)

        # Calculate Shannon entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _calculate_confidence(
        self,
        value: str,
        context: str | None,
        entropy: float,
    ) -> float:
        """Calculate confidence score for potential secret.

        Args:
            value: The potential secret value
            context: Surrounding text
            entropy: Entropy of the value

        Returns:
            Confidence score 0.0-1.0
        """
        confidence = 0.5  # Base confidence for high-entropy string

        # Boost confidence based on entropy
        if entropy >= self.MIN_ENTROPY + 1.0:
            confidence += 0.2
        elif entropy >= self.MIN_ENTROPY + 0.5:
            confidence += 0.1

        # Boost if in suspicious context
        if context:
            suspicious_keywords = [
                "key",
                "token",
                "secret",
                "password",
                "credential",
                "auth",
                "api",
            ]
            context_lower = context.lower()
            for keyword in suspicious_keywords:
                if keyword in context_lower:
                    confidence += 0.15
                    break

        # Reduce confidence for common patterns that aren't secrets
        common_patterns = [
            r"^[0-9a-f]{32,}$",  # Hex hashes (MD5, SHA)
            r"^[A-Za-z0-9+/]{40,}={0,2}$",  # Base64 (but could be secret)
        ]
        for pattern in common_patterns:
            if re.match(pattern, value):
                confidence -= 0.1
                break

        return max(0.0, min(1.0, confidence))

    def _get_context(self, text: str, start: int, end: int, window: int = 30) -> str:
        """Get surrounding context for a match.

        Args:
            text: Full text
            start: Match start index
            end: Match end index
            window: Context window size (characters before/after)

        Returns:
            Context string
        """
        context_start = max(0, start - window)
        context_end = min(len(text), end + window)
        return text[context_start:context_end]

    def _deduplicate_matches(self, matches: list[SecretMatch]) -> list[SecretMatch]:
        """Remove overlapping matches, keeping highest confidence.

        Args:
            matches: List of matches

        Returns:
            Deduplicated list
        """
        if not matches:
            return []

        # Sort by start position
        sorted_matches = sorted(matches, key=lambda m: m.start)

        result: list[SecretMatch] = []
        current = sorted_matches[0]

        for match in sorted_matches[1:]:
            # Check for overlap
            if match.start < current.end:
                # Keep higher confidence match
                if match.confidence > current.confidence:
                    current = match
            else:
                result.append(current)
                current = match

        result.append(current)
        return result

    def redact(self, text: str, replacement: str = "[REDACTED]") -> str:
        """Scan and redact secrets from text.

        Args:
            text: Text to redact
            replacement: Replacement string for secrets

        Returns:
            Redacted text
        """
        matches = self.scan(text)

        # Redact from end to start to maintain indices
        result = text
        for match in sorted(matches, key=lambda m: m.start, reverse=True):
            result = result[: match.start] + replacement + result[match.end :]

        return result

    def alert_if_leaked(
        self,
        text: str,
        source: str = "unknown",
    ) -> list[SecretMatch]:
        """Scan text and return alerts for any secrets found.

        Args:
            text: Text to scan
            source: Source identifier for logging

        Returns:
            List of detected secrets (empty if none found)
        """
        matches = self.scan(text)

        if matches:
            # Log alert (in production, send to security monitoring)
            print(f"[SECURITY ALERT] Potential credential leakage in {source}:")
            for match in matches:
                print(f"  - Type: {match.type.value}, Confidence: {match.confidence:.2f}")
                if match.context:
                    print(f"    Context: ...{match.context}...")

        return matches
