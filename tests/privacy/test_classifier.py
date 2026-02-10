"""Tests for the sensitivity classifier."""

import pytest

from harombe.llm.client import Message
from harombe.privacy.classifier import SensitivityClassifier
from harombe.privacy.models import SensitivityLevel


@pytest.fixture
def classifier():
    return SensitivityClassifier()


class TestSensitivityClassifier:
    def test_public_query(self, classifier):
        result = classifier.classify("What is the weather like today?")
        assert result.level == SensitivityLevel.PUBLIC
        assert not result.detected_entities

    def test_detects_email(self, classifier):
        result = classifier.classify("Send this to john@example.com please")
        assert result.level == SensitivityLevel.INTERNAL
        entities = [e for e in result.detected_entities if e.type == "email"]
        assert len(entities) >= 1
        assert entities[0].value == "john@example.com"

    def test_detects_ssn(self, classifier):
        result = classifier.classify("My SSN is 123-45-6789")
        assert result.level == SensitivityLevel.INTERNAL
        entities = [e for e in result.detected_entities if e.type == "ssn"]
        assert len(entities) == 1
        assert entities[0].value == "123-45-6789"

    def test_detects_phone(self, classifier):
        result = classifier.classify("Call me at (555) 123-4567")
        assert result.level == SensitivityLevel.INTERNAL
        entities = [e for e in result.detected_entities if e.type == "phone"]
        assert len(entities) == 1

    def test_detects_credit_card(self, classifier):
        result = classifier.classify("My card is 4111-1111-1111-1111")
        assert result.level == SensitivityLevel.INTERNAL
        entities = [e for e in result.detected_entities if e.type == "credit_card"]
        assert len(entities) == 1

    def test_detects_ip_address(self, classifier):
        result = classifier.classify("The server is at 192.168.1.100")
        assert result.level == SensitivityLevel.INTERNAL
        entities = [e for e in result.detected_entities if e.type == "ip_address"]
        assert len(entities) == 1

    def test_detects_github_token(self, classifier):
        token = "ghp_" + "a" * 36
        result = classifier.classify(f"My token is {token}")
        assert result.level == SensitivityLevel.CONFIDENTIAL
        assert any("credential" in e.type for e in result.detected_entities)

    def test_detects_aws_key(self, classifier):
        result = classifier.classify("My key is AKIA1234567890123456")
        assert result.level == SensitivityLevel.CONFIDENTIAL

    def test_restricted_keyword_confidential(self, classifier):
        result = classifier.classify("This document is CONFIDENTIAL")
        assert result.level == SensitivityLevel.RESTRICTED

    def test_restricted_keyword_hipaa(self, classifier):
        result = classifier.classify("This data falls under HIPAA regulations")
        assert result.level == SensitivityLevel.RESTRICTED

    def test_restricted_keyword_nda(self, classifier):
        result = classifier.classify("This is covered by our NDA")
        assert result.level == SensitivityLevel.RESTRICTED

    def test_custom_patterns(self):
        classifier = SensitivityClassifier(custom_patterns={"employee_id": r"\bEMP-\d{6}\b"})
        result = classifier.classify("Employee EMP-123456 needs access")
        assert result.level == SensitivityLevel.INTERNAL
        entities = [e for e in result.detected_entities if e.type == "employee_id"]
        assert len(entities) == 1

    def test_custom_restricted_keywords(self):
        classifier = SensitivityClassifier(custom_restricted_keywords=["project-x"])
        result = classifier.classify("This is about project-x")
        assert result.level == SensitivityLevel.RESTRICTED

    def test_scans_message_history(self, classifier):
        messages = [
            Message(role="user", content="My email is secret@corp.com"),
            Message(role="assistant", content="Got it."),
        ]
        result = classifier.classify("What did I say?", messages)
        # Should detect email from history
        assert result.level == SensitivityLevel.INTERNAL

    def test_multiple_entities(self, classifier):
        text = "Contact john@example.com at 555-123-4567 about SSN 123-45-6789"
        result = classifier.classify(text)
        assert len(result.detected_entities) >= 3
        assert len(result.pii_locations) >= 3

    def test_confidence_scores(self, classifier):
        result = classifier.classify("My SSN is 123-45-6789")
        for entity in result.detected_entities:
            assert 0.0 <= entity.confidence <= 1.0
        assert 0.0 <= result.confidence <= 1.0

    def test_reasons_populated(self, classifier):
        result = classifier.classify("Email: test@example.com")
        assert len(result.reasons) >= 1

    def test_empty_query(self, classifier):
        result = classifier.classify("")
        assert result.level == SensitivityLevel.PUBLIC
