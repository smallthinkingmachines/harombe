"""Tests for smart routing and complexity classification."""

import pytest

from harombe.coordination.router import (
    ComplexityClassifier,
    Router,
    RoutingDecision,
    TaskComplexity,
)
from harombe.llm.client import Message


def test_classifier_simple_query():
    """Test classification of simple queries."""
    classifier = ComplexityClassifier()

    # Short factual questions
    assert classifier.classify_query("What is Python?") == TaskComplexity.SIMPLE
    assert classifier.classify_query("When was Docker released?") == TaskComplexity.SIMPLE
    assert classifier.classify_query("Who created Linux?") == TaskComplexity.SIMPLE


def test_classifier_medium_query():
    """Test classification of medium complexity queries."""
    classifier = ComplexityClassifier()

    # Moderate length with "compare" keyword
    query = "Compare the performance of PostgreSQL and MySQL for read-heavy workloads"
    complexity = classifier.classify_query(query)
    # "Compare" is a complex keyword, should be at least MEDIUM
    assert complexity in (TaskComplexity.MEDIUM, TaskComplexity.COMPLEX)


def test_classifier_complex_query():
    """Test classification of complex queries."""
    classifier = ComplexityClassifier()

    # Code review/analysis with code block
    query = """
    Please analyze this Python code and explain what optimizations could be made:

    ```python
    def process_data(items):
        result = []
        for item in items:
            if item > 0:
                result.append(item * 2)
        return result
    ```
    """
    complexity = classifier.classify_query(query)
    # Has code block, "analyze", and "explain" keywords
    assert complexity == TaskComplexity.COMPLEX

    # Detailed implementation request with multiple complex keywords
    query = "Implement a comprehensive distributed cache system with TTL support, eviction policies, and cluster-aware replication"
    complexity = classifier.classify_query(query)
    # "implement" and "comprehensive" are complex keywords
    assert complexity in (TaskComplexity.MEDIUM, TaskComplexity.COMPLEX)


def test_classifier_with_context():
    """Test classification considers conversation context."""
    classifier = ComplexityClassifier()

    # Simple query without context
    query = "What about error handling?"
    complexity_no_context = classifier.classify_query(query)

    # Same query with very large context
    context = [
        Message(role="user", content="Can you help me build a web scraper?"),
        Message(
            role="assistant",
            content="Sure! Here's a basic web scraper using Beautiful Soup. " + "word " * 5000,
        ),
        Message(role="user", content="How do I handle rate limiting?"),
        Message(
            role="assistant",
            content="Rate limiting can be handled with exponential backoff. " + "word " * 5000,
        ),
    ]
    complexity_with_context = classifier.classify_query(query, context=context)
    # Large context should increase or maintain complexity (context scoring adds to total)
    # At minimum, context should not decrease complexity
    assert complexity_with_context.value >= complexity_no_context.value


def test_classifier_code_presence():
    """Test detection of code in queries."""
    classifier = ComplexityClassifier()

    # Query with code block should score high
    query = """
    Fix this bug:
    ```python
    def add(a, b):
        return a - b  # Wrong operator!
    ```
    """
    complexity = classifier.classify_query(query)
    # Code block is a strong signal, should be at least MEDIUM
    assert complexity in (TaskComplexity.MEDIUM, TaskComplexity.COMPLEX)


def test_classifier_length_scoring():
    """Test that query length affects complexity."""
    classifier = ComplexityClassifier()

    # Very short query
    short_query = "Hi"
    assert classifier.classify_query(short_query) == TaskComplexity.SIMPLE

    # Very long query (>80 words triggers high length score)
    long_query = " ".join(["analyze"] * 120)  # Use "analyze" to also trigger keyword score
    complexity = classifier.classify_query(long_query)
    # Length + keyword should push at least to MEDIUM
    assert complexity in (TaskComplexity.MEDIUM, TaskComplexity.COMPLEX)


def test_router_basic():
    """Test basic router functionality."""
    router = Router()

    # Simple query
    decision = router.analyze_routing("What is Docker?")
    assert decision.complexity == TaskComplexity.SIMPLE
    assert decision.recommended_tier == 0
    assert decision.estimated_tokens > 0


def test_router_tier_mapping():
    """Test that complexity maps to correct tiers."""
    router = Router()

    # Simple -> Tier 0
    decision = router.analyze_routing("Quick question about Python")
    assert decision.recommended_tier == 0

    # Medium -> Tier 1
    decision = router.analyze_routing(
        "Explain how to implement a binary search tree with balanced rotations"
    )
    assert decision.recommended_tier in (1, 2)  # Could be 1 or 2

    # Complex -> Tier 2
    decision = router.analyze_routing(
        """
        Analyze this codebase and provide a comprehensive refactoring plan:

        ```python
        # 100 lines of complex code here
        """ + "code line\n" * 100 + """
        ```
        """
    )
    assert decision.recommended_tier == 2


def test_router_token_estimation():
    """Test token estimation."""
    router = Router()

    # Short query
    decision = router.analyze_routing("Hello")
    assert decision.estimated_tokens < 10

    # Medium query
    query = " ".join(["word"] * 50)
    decision = router.analyze_routing(query)
    assert 30 < decision.estimated_tokens < 70

    # With context
    context = [
        Message(role="user", content="Previous message" * 100),
    ]
    decision = router.analyze_routing(query, context=context)
    # Should be much higher with context
    assert decision.estimated_tokens > 300


def test_router_context_upgrades_tier():
    """Test that large context upgrades tier recommendation."""
    router = Router()

    # Simple query without context -> Tier 0
    decision = router.analyze_routing("What next?")
    assert decision.recommended_tier == 0

    # Same query with huge context -> Higher tier
    large_context = [
        Message(role="user", content="x" * 10000),
        Message(role="assistant", content="y" * 10000),
    ]
    decision = router.analyze_routing("What next?", context=large_context)
    # Large context should force tier 2
    assert decision.recommended_tier == 2
    assert "large context" in decision.reasoning.lower()


def test_router_reasoning():
    """Test that router provides reasoning for decisions."""
    router = Router()

    decision = router.analyze_routing("What is Python?")
    assert len(decision.reasoning) > 0
    assert isinstance(decision.reasoning, str)

    # Complex query with multiple indicators
    decision = router.analyze_routing(
        """Implement a comprehensive distributed consensus algorithm with Raft.
        Please analyze the design patterns and explain the detailed implementation steps."""
    )
    # Should be at least tier 1 due to multiple complex keywords
    assert decision.recommended_tier >= 1
    # Reasoning should mention complexity or model type
    assert any(word in decision.reasoning.lower() for word in ["complex", "powerful", "medium", "balanced"])


def test_routing_decision_fields():
    """Test RoutingDecision has all required fields."""
    router = Router()
    decision = router.analyze_routing("Test query")

    assert isinstance(decision.complexity, TaskComplexity)
    assert isinstance(decision.recommended_tier, int)
    assert 0 <= decision.recommended_tier <= 2
    assert isinstance(decision.reasoning, str)
    assert isinstance(decision.estimated_tokens, int)
    assert decision.estimated_tokens > 0
