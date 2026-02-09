"""Tests for circuit breaker pattern."""

import time

from harombe.coordination.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerRegistry,
    CircuitState,
)


def test_circuit_breaker_closed_state():
    """Test circuit breaker starts in closed state."""
    config = CircuitBreakerConfig(failure_threshold=3)
    breaker = CircuitBreaker(config)

    assert breaker.get_state() == CircuitState.CLOSED
    assert breaker.can_attempt() is True


def test_circuit_breaker_opens_after_failures():
    """Test circuit opens after threshold failures."""
    config = CircuitBreakerConfig(failure_threshold=3)
    breaker = CircuitBreaker(config)

    # Record failures
    breaker.record_failure()
    assert breaker.get_state() == CircuitState.CLOSED

    breaker.record_failure()
    assert breaker.get_state() == CircuitState.CLOSED

    breaker.record_failure()
    assert breaker.get_state() == CircuitState.OPEN
    assert breaker.can_attempt() is False


def test_circuit_breaker_half_open_transition():
    """Test circuit transitions to half-open after timeout."""
    config = CircuitBreakerConfig(failure_threshold=2, timeout=0.1)
    breaker = CircuitBreaker(config)

    # Open the circuit
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.get_state() == CircuitState.OPEN

    # Wait for timeout
    time.sleep(0.15)

    # Should transition to half-open
    assert breaker.can_attempt() is True
    assert breaker.get_state() == CircuitState.HALF_OPEN


def test_circuit_breaker_closes_after_successes():
    """Test circuit closes after success threshold in half-open."""
    config = CircuitBreakerConfig(
        failure_threshold=2,
        success_threshold=2,
        timeout=0.1,
    )
    breaker = CircuitBreaker(config)

    # Open the circuit
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.get_state() == CircuitState.OPEN

    # Wait and transition to half-open
    time.sleep(0.15)
    breaker.can_attempt()
    assert breaker.get_state() == CircuitState.HALF_OPEN

    # Record successes
    breaker.record_success()
    assert breaker.get_state() == CircuitState.HALF_OPEN

    breaker.record_success()
    assert breaker.get_state() == CircuitState.CLOSED


def test_circuit_breaker_reopens_on_half_open_failure():
    """Test circuit reopens if failure occurs in half-open."""
    config = CircuitBreakerConfig(failure_threshold=2, timeout=0.1)
    breaker = CircuitBreaker(config)

    # Open the circuit
    breaker.record_failure()
    breaker.record_failure()

    # Transition to half-open
    time.sleep(0.15)
    breaker.can_attempt()
    assert breaker.get_state() == CircuitState.HALF_OPEN

    # Failure in half-open reopens circuit
    breaker.record_failure()
    assert breaker.get_state() == CircuitState.OPEN


def test_circuit_breaker_resets_failures_on_success():
    """Test failure count resets on success in closed state."""
    config = CircuitBreakerConfig(failure_threshold=3)
    breaker = CircuitBreaker(config)

    breaker.record_failure()
    breaker.record_failure()
    assert breaker.failure_count == 2

    # Success resets failures
    breaker.record_success()
    assert breaker.failure_count == 0
    assert breaker.get_state() == CircuitState.CLOSED


def test_circuit_breaker_registry():
    """Test circuit breaker registry manages multiple breakers."""
    config = CircuitBreakerConfig(failure_threshold=2)
    registry = CircuitBreakerRegistry(config)

    # Get breakers for different nodes
    breaker1 = registry.get_breaker("node1")
    breaker2 = registry.get_breaker("node2")

    assert breaker1 is not breaker2

    # Operations on one don't affect the other
    registry.record_failure("node1")
    registry.record_failure("node1")

    assert registry.get_state("node1") == CircuitState.OPEN
    assert registry.get_state("node2") == CircuitState.CLOSED


def test_circuit_breaker_registry_operations():
    """Test registry convenience methods."""
    config = CircuitBreakerConfig(failure_threshold=2)
    registry = CircuitBreakerRegistry(config)

    assert registry.can_attempt("node1") is True

    registry.record_failure("node1")
    registry.record_failure("node1")

    assert registry.can_attempt("node1") is False

    registry.record_success("node1")  # In closed state, this resets
