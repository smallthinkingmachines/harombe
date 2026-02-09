"""Circuit breaker pattern for failing nodes."""

import time
from dataclasses import dataclass
from enum import Enum


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Too many failures, circuit is open
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""

    failure_threshold: int = 5  # Open circuit after this many failures
    success_threshold: int = 2  # Close circuit after this many successes in half-open
    timeout: float = 60.0  # Seconds before trying half-open
    half_open_timeout: float = 30.0  # Seconds to wait in half-open before reopening


class CircuitBreaker:
    """
    Circuit breaker for protecting against cascading failures.

    Tracks failures and opens circuit when threshold is reached.
    """

    def __init__(self, config: CircuitBreakerConfig):
        """
        Initialize circuit breaker.

        Args:
            config: Circuit breaker configuration
        """
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: float = 0
        self.opened_at: float = 0

    def record_success(self) -> None:
        """Record a successful operation."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self._close_circuit()
        elif self.state == CircuitState.CLOSED:
            # Reset failure count on success
            self.failure_count = 0

    def record_failure(self) -> None:
        """Record a failed operation."""
        self.last_failure_time = time.time()

        if self.state == CircuitState.CLOSED:
            self.failure_count += 1
            if self.failure_count >= self.config.failure_threshold:
                self._open_circuit()

        elif self.state == CircuitState.HALF_OPEN:
            # Failed during recovery, reopen
            self._open_circuit()

    def can_attempt(self) -> bool:
        """Check if an operation can be attempted."""
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            # Check if timeout has elapsed
            if time.time() - self.opened_at >= self.config.timeout:
                self._transition_to_half_open()
                return True
            return False

        if self.state == CircuitState.HALF_OPEN:
            # Check half-open timeout
            if time.time() - self.opened_at >= self.config.half_open_timeout:
                self._open_circuit()  # Took too long, reopen
                return False
            return True

        return False

    def _open_circuit(self) -> None:
        """Transition to OPEN state."""
        self.state = CircuitState.OPEN
        self.opened_at = time.time()
        self.success_count = 0

    def _close_circuit(self) -> None:
        """Transition to CLOSED state."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0

    def _transition_to_half_open(self) -> None:
        """Transition to HALF_OPEN state."""
        self.state = CircuitState.HALF_OPEN
        self.opened_at = time.time()
        self.success_count = 0

    def get_state(self) -> CircuitState:
        """Get current circuit state."""
        # Update state if needed
        if self.state == CircuitState.OPEN:
            if time.time() - self.opened_at >= self.config.timeout:
                self._transition_to_half_open()

        return self.state


class CircuitBreakerRegistry:
    """Registry of circuit breakers per node."""

    def __init__(self, config: CircuitBreakerConfig):
        """
        Initialize registry.

        Args:
            config: Default circuit breaker configuration
        """
        self.config = config
        self._breakers: dict[str, CircuitBreaker] = {}

    def get_breaker(self, node_name: str) -> CircuitBreaker:
        """
        Get circuit breaker for a node.

        Args:
            node_name: Node name

        Returns:
            Circuit breaker for the node
        """
        if node_name not in self._breakers:
            self._breakers[node_name] = CircuitBreaker(self.config)
        return self._breakers[node_name]

    def can_attempt(self, node_name: str) -> bool:
        """Check if operation can be attempted on node."""
        return self.get_breaker(node_name).can_attempt()

    def record_success(self, node_name: str) -> None:
        """Record successful operation for node."""
        self.get_breaker(node_name).record_success()

    def record_failure(self, node_name: str) -> None:
        """Record failed operation for node."""
        self.get_breaker(node_name).record_failure()

    def get_state(self, node_name: str) -> CircuitState:
        """Get circuit state for node."""
        return self.get_breaker(node_name).get_state()
