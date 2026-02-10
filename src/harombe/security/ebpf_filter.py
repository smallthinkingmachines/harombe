"""eBPF-based syscall filtering for container security.

This module provides syscall filtering using an eBPF-inspired architecture with
a software-based simulation backend. It allows defining policies that control
which system calls are permitted, denied, logged, or result in process termination.

The software simulation backend evaluates syscall rules with condition matching
(path prefixes, port numbers, user IDs) and priority-based ordering, recording
all events for audit and analysis.

Features:
- Policy-based syscall filtering with priority rules
- Condition evaluation: path_prefix, port, uid
- Software simulation backend (no kernel dependencies)
- Stub for real Linux eBPF/seccomp integration
- Event recording and statistics tracking
- Multiple simultaneous policies

Example:
    >>> from harombe.security.ebpf_filter import (
    ...     SyscallAction,
    ...     SyscallFilterManager,
    ...     SyscallRule,
    ... )
    >>>
    >>> manager = SyscallFilterManager()
    >>> await manager.start()
    >>>
    >>> # Create a policy
    >>> policy = await manager.create_policy(
    ...     name="web-server",
    ...     rules=[
    ...         SyscallRule(
    ...             syscall_name="read",
    ...             action=SyscallAction.ALLOW,
    ...         ),
    ...         SyscallRule(
    ...             syscall_name="execve",
    ...             action=SyscallAction.DENY,
    ...         ),
    ...     ],
    ... )
    >>>
    >>> # Load and check syscalls
    >>> await manager.load_policy(policy.policy_id)
    >>> action = await manager.check_syscall("read")
    >>> assert action == SyscallAction.ALLOW
"""

import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class SyscallAction(StrEnum):
    """Action to take when a syscall matches a rule.

    Attributes:
        ALLOW: Permit the syscall to proceed.
        DENY: Block the syscall and return an error.
        LOG: Allow the syscall but record it for auditing.
        KILL: Terminate the process making the syscall.
    """

    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"
    KILL = "kill"


class SyscallRule(BaseModel):
    """A single syscall filtering rule.

    Defines what action to take when a specific syscall is invoked,
    optionally with conditions that must also match.

    Attributes:
        syscall_name: Name of the syscall (e.g., "read", "write", "execve").
        action: Action to take when the rule matches.
        conditions: Optional conditions for matching (e.g., path_prefix, port, uid).
        priority: Rule priority; higher values are checked first.
        description: Optional human-readable description.
    """

    syscall_name: str
    action: SyscallAction
    conditions: dict[str, Any] = Field(default_factory=dict)
    priority: int = 0
    description: str | None = None


class EBPFFilterPolicy(BaseModel):
    """A collection of syscall filtering rules forming a policy.

    Attributes:
        policy_id: Unique identifier for this policy.
        name: Human-readable policy name.
        rules: List of syscall rules in this policy.
        default_action: Action when no rule matches (default: DENY).
        created_at: Timestamp when the policy was created.
        enabled: Whether the policy is active.
    """

    policy_id: str
    name: str
    rules: list[SyscallRule] = Field(default_factory=list)
    default_action: SyscallAction = SyscallAction.DENY
    created_at: datetime = Field(default_factory=datetime.utcnow)
    enabled: bool = True


class EBPFEvent(BaseModel):
    """A recorded syscall filtering event.

    Attributes:
        event_id: Unique identifier for this event.
        timestamp: When the event occurred.
        syscall_name: Name of the syscall that triggered the event.
        action_taken: Action that was applied.
        process_id: Process ID that made the syscall.
        details: Additional context about the event.
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    syscall_name: str
    action_taken: SyscallAction
    process_id: int = 0
    details: dict[str, Any] = Field(default_factory=dict)


class EBPFFilterBackend(ABC):
    """Abstract base class for eBPF filter backends.

    Defines the interface that all filter backends must implement,
    whether using real eBPF/seccomp or software simulation.
    """

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the filter backend."""

    @abstractmethod
    async def load_policy(self, policy: EBPFFilterPolicy) -> None:
        """Load a filtering policy into the backend.

        Args:
            policy: The policy to load.
        """

    @abstractmethod
    async def check_syscall(
        self,
        syscall_name: str,
        context: dict[str, Any] | None = None,
    ) -> SyscallAction:
        """Check a syscall against loaded policies.

        Args:
            syscall_name: Name of the syscall to check.
            context: Optional context for condition evaluation.

        Returns:
            The action to take for this syscall.
        """

    @abstractmethod
    async def get_events(self, limit: int = 100) -> list[EBPFEvent]:
        """Retrieve recorded filter events.

        Args:
            limit: Maximum number of events to return.

        Returns:
            List of recorded events, most recent first.
        """

    @abstractmethod
    async def get_stats(self) -> dict[str, Any]:
        """Get filtering statistics.

        Returns:
            Dictionary with statistics about filter operations.
        """

    @abstractmethod
    async def shutdown(self) -> None:
        """Shut down the filter backend and release resources."""


class LinuxEBPFFilter(EBPFFilterBackend):
    """Linux eBPF/seccomp-based syscall filter (stub).

    This backend would use the Linux kernel's eBPF subsystem and
    seccomp-bpf to perform in-kernel syscall filtering. It requires
    a Linux kernel >= 4.14 with BPF support and appropriate
    capabilities (CAP_SYS_ADMIN or CAP_BPF).

    Currently raises NotImplementedError for all operations. A full
    implementation would:
    - Compile BPF programs from policy rules
    - Attach them via seccomp(2) or bpf(2)
    - Read events from BPF ring buffers
    - Collect statistics from BPF maps
    """

    async def initialize(self) -> None:
        """Initialize the Linux eBPF subsystem.

        Would verify kernel support, load BPF helpers, and set up
        ring buffers for event collection.
        """
        raise NotImplementedError("Linux eBPF/seccomp not available")

    async def load_policy(self, policy: EBPFFilterPolicy) -> None:
        """Compile and load a BPF program from the policy.

        Would translate SyscallRule objects into BPF instructions
        and attach them via seccomp-bpf.
        """
        raise NotImplementedError("Linux eBPF/seccomp not available")

    async def check_syscall(
        self,
        syscall_name: str,
        context: dict[str, Any] | None = None,
    ) -> SyscallAction:
        """Check a syscall via the loaded BPF program.

        In a real implementation, this would be handled in-kernel
        by the BPF program with zero userspace overhead.
        """
        raise NotImplementedError("Linux eBPF/seccomp not available")

    async def get_events(self, limit: int = 100) -> list[EBPFEvent]:
        """Read events from the BPF ring buffer.

        Would poll the perf event or ring buffer map for recorded
        syscall events.
        """
        raise NotImplementedError("Linux eBPF/seccomp not available")

    async def get_stats(self) -> dict[str, Any]:
        """Read statistics from BPF maps.

        Would read per-CPU counters from BPF hash/array maps.
        """
        raise NotImplementedError("Linux eBPF/seccomp not available")

    async def shutdown(self) -> None:
        """Detach BPF programs and release resources.

        Would unpin BPF programs, close file descriptors, and
        free ring buffer memory.
        """
        raise NotImplementedError("Linux eBPF/seccomp not available")


class SoftwareEBPFFilter(EBPFFilterBackend):
    """Software-based syscall filter simulating eBPF behavior.

    Evaluates syscall rules in userspace with support for condition
    matching on path prefixes, port numbers, and user IDs. Records
    all events and tracks statistics for monitoring and auditing.

    Rules are evaluated in priority order (highest first). The first
    matching rule determines the action. If no rule matches, the
    policy's default action is used.

    Example:
        >>> backend = SoftwareEBPFFilter()
        >>> await backend.initialize()
        >>> await backend.load_policy(policy)
        >>> action = await backend.check_syscall("read")
    """

    def __init__(self) -> None:
        """Initialize the software eBPF filter."""
        self._policies: dict[str, EBPFFilterPolicy] = {}
        self._events: list[EBPFEvent] = []
        self._stats: dict[str, int] = {
            "total_checks": 0,
            "allowed": 0,
            "denied": 0,
            "logged": 0,
            "killed": 0,
        }
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the software filter backend."""
        self._initialized = True
        logger.info("Software eBPF filter initialized")

    async def load_policy(self, policy: EBPFFilterPolicy) -> None:
        """Load a filtering policy.

        Args:
            policy: The policy to load.
        """
        self._policies[policy.policy_id] = policy
        logger.info(
            f"Loaded policy '{policy.name}' " f"(id={policy.policy_id}, rules={len(policy.rules)})"
        )

    async def check_syscall(
        self,
        syscall_name: str,
        context: dict[str, Any] | None = None,
    ) -> SyscallAction:
        """Check a syscall against all loaded policies.

        Iterates through all enabled policies and their rules sorted
        by priority (highest first). Returns the action from the first
        matching rule. Falls back to the policy default action if no
        rule matches.

        Args:
            syscall_name: Name of the syscall to check.
            context: Optional context for condition evaluation.

        Returns:
            The action to take for this syscall.
        """
        self._stats["total_checks"] += 1
        ctx = context or {}

        # Check each enabled policy
        for policy in self._policies.values():
            if not policy.enabled:
                continue

            # Sort rules by priority (highest first)
            sorted_rules = sorted(policy.rules, key=lambda r: r.priority, reverse=True)

            for rule in sorted_rules:
                if rule.syscall_name != syscall_name:
                    continue

                # Evaluate conditions
                if not self._evaluate_conditions(rule.conditions, ctx):
                    continue

                # Rule matched
                action = rule.action
                self._record_action(action)
                self._events.append(
                    EBPFEvent(
                        syscall_name=syscall_name,
                        action_taken=action,
                        process_id=ctx.get("pid", 0),
                        details={
                            "policy_id": policy.policy_id,
                            "rule_description": rule.description,
                            "context": ctx,
                        },
                    )
                )

                logger.debug(
                    f"Syscall '{syscall_name}' matched rule "
                    f"(action={action}, policy={policy.name})"
                )
                return action

            # No rule matched in this policy; use default action
            action = policy.default_action
            self._record_action(action)
            self._events.append(
                EBPFEvent(
                    syscall_name=syscall_name,
                    action_taken=action,
                    process_id=ctx.get("pid", 0),
                    details={
                        "policy_id": policy.policy_id,
                        "reason": "default_action",
                        "context": ctx,
                    },
                )
            )

            logger.debug(
                f"Syscall '{syscall_name}' fell through to "
                f"default action (action={action}, "
                f"policy={policy.name})"
            )
            return action

        # No policies loaded at all; deny by default
        action = SyscallAction.DENY
        self._record_action(action)
        self._events.append(
            EBPFEvent(
                syscall_name=syscall_name,
                action_taken=action,
                process_id=ctx.get("pid", 0),
                details={
                    "reason": "no_policies_loaded",
                    "context": ctx,
                },
            )
        )

        logger.debug(f"Syscall '{syscall_name}' denied " f"(no policies loaded)")
        return action

    def _evaluate_conditions(
        self,
        conditions: dict[str, Any],
        context: dict[str, Any],
    ) -> bool:
        """Evaluate rule conditions against the syscall context.

        Supported conditions:
        - path_prefix: Check if context 'path' starts with the prefix.
        - port: Check if context 'port' matches the specified port.
        - uid: Check if context 'uid' matches the specified user ID.

        All specified conditions must match (AND logic).

        Args:
            conditions: Conditions from the rule.
            context: Context from the syscall check.

        Returns:
            True if all conditions match or no conditions specified.
        """
        if not conditions:
            return True

        for key, value in conditions.items():
            if key == "path_prefix":
                path = context.get("path", "")
                if not path.startswith(value):
                    return False
            elif key == "port":
                port = context.get("port")
                if port != value:
                    return False
            elif key == "uid":
                uid = context.get("uid")
                if uid != value:
                    return False
            else:
                logger.warning(f"Unknown condition type: {key}")

        return True

    def _record_action(self, action: SyscallAction) -> None:
        """Update statistics for the given action.

        Args:
            action: The action that was taken.
        """
        if action == SyscallAction.ALLOW:
            self._stats["allowed"] += 1
        elif action == SyscallAction.DENY:
            self._stats["denied"] += 1
        elif action == SyscallAction.LOG:
            self._stats["logged"] += 1
        elif action == SyscallAction.KILL:
            self._stats["killed"] += 1

    async def get_events(self, limit: int = 100) -> list[EBPFEvent]:
        """Get recorded filter events.

        Args:
            limit: Maximum number of events to return.

        Returns:
            List of events, most recent first.
        """
        return list(reversed(self._events[-limit:]))

    async def get_stats(self) -> dict[str, Any]:
        """Get filtering statistics.

        Returns:
            Dictionary with counts of checks, allows, denies,
            logs, and kills.
        """
        return dict(self._stats)

    async def shutdown(self) -> None:
        """Shut down the software filter and clear state."""
        self._policies.clear()
        self._initialized = False
        logger.info("Software eBPF filter shut down")


class SyscallFilterManager:
    """High-level manager for eBPF-based syscall filtering.

    Provides a simplified interface for creating and managing syscall
    filtering policies, checking syscalls, and retrieving events and
    statistics.

    Example:
        >>> manager = SyscallFilterManager()
        >>> await manager.start()
        >>> policy = await manager.create_policy(
        ...     name="default",
        ...     rules=[
        ...         SyscallRule(
        ...             syscall_name="read",
        ...             action=SyscallAction.ALLOW,
        ...         ),
        ...     ],
        ... )
        >>> await manager.load_policy(policy.policy_id)
        >>> action = await manager.check_syscall("read")
        >>> await manager.stop()
    """

    def __init__(self, backend: EBPFFilterBackend | None = None) -> None:
        """Initialize the syscall filter manager.

        Args:
            backend: Filter backend to use. Defaults to
                SoftwareEBPFFilter if not specified.
        """
        self._backend = backend or SoftwareEBPFFilter()
        self._policies: dict[str, EBPFFilterPolicy] = {}
        self._running = False

    async def start(self) -> None:
        """Start the filter manager and initialize the backend."""
        await self._backend.initialize()
        self._running = True
        logger.info("SyscallFilterManager started")

    async def stop(self) -> None:
        """Stop the filter manager and shut down the backend."""
        await self._backend.shutdown()
        self._running = False
        logger.info("SyscallFilterManager stopped")

    async def create_policy(
        self,
        name: str,
        rules: list[SyscallRule] | None = None,
        default_action: SyscallAction = SyscallAction.DENY,
    ) -> EBPFFilterPolicy:
        """Create a new syscall filtering policy.

        The policy is stored internally but not loaded into the
        backend until load_policy() is called.

        Args:
            name: Human-readable policy name.
            rules: List of syscall rules for the policy.
            default_action: Action when no rule matches.

        Returns:
            The created policy.
        """
        policy_id = str(uuid.uuid4())
        policy = EBPFFilterPolicy(
            policy_id=policy_id,
            name=name,
            rules=rules or [],
            default_action=default_action,
        )
        self._policies[policy_id] = policy

        logger.info(f"Created policy '{name}' (id={policy_id}, " f"rules={len(policy.rules)})")
        return policy

    async def load_policy(self, policy_id: str) -> None:
        """Load a policy into the filter backend.

        Args:
            policy_id: ID of the policy to load.

        Raises:
            KeyError: If the policy_id is not found.
        """
        if policy_id not in self._policies:
            raise KeyError(f"Policy not found: {policy_id}")

        policy = self._policies[policy_id]
        await self._backend.load_policy(policy)

        logger.info(f"Loaded policy '{policy.name}' into backend")

    async def check_syscall(
        self,
        syscall_name: str,
        context: dict[str, Any] | None = None,
    ) -> SyscallAction:
        """Check a syscall against loaded policies.

        Args:
            syscall_name: Name of the syscall to check.
            context: Optional context for condition evaluation.

        Returns:
            The action to take for this syscall.
        """
        return await self._backend.check_syscall(syscall_name, context)

    async def get_events(self, limit: int = 100) -> list[EBPFEvent]:
        """Get recorded filter events from the backend.

        Args:
            limit: Maximum number of events to return.

        Returns:
            List of recorded events.
        """
        return await self._backend.get_events(limit)

    async def get_policy(self, policy_id: str) -> EBPFFilterPolicy | None:
        """Get a policy by its ID.

        Args:
            policy_id: ID of the policy to retrieve.

        Returns:
            The policy, or None if not found.
        """
        return self._policies.get(policy_id)

    async def list_policies(self) -> list[EBPFFilterPolicy]:
        """List all managed policies.

        Returns:
            List of all policies.
        """
        return list(self._policies.values())

    async def remove_policy(self, policy_id: str) -> None:
        """Remove a policy from the manager.

        Args:
            policy_id: ID of the policy to remove.

        Raises:
            KeyError: If the policy_id is not found.
        """
        if policy_id not in self._policies:
            raise KeyError(f"Policy not found: {policy_id}")

        policy = self._policies.pop(policy_id)
        logger.info(f"Removed policy '{policy.name}' (id={policy_id})")

    async def get_stats(self) -> dict[str, Any]:
        """Get filtering statistics from the backend.

        Returns:
            Dictionary with filter operation statistics.
        """
        return await self._backend.get_stats()
