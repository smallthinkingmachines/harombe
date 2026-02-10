"""Tests for eBPF-based syscall filtering.

Tests cover:
- SyscallAction enum values (1 test)
- SyscallRule creation (2 tests)
- EBPFFilterPolicy creation with defaults (1 test)
- EBPFFilterPolicy with custom rules (1 test)
- SoftwareEBPFFilter initialize (1 test)
- SoftwareEBPFFilter load_policy (1 test)
- SoftwareEBPFFilter check_syscall ALLOW / DENY / LOG (3 tests)
- SoftwareEBPFFilter default_action fallthrough (1 test)
- SoftwareEBPFFilter rule priority ordering (1 test)
- SoftwareEBPFFilter condition: path_prefix match (1 test)
- SoftwareEBPFFilter condition: path_prefix mismatch (1 test)
- SoftwareEBPFFilter condition: port match (1 test)
- SoftwareEBPFFilter condition: uid match (1 test)
- SoftwareEBPFFilter get_events (1 test)
- SoftwareEBPFFilter get_stats (1 test)
- SoftwareEBPFFilter shutdown (1 test)
- LinuxEBPFFilter raises NotImplementedError (6 tests)
- SyscallFilterManager start/stop (1 test)
- SyscallFilterManager create_policy (1 test)
- SyscallFilterManager load_policy and check_syscall (1 test)
- SyscallFilterManager get_events (1 test)
- SyscallFilterManager list_policies (1 test)
- SyscallFilterManager remove_policy (1 test)
- SyscallFilterManager get_stats (1 test)
- SyscallFilterManager check with no loaded policies (1 test)
- Multiple policies loaded simultaneously (1 test)
- SyscallFilterManager get_policy (1 test)
- SyscallFilterManager load_policy KeyError (1 test)
- SyscallFilterManager remove_policy KeyError (1 test)

Total: 34 tests

Run tests:
    pytest tests/security/test_ebpf_filter.py -v
"""

import pytest

from harombe.security.ebpf_filter import (
    EBPFEvent,
    EBPFFilterPolicy,
    LinuxEBPFFilter,
    SoftwareEBPFFilter,
    SyscallAction,
    SyscallFilterManager,
    SyscallRule,
)

# ============================================================================
# SyscallAction Tests
# ============================================================================


class TestSyscallAction:
    """Test SyscallAction enum."""

    def test_enum_values(self):
        """Test all SyscallAction enum members exist with correct values."""
        assert SyscallAction.ALLOW == "allow"
        assert SyscallAction.DENY == "deny"
        assert SyscallAction.LOG == "log"
        assert SyscallAction.KILL == "kill"
        assert len(SyscallAction) == 4


# ============================================================================
# SyscallRule Tests
# ============================================================================


class TestSyscallRule:
    """Test SyscallRule model."""

    def test_rule_creation_minimal(self):
        """Test creating a rule with only required fields."""
        rule = SyscallRule(
            syscall_name="read",
            action=SyscallAction.ALLOW,
        )
        assert rule.syscall_name == "read"
        assert rule.action == SyscallAction.ALLOW
        assert rule.conditions == {}
        assert rule.priority == 0
        assert rule.description is None

    def test_rule_creation_full(self):
        """Test creating a rule with all fields."""
        rule = SyscallRule(
            syscall_name="open",
            action=SyscallAction.DENY,
            conditions={"path_prefix": "/etc"},
            priority=10,
            description="Block access to /etc",
        )
        assert rule.syscall_name == "open"
        assert rule.action == SyscallAction.DENY
        assert rule.conditions == {"path_prefix": "/etc"}
        assert rule.priority == 10
        assert rule.description == "Block access to /etc"


# ============================================================================
# EBPFFilterPolicy Tests
# ============================================================================


class TestEBPFFilterPolicy:
    """Test EBPFFilterPolicy model."""

    def test_policy_creation_defaults(self):
        """Test creating a policy with default values."""
        policy = EBPFFilterPolicy(
            policy_id="test-1",
            name="test-policy",
        )
        assert policy.policy_id == "test-1"
        assert policy.name == "test-policy"
        assert policy.rules == []
        assert policy.default_action == SyscallAction.DENY
        assert policy.enabled is True
        assert policy.created_at is not None

    def test_policy_creation_with_rules(self):
        """Test creating a policy with custom rules."""
        rules = [
            SyscallRule(
                syscall_name="read",
                action=SyscallAction.ALLOW,
            ),
            SyscallRule(
                syscall_name="write",
                action=SyscallAction.LOG,
            ),
        ]
        policy = EBPFFilterPolicy(
            policy_id="test-2",
            name="custom-policy",
            rules=rules,
            default_action=SyscallAction.KILL,
            enabled=False,
        )
        assert len(policy.rules) == 2
        assert policy.default_action == SyscallAction.KILL
        assert policy.enabled is False


# ============================================================================
# EBPFEvent Tests
# ============================================================================


class TestEBPFEvent:
    """Test EBPFEvent model."""

    def test_event_creation(self):
        """Test creating an event with defaults."""
        event = EBPFEvent(
            syscall_name="read",
            action_taken=SyscallAction.ALLOW,
        )
        assert event.event_id is not None
        assert event.timestamp is not None
        assert event.syscall_name == "read"
        assert event.action_taken == SyscallAction.ALLOW
        assert event.process_id == 0
        assert event.details == {}


# ============================================================================
# SoftwareEBPFFilter Tests
# ============================================================================


class TestSoftwareEBPFFilter:
    """Test SoftwareEBPFFilter backend."""

    @pytest.mark.asyncio
    async def test_initialize(self):
        """Test initializing the software filter."""
        backend = SoftwareEBPFFilter()
        assert backend._initialized is False
        await backend.initialize()
        assert backend._initialized is True

    @pytest.mark.asyncio
    async def test_load_policy(self):
        """Test loading a policy into the filter."""
        backend = SoftwareEBPFFilter()
        await backend.initialize()

        policy = EBPFFilterPolicy(
            policy_id="p1",
            name="test",
            rules=[
                SyscallRule(
                    syscall_name="read",
                    action=SyscallAction.ALLOW,
                ),
            ],
        )
        await backend.load_policy(policy)
        assert "p1" in backend._policies

    @pytest.mark.asyncio
    async def test_check_syscall_allow(self):
        """Test check_syscall returns ALLOW for matching rule."""
        backend = SoftwareEBPFFilter()
        await backend.initialize()

        policy = EBPFFilterPolicy(
            policy_id="p1",
            name="test",
            rules=[
                SyscallRule(
                    syscall_name="read",
                    action=SyscallAction.ALLOW,
                ),
            ],
        )
        await backend.load_policy(policy)

        action = await backend.check_syscall("read")
        assert action == SyscallAction.ALLOW

    @pytest.mark.asyncio
    async def test_check_syscall_deny(self):
        """Test check_syscall returns DENY for matching rule."""
        backend = SoftwareEBPFFilter()
        await backend.initialize()

        policy = EBPFFilterPolicy(
            policy_id="p1",
            name="test",
            rules=[
                SyscallRule(
                    syscall_name="execve",
                    action=SyscallAction.DENY,
                ),
            ],
        )
        await backend.load_policy(policy)

        action = await backend.check_syscall("execve")
        assert action == SyscallAction.DENY

    @pytest.mark.asyncio
    async def test_check_syscall_log(self):
        """Test check_syscall returns LOG for matching rule."""
        backend = SoftwareEBPFFilter()
        await backend.initialize()

        policy = EBPFFilterPolicy(
            policy_id="p1",
            name="test",
            rules=[
                SyscallRule(
                    syscall_name="connect",
                    action=SyscallAction.LOG,
                ),
            ],
        )
        await backend.load_policy(policy)

        action = await backend.check_syscall("connect")
        assert action == SyscallAction.LOG

    @pytest.mark.asyncio
    async def test_check_syscall_falls_through_to_default(self):
        """Test check_syscall uses default_action when no rule matches."""
        backend = SoftwareEBPFFilter()
        await backend.initialize()

        policy = EBPFFilterPolicy(
            policy_id="p1",
            name="test",
            rules=[
                SyscallRule(
                    syscall_name="read",
                    action=SyscallAction.ALLOW,
                ),
            ],
            default_action=SyscallAction.KILL,
        )
        await backend.load_policy(policy)

        # "write" has no matching rule, falls to default KILL
        action = await backend.check_syscall("write")
        assert action == SyscallAction.KILL

    @pytest.mark.asyncio
    async def test_rule_priority_ordering(self):
        """Test higher priority rules are evaluated first."""
        backend = SoftwareEBPFFilter()
        await backend.initialize()

        policy = EBPFFilterPolicy(
            policy_id="p1",
            name="priority-test",
            rules=[
                SyscallRule(
                    syscall_name="open",
                    action=SyscallAction.DENY,
                    priority=1,
                ),
                SyscallRule(
                    syscall_name="open",
                    action=SyscallAction.ALLOW,
                    priority=10,
                ),
            ],
        )
        await backend.load_policy(policy)

        # Higher priority (10) ALLOW should win over lower (1) DENY
        action = await backend.check_syscall("open")
        assert action == SyscallAction.ALLOW

    @pytest.mark.asyncio
    async def test_condition_path_prefix_match(self):
        """Test path_prefix condition matches correctly."""
        backend = SoftwareEBPFFilter()
        await backend.initialize()

        policy = EBPFFilterPolicy(
            policy_id="p1",
            name="path-test",
            rules=[
                SyscallRule(
                    syscall_name="open",
                    action=SyscallAction.DENY,
                    conditions={"path_prefix": "/etc"},
                    priority=10,
                ),
                SyscallRule(
                    syscall_name="open",
                    action=SyscallAction.ALLOW,
                    priority=0,
                ),
            ],
        )
        await backend.load_policy(policy)

        # /etc/passwd matches path_prefix "/etc"
        action = await backend.check_syscall("open", {"path": "/etc/passwd"})
        assert action == SyscallAction.DENY

    @pytest.mark.asyncio
    async def test_condition_path_prefix_no_match(self):
        """Test path_prefix condition does not match non-matching paths."""
        backend = SoftwareEBPFFilter()
        await backend.initialize()

        policy = EBPFFilterPolicy(
            policy_id="p1",
            name="path-test",
            rules=[
                SyscallRule(
                    syscall_name="open",
                    action=SyscallAction.DENY,
                    conditions={"path_prefix": "/etc"},
                    priority=10,
                ),
                SyscallRule(
                    syscall_name="open",
                    action=SyscallAction.ALLOW,
                    priority=0,
                ),
            ],
        )
        await backend.load_policy(policy)

        # /tmp/file does not match path_prefix "/etc"
        action = await backend.check_syscall("open", {"path": "/tmp/file"})
        assert action == SyscallAction.ALLOW

    @pytest.mark.asyncio
    async def test_condition_port_match(self):
        """Test port condition matches correctly."""
        backend = SoftwareEBPFFilter()
        await backend.initialize()

        policy = EBPFFilterPolicy(
            policy_id="p1",
            name="port-test",
            rules=[
                SyscallRule(
                    syscall_name="connect",
                    action=SyscallAction.DENY,
                    conditions={"port": 22},
                ),
            ],
        )
        await backend.load_policy(policy)

        action = await backend.check_syscall("connect", {"port": 22})
        assert action == SyscallAction.DENY

    @pytest.mark.asyncio
    async def test_condition_uid_match(self):
        """Test uid condition matches correctly."""
        backend = SoftwareEBPFFilter()
        await backend.initialize()

        policy = EBPFFilterPolicy(
            policy_id="p1",
            name="uid-test",
            rules=[
                SyscallRule(
                    syscall_name="execve",
                    action=SyscallAction.ALLOW,
                    conditions={"uid": 0},
                ),
            ],
            default_action=SyscallAction.DENY,
        )
        await backend.load_policy(policy)

        # uid=0 (root) matches
        action = await backend.check_syscall("execve", {"uid": 0})
        assert action == SyscallAction.ALLOW

        # uid=1000 does not match, falls to default DENY
        action = await backend.check_syscall("execve", {"uid": 1000})
        assert action == SyscallAction.DENY

    @pytest.mark.asyncio
    async def test_get_events(self):
        """Test get_events returns recorded events."""
        backend = SoftwareEBPFFilter()
        await backend.initialize()

        policy = EBPFFilterPolicy(
            policy_id="p1",
            name="test",
            rules=[
                SyscallRule(
                    syscall_name="read",
                    action=SyscallAction.ALLOW,
                ),
            ],
        )
        await backend.load_policy(policy)

        await backend.check_syscall("read")
        await backend.check_syscall("write")

        events = await backend.get_events()
        assert len(events) == 2
        # Most recent first
        assert events[0].syscall_name == "write"
        assert events[1].syscall_name == "read"

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """Test get_stats tracks action counts."""
        backend = SoftwareEBPFFilter()
        await backend.initialize()

        policy = EBPFFilterPolicy(
            policy_id="p1",
            name="test",
            rules=[
                SyscallRule(
                    syscall_name="read",
                    action=SyscallAction.ALLOW,
                ),
                SyscallRule(
                    syscall_name="execve",
                    action=SyscallAction.DENY,
                ),
            ],
        )
        await backend.load_policy(policy)

        await backend.check_syscall("read")
        await backend.check_syscall("read")
        await backend.check_syscall("execve")

        stats = await backend.get_stats()
        assert stats["total_checks"] == 3
        assert stats["allowed"] == 2
        assert stats["denied"] == 1
        assert stats["logged"] == 0
        assert stats["killed"] == 0

    @pytest.mark.asyncio
    async def test_shutdown(self):
        """Test shutdown clears policies and resets state."""
        backend = SoftwareEBPFFilter()
        await backend.initialize()
        assert backend._initialized is True

        policy = EBPFFilterPolicy(
            policy_id="p1",
            name="test",
        )
        await backend.load_policy(policy)
        assert len(backend._policies) == 1

        await backend.shutdown()
        assert backend._initialized is False
        assert len(backend._policies) == 0


# ============================================================================
# LinuxEBPFFilter Tests
# ============================================================================


class TestLinuxEBPFFilter:
    """Test LinuxEBPFFilter stub raises NotImplementedError."""

    @pytest.mark.asyncio
    async def test_initialize_raises(self):
        """Test initialize raises NotImplementedError."""
        backend = LinuxEBPFFilter()
        with pytest.raises(NotImplementedError, match="Linux eBPF"):
            await backend.initialize()

    @pytest.mark.asyncio
    async def test_load_policy_raises(self):
        """Test load_policy raises NotImplementedError."""
        backend = LinuxEBPFFilter()
        policy = EBPFFilterPolicy(policy_id="p1", name="test")
        with pytest.raises(NotImplementedError, match="Linux eBPF"):
            await backend.load_policy(policy)

    @pytest.mark.asyncio
    async def test_check_syscall_raises(self):
        """Test check_syscall raises NotImplementedError."""
        backend = LinuxEBPFFilter()
        with pytest.raises(NotImplementedError, match="Linux eBPF"):
            await backend.check_syscall("read")

    @pytest.mark.asyncio
    async def test_get_events_raises(self):
        """Test get_events raises NotImplementedError."""
        backend = LinuxEBPFFilter()
        with pytest.raises(NotImplementedError, match="Linux eBPF"):
            await backend.get_events()

    @pytest.mark.asyncio
    async def test_get_stats_raises(self):
        """Test get_stats raises NotImplementedError."""
        backend = LinuxEBPFFilter()
        with pytest.raises(NotImplementedError, match="Linux eBPF"):
            await backend.get_stats()

    @pytest.mark.asyncio
    async def test_shutdown_raises(self):
        """Test shutdown raises NotImplementedError."""
        backend = LinuxEBPFFilter()
        with pytest.raises(NotImplementedError, match="Linux eBPF"):
            await backend.shutdown()


# ============================================================================
# SyscallFilterManager Tests
# ============================================================================


class TestSyscallFilterManager:
    """Test SyscallFilterManager high-level interface."""

    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        """Test manager start and stop lifecycle."""
        manager = SyscallFilterManager()
        await manager.start()
        assert manager._running is True

        await manager.stop()
        assert manager._running is False

    @pytest.mark.asyncio
    async def test_create_policy(self):
        """Test creating a policy via the manager."""
        manager = SyscallFilterManager()
        await manager.start()

        policy = await manager.create_policy(
            name="test-policy",
            rules=[
                SyscallRule(
                    syscall_name="read",
                    action=SyscallAction.ALLOW,
                ),
            ],
        )

        assert policy.name == "test-policy"
        assert len(policy.rules) == 1
        assert policy.policy_id in manager._policies

        await manager.stop()

    @pytest.mark.asyncio
    async def test_load_policy_and_check_syscall(self):
        """Test loading a policy and checking syscalls."""
        manager = SyscallFilterManager()
        await manager.start()

        policy = await manager.create_policy(
            name="test",
            rules=[
                SyscallRule(
                    syscall_name="read",
                    action=SyscallAction.ALLOW,
                ),
                SyscallRule(
                    syscall_name="execve",
                    action=SyscallAction.DENY,
                ),
            ],
        )

        await manager.load_policy(policy.policy_id)

        assert await manager.check_syscall("read") == SyscallAction.ALLOW
        assert await manager.check_syscall("execve") == SyscallAction.DENY

        await manager.stop()

    @pytest.mark.asyncio
    async def test_get_events(self):
        """Test retrieving events from the manager."""
        manager = SyscallFilterManager()
        await manager.start()

        policy = await manager.create_policy(
            name="test",
            rules=[
                SyscallRule(
                    syscall_name="read",
                    action=SyscallAction.ALLOW,
                ),
            ],
        )
        await manager.load_policy(policy.policy_id)
        await manager.check_syscall("read")

        events = await manager.get_events()
        assert len(events) == 1
        assert events[0].syscall_name == "read"
        assert events[0].action_taken == SyscallAction.ALLOW

        await manager.stop()

    @pytest.mark.asyncio
    async def test_list_policies(self):
        """Test listing all policies."""
        manager = SyscallFilterManager()
        await manager.start()

        await manager.create_policy(name="policy-a")
        await manager.create_policy(name="policy-b")

        policies = await manager.list_policies()
        assert len(policies) == 2
        names = {p.name for p in policies}
        assert names == {"policy-a", "policy-b"}

        await manager.stop()

    @pytest.mark.asyncio
    async def test_remove_policy(self):
        """Test removing a policy."""
        manager = SyscallFilterManager()
        await manager.start()

        policy = await manager.create_policy(name="to-remove")
        assert len(await manager.list_policies()) == 1

        await manager.remove_policy(policy.policy_id)
        assert len(await manager.list_policies()) == 0

        await manager.stop()

    @pytest.mark.asyncio
    async def test_remove_policy_not_found(self):
        """Test removing a non-existent policy raises KeyError."""
        manager = SyscallFilterManager()
        await manager.start()

        with pytest.raises(KeyError, match="Policy not found"):
            await manager.remove_policy("nonexistent-id")

        await manager.stop()

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """Test getting stats from the manager."""
        manager = SyscallFilterManager()
        await manager.start()

        policy = await manager.create_policy(
            name="test",
            rules=[
                SyscallRule(
                    syscall_name="read",
                    action=SyscallAction.ALLOW,
                ),
            ],
        )
        await manager.load_policy(policy.policy_id)
        await manager.check_syscall("read")

        stats = await manager.get_stats()
        assert stats["total_checks"] == 1
        assert stats["allowed"] == 1

        await manager.stop()

    @pytest.mark.asyncio
    async def test_check_syscall_no_loaded_policies(self):
        """Test check with no loaded policies defaults to DENY."""
        manager = SyscallFilterManager()
        await manager.start()

        action = await manager.check_syscall("read")
        assert action == SyscallAction.DENY

        await manager.stop()

    @pytest.mark.asyncio
    async def test_multiple_policies_loaded(self):
        """Test loading multiple policies simultaneously."""
        manager = SyscallFilterManager()
        await manager.start()

        policy_a = await manager.create_policy(
            name="policy-a",
            rules=[
                SyscallRule(
                    syscall_name="read",
                    action=SyscallAction.ALLOW,
                ),
            ],
        )
        policy_b = await manager.create_policy(
            name="policy-b",
            rules=[
                SyscallRule(
                    syscall_name="write",
                    action=SyscallAction.LOG,
                ),
            ],
        )

        await manager.load_policy(policy_a.policy_id)
        await manager.load_policy(policy_b.policy_id)

        # First loaded policy handles "read"
        action = await manager.check_syscall("read")
        assert action == SyscallAction.ALLOW

        await manager.stop()

    @pytest.mark.asyncio
    async def test_get_policy(self):
        """Test retrieving a specific policy by ID."""
        manager = SyscallFilterManager()
        await manager.start()

        policy = await manager.create_policy(name="findme")

        result = await manager.get_policy(policy.policy_id)
        assert result is not None
        assert result.name == "findme"

        result_none = await manager.get_policy("nonexistent")
        assert result_none is None

        await manager.stop()

    @pytest.mark.asyncio
    async def test_load_policy_not_found(self):
        """Test loading a non-existent policy raises KeyError."""
        manager = SyscallFilterManager()
        await manager.start()

        with pytest.raises(KeyError, match="Policy not found"):
            await manager.load_policy("nonexistent-id")

        await manager.stop()

    @pytest.mark.asyncio
    async def test_default_backend_is_software(self):
        """Test that default backend is SoftwareEBPFFilter."""
        manager = SyscallFilterManager()
        assert isinstance(manager._backend, SoftwareEBPFFilter)
