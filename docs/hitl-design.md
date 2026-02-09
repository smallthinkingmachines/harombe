# Human-in-the-Loop (HITL) Gates - Phase 4.5

**Status:** Design Complete
**Implementation:** Phase 4.5
**Dependencies:** Phase 4.1-4.4 (MCP Gateway, Audit Logging)

## Overview

Human-in-the-Loop (HITL) gates provide a safety mechanism that requires explicit user approval before executing potentially dangerous or irreversible operations. This prevents AI agents from performing destructive actions without human oversight.

## Goals

1. **Prevent accidental damage** - Block destructive operations by default
2. **Enable informed decisions** - Show user what will happen before execution
3. **Maintain audit trail** - Log all approval/denial decisions
4. **Flexible configuration** - Per-tool and per-action rules
5. **Timeout safety** - Auto-deny if user doesn't respond

## Architecture

### Request Flow

```
┌─────────────────────────────────────────────────────────┐
│ 1. Agent sends tool call request                        │
│    POST /mcp with {"method": "tools/call", ...}        │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────┐
│ 2. MCP Gateway receives request                         │
│    - Parses tool name and parameters                    │
│    - Checks HITL configuration                          │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────┐
│ 3. HITL Gate checks if approval required                │
│    - Risk classification (low/medium/high/critical)     │
│    - Match against HITL rules                           │
│    - Check if user approval needed                      │
└──────────────────┬──────────────────────────────────────┘
                   │
         ┌─────────┴─────────┐
         │                   │
         ▼                   ▼
    ┌─────────┐         ┌─────────┐
    │ No HITL │         │ HITL    │
    │ Required│         │ Required│
    └────┬────┘         └────┬────┘
         │                   │
         │                   ▼
         │          ┌─────────────────────────┐
         │          │ 4. Prompt user          │
         │          │    - Show operation     │
         │          │    - Show parameters    │
         │          │    - Show risk level    │
         │          │    - Wait for response  │
         │          └────┬────────────────────┘
         │               │
         │               ▼
         │          ┌─────────────────────────┐
         │          │ 5. User decision        │
         │          │    - Approve (y)        │
         │          │    - Deny (n)           │
         │          │    - Timeout (auto-deny)│
         │          └────┬────────────────────┘
         │               │
         │         ┌─────┴─────┐
         │         │           │
         │         ▼           ▼
         │    ┌─────────┐ ┌─────────┐
         │    │Approved │ │ Denied  │
         │    └────┬────┘ └────┬────┘
         │         │           │
         ▼         ▼           ▼
    ┌──────────────────────────────────┐
    │ 6. Log decision to audit trail   │
    │    - Decision (approve/deny)     │
    │    - User who decided            │
    │    - Timestamp                   │
    │    - Reason (if provided)        │
    └──────────────┬───────────────────┘
                   │
         ┌─────────┴─────────┐
         │                   │
         ▼                   ▼
    ┌─────────┐         ┌─────────┐
    │Execute  │         │ Return  │
    │Tool     │         │ Denied  │
    └────┬────┘         └────┬────┘
         │                   │
         ▼                   ▼
    ┌──────────────────────────────────┐
    │ 7. Return result to agent        │
    └──────────────────────────────────┘
```

### Core Components

#### 1. HITLGate

Central class that manages approval requests:

```python
class HITLGate:
    """Manages human-in-the-loop approval for operations."""

    async def check_approval(
        self,
        operation: Operation,
        context: RequestContext
    ) -> ApprovalDecision:
        """Check if operation requires approval and get user decision."""

    async def prompt_user(
        self,
        operation: Operation,
        timeout: int = 60
    ) -> ApprovalDecision:
        """Prompt user for approval with timeout."""

    def classify_risk(
        self,
        operation: Operation
    ) -> RiskLevel:
        """Classify operation risk level."""
```

#### 2. RiskClassifier

Analyzes operations and assigns risk levels:

```python
class RiskLevel(Enum):
    LOW = "low"           # Read-only operations, safe actions
    MEDIUM = "medium"     # Modifications with easy undo
    HIGH = "high"         # Destructive operations, hard to undo
    CRITICAL = "critical" # Irreversible operations, data loss

class RiskClassifier:
    """Classifies operation risk based on rules."""

    def classify(self, operation: Operation) -> RiskLevel:
        """Determine risk level for operation."""

        # Check operation type
        if operation.tool_name == "send_email":
            return RiskLevel.HIGH

        if operation.tool_name == "delete_file":
            # Check if system file
            if is_system_file(operation.params["path"]):
                return RiskLevel.CRITICAL
            return RiskLevel.HIGH

        # Default: low risk
        return RiskLevel.LOW
```

#### 3. ApprovalPrompt

Handles user interaction:

```python
class ApprovalPrompt:
    """Manages user approval prompts."""

    async def prompt_cli(
        self,
        operation: Operation,
        risk_level: RiskLevel,
        timeout: int
    ) -> ApprovalDecision:
        """Show CLI prompt with timeout."""

    async def prompt_api(
        self,
        operation: Operation,
        risk_level: RiskLevel,
        timeout: int
    ) -> ApprovalDecision:
        """Create pending approval for API clients."""
```

#### 4. ApprovalDecision

Result of approval request:

```python
@dataclass
class ApprovalDecision:
    """Result of approval request."""

    decision: Literal["approve", "deny", "timeout"]
    user: str  # Who made the decision
    timestamp: datetime
    reason: Optional[str] = None
    timeout_seconds: Optional[int] = None
```

## Configuration

### HITL Rules

Define which operations require approval:

```yaml
security:
  hitl:
    enabled: true
    default_timeout: 60 # seconds

    # Rules for requiring approval
    rules:
      # Always require approval for these tools
      - tools: [send_email, delete_file, execute_sql]
        risk: high
        require_approval: true
        timeout: 60

      # Require approval for destructive actions
      - tools: [write_file]
        conditions:
          - param: path
            matches: "^/etc/.*|^/sys/.*|^/root/.*"
        risk: critical
        require_approval: true
        timeout: 30

      # No approval for read-only operations
      - tools: [read_file, list_files, web_search]
        risk: low
        require_approval: false
```

### Risk-Based Approval

Configure approval based on risk level:

```yaml
security:
  hitl:
    enabled: true

    # Risk-based policies
    policies:
      low:
        require_approval: false

      medium:
        require_approval: true
        timeout: 120 # 2 minutes
        allow_skip: true # User can choose "always allow"

      high:
        require_approval: true
        timeout: 60
        allow_skip: false

      critical:
        require_approval: true
        timeout: 30
        allow_skip: false
        require_reason: true # Must provide reason
```

## User Experience

### CLI Approval Prompt

```
┌─────────────────────────────────────────────────────────┐
│ [!] APPROVAL REQUIRED                                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ The agent wants to perform a HIGH RISK operation:      │
│                                                         │
│ Tool: send_email                                        │
│ Action: Send email message                             │
│                                                         │
│ Parameters:                                             │
│   to: user@example.com                                  │
│   subject: "Project Update"                             │
│   body: "The project is complete..."                    │
│                                                         │
│ Risk: HIGH - This operation cannot be easily undone    │
│                                                         │
│ [a] Approve  [d] Deny  [v] View full details           │
│                                                         │
│ Auto-deny in 60 seconds...                             │
└─────────────────────────────────────────────────────────┘
```

### API Approval Flow

For API clients (web UI, mobile apps):

1. Gateway returns `202 Accepted` with pending approval ID
2. Client polls `/hitl/pending/{approval_id}` for status
3. User approves/denies via `/hitl/decide/{approval_id}`
4. Original request completes or returns error

```python
# API endpoint
POST /hitl/decide/{approval_id}
{
  "decision": "approve",
  "reason": "Reviewed email, looks good"
}

# Response
{
  "status": "approved",
  "approved_by": "user@example.com",
  "approved_at": "2026-02-09T15:30:45Z"
}
```

## Audit Integration

All HITL decisions are logged to the audit database:

```python
# Audit log entry
{
  "event_type": "hitl_decision",
  "correlation_id": "req-12345",
  "timestamp": "2026-02-09T15:30:45Z",
  "decision": "approve",
  "operation": {
    "tool_name": "send_email",
    "params": {
      "to": "user@example.com",
      "subject": "Project Update"
    }
  },
  "risk_level": "high",
  "user": "admin@example.com",
  "reason": "Reviewed email, looks good",
  "timeout_seconds": 60
}
```

Query approval history:

```bash
# Get all denied operations
harombe audit query --event-type=hitl_decision --filter='decision=deny'

# Get critical operations
harombe audit query --event-type=hitl_decision --filter='risk_level=critical'
```

## Security Considerations

### Default Deny

- **All timeouts result in DENY** - Never auto-approve
- **Unknown operations default to HIGH risk** - Require approval
- **Configuration errors result in DENY** - Fail-safe

### Bypass Prevention

- **No programmatic bypass** - Agent cannot approve itself
- **Audit all decisions** - Even when HITL is disabled
- **Require authentication** - Verify user identity for approvals

### Privilege Escalation

- **Per-user rules** - Some users can approve critical operations
- **Role-based access** - Admin vs. standard user approval rights
- **Approval delegation** - Support approval workflows

## Performance Considerations

### Timeout Handling

- **Non-blocking waits** - Use async/await for timeout
- **Graceful timeout** - Clear error message on timeout
- **Configurable defaults** - Per-operation timeout overrides

### Caching

- **"Always allow" cache** - User can skip future prompts for specific operations
- **Cache expiration** - Clear cache after N hours
- **Per-session cache** - Don't persist across sessions by default

### Rate Limiting

- **Max pending approvals** - Limit to N simultaneous pending approvals
- **Approval queue** - Queue additional requests
- **Request deduplication** - Detect duplicate approval requests

## Implementation Phases

### Phase 1: Core Implementation (Days 1-2)

- [ ] Implement `HITLGate` class
- [ ] Implement `RiskClassifier` with basic rules
- [ ] Implement CLI approval prompt
- [ ] Implement timeout handling
- [ ] Add audit logging integration

### Phase 2: Gateway Integration (Day 3)

- [ ] Add HITL middleware to MCP Gateway
- [ ] Update configuration schema
- [ ] Implement approval decision storage
- [ ] Test with existing tools

### Phase 3: API Support (Day 4)

- [ ] Add API endpoints for pending approvals
- [ ] Add approval decision endpoint
- [ ] Implement polling mechanism
- [ ] Add WebSocket support for real-time updates

### Phase 4: Testing & Documentation (Day 5)

- [ ] Unit tests for HITL gate
- [ ] Integration tests with gateway
- [ ] User documentation
- [ ] Configuration examples
- [ ] Update security docs

## Testing Strategy

### Unit Tests

```python
async def test_approval_required():
    """Test that high-risk operations require approval."""
    gate = HITLGate()
    operation = Operation(tool_name="send_email", params={...})

    decision = await gate.check_approval(operation)
    assert decision.decision == "deny"  # No approval given

async def test_timeout_denies():
    """Test that timeout results in deny."""
    gate = HITLGate(timeout=1)
    operation = Operation(tool_name="delete_file", params={...})

    # Don't provide approval, let it timeout
    decision = await gate.check_approval(operation)
    assert decision.decision == "timeout"

async def test_low_risk_auto_approved():
    """Test that low-risk operations auto-approve."""
    gate = HITLGate()
    operation = Operation(tool_name="read_file", params={...})

    decision = await gate.check_approval(operation)
    assert decision.decision == "approve"
```

### Integration Tests

```python
async def test_gateway_blocks_without_approval():
    """Test that gateway blocks high-risk operations."""
    # Send tool call to gateway
    response = await client.post("/mcp", json={
        "method": "tools/call",
        "params": {
            "name": "send_email",
            "arguments": {...}
        }
    })

    # Should return pending approval
    assert response.status_code == 202
    assert "approval_id" in response.json()

async def test_approval_flow():
    """Test full approval flow."""
    # 1. Submit operation
    response = await client.post("/mcp", json={...})
    approval_id = response.json()["approval_id"]

    # 2. Approve operation
    await client.post(f"/hitl/decide/{approval_id}", json={
        "decision": "approve"
    })

    # 3. Original request should complete
    result = await client.get(f"/hitl/result/{approval_id}")
    assert result.status_code == 200
```

## Future Enhancements

### Phase 4.6+

- **Approval templates** - Pre-configured approval rules
- **Approval workflows** - Multi-level approvals
- **Approval analytics** - Track approval rates, common denials
- **Smart suggestions** - Learn from past decisions
- **Batch approvals** - Approve multiple operations at once

## References

- [Audit Logging](./audit-logging.md) - Audit trail integration
- [MCP Gateway Design](./mcp-gateway-design.md) - Gateway architecture
- [Security Network](./security-network.md) - Network isolation patterns
