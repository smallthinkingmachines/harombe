# Reference Architecture: Secure Code Analysis Team

A 3-agent setup for automated code review with security scanning.

## Overview

This architecture uses multi-agent delegation to split code review into specialized tasks: a lead reviewer triages incoming requests, a security scanner checks for vulnerabilities, and a code quality agent analyzes style and correctness.

## Hardware Requirements

| Role        | Machine         | Model           | Purpose                |
| ----------- | --------------- | --------------- | ---------------------- |
| Coordinator | Any (laptop OK) | —               | Routes tasks, runs CLI |
| Inference   | 32 GB+ RAM      | `codellama:34b` | Code analysis          |
| Lightweight | 16 GB RAM       | `codellama:7b`  | Quick checks           |

A single machine with 32 GB RAM can run all three agents locally.

## Architecture

```
┌───────────────────────────────────┐
│  harombe chat / REST API          │
│  ┌─────────────────────────────┐  │
│  │  lead_reviewer (root agent) │  │
│  │  Triages and delegates      │  │
│  └──────┬───────────┬──────────┘  │
│         │           │             │
│    ┌────▼────┐ ┌────▼──────────┐  │
│    │security │ │ code_quality  │  │
│    │_scanner │ │ _reviewer     │  │
│    └─────────┘ └───────────────┘  │
└───────────────────────────────────┘
```

## Configuration

```yaml
# harombe.yaml

model:
  name: codellama:34b

tools:
  shell: true
  filesystem: true
  web_search: false
  confirm_dangerous: true

delegation:
  enabled: true
  max_depth: 2

agents:
  - name: security_scanner
    description: "Scans code for security vulnerabilities (OWASP top 10, injection, XSS, secrets)"
    system_prompt: |
      You are a security-focused code reviewer. Analyze code for:
      - Injection vulnerabilities (SQL, command, XSS)
      - Authentication and authorization flaws
      - Hardcoded secrets or credentials
      - Insecure cryptographic practices
      - OWASP Top 10 issues
      Report findings with severity (critical/high/medium/low), affected lines, and remediation.
    tools:
      shell: false
      filesystem: true
      web_search: false
    max_steps: 15

  - name: code_quality_reviewer
    description: "Reviews code for quality, correctness, style, and maintainability"
    system_prompt: |
      You are a code quality reviewer. Analyze code for:
      - Logic errors and edge cases
      - Code style and consistency
      - Performance issues
      - Missing error handling
      - Test coverage gaps
      Provide specific, actionable feedback with line references.
    tools:
      shell: true
      filesystem: true
      web_search: false
    max_steps: 15

agent:
  system_prompt: |
    You are a lead code reviewer. When asked to review code:
    1. Read the file(s) to understand the scope
    2. Delegate security analysis to security_scanner
    3. Delegate quality review to code_quality_reviewer
    4. Synthesize both reports into a unified review
  max_steps: 20

security:
  hitl:
    enabled: true
    always_confirm:
      - shell
```

## Usage

```bash
# Start interactive review
harombe chat

# Example prompt
You> Review the authentication module in src/auth/ for security and quality issues
```

## Security Considerations

- Shell tool is enabled for running linters but requires HITL confirmation
- Web search is disabled to prevent data exfiltration
- Filesystem access is read-only for child agents (security_scanner has `shell: false`)
- All tool calls are audit-logged
