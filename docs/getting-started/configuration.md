# Configuration

This guide covers all configuration options for Harombe.

## Configuration Methods

Harombe can be configured in three ways:

1. **Environment Variables** (`.env` file)
2. **Configuration File** (`harombe.yaml`)
3. **Programmatic Configuration** (Python code)

## Environment Variables

Create a `.env` file in your project root:

```bash
# API Keys
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GITHUB_TOKEN=ghp_...

# Application
ENVIRONMENT=production
LOG_LEVEL=INFO
DEBUG=false

# Vault (Credential Management)
VAULT_ADDR=http://127.0.0.1:8200
VAULT_TOKEN=your-vault-token
VAULT_MOUNT_POINT=kv

# Sandbox (Code Execution)
ENABLE_SANDBOXING=true
SANDBOX_RUNTIME=runsc
SANDBOX_MEMORY_LIMIT=2g
SANDBOX_CPU_LIMIT=2.0
SANDBOX_TIMEOUT=300

# Network Security
EGRESS_MODE=allowlist
ALLOWED_DOMAINS=api.anthropic.com,api.openai.com,api.github.com
BLOCK_PRIVATE_IPS=true

# Audit Logging
AUDIT_DB_PATH=./data/audit.db
AUDIT_RETENTION_DAYS=90

# HITL (Human-in-the-Loop)
HITL_HIGH_RISK_TOOLS=execute_code,file_write,git_push
HITL_APPROVAL_TIMEOUT=300

# Memory/RAG
CHROMA_PERSIST_DIR=./data/memory
EMBEDDING_MODEL=text-embedding-3-small
```

## Configuration File

Create `harombe.yaml`:

```yaml
# Agent Configuration
agent:
  name: harombe
  model: claude-sonnet-4-5-20250929
  max_iterations: 10
  temperature: 0.7
  max_tokens: 4096

# Memory Configuration
memory:
  enabled: true
  collection_name: harombe_memory
  persist_directory: ./data/memory
  embedding_model: text-embedding-3-small
  max_results: 5

# Security Configuration
security:
  # Sandboxing
  sandbox:
    enabled: true
    runtime: runsc # or 'runc' for standard Docker
    memory_limit: 2g
    cpu_limit: 2.0
    timeout: 300 # seconds
    user: nobody
    readonly_root: true

  # Network Security
  network:
    egress_mode: allowlist # or 'denylist' or 'disabled'
    allowed_domains:
      - api.anthropic.com
      - api.openai.com
      - api.github.com
      - "*.huggingface.co"
    block_private_ips: true
    dns_timeout: 5

  # Credential Management
  vault:
    enabled: true
    address: http://127.0.0.1:8200
    mount_point: kv
    token_ttl: 3600

  # Audit Logging
  audit:
    enabled: true
    db_path: ./data/audit.db
    retention_days: 90
    wal_mode: true

  # HITL (Human-in-the-Loop)
  hitl:
    enabled: true
    high_risk_tools:
      - execute_code
      - file_write
      - file_delete
      - git_push
      - network_request
    approval_timeout: 300
    auto_approve_low_risk: true

# Logging Configuration
logging:
  level: INFO # DEBUG, INFO, WARNING, ERROR, CRITICAL
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: ./logs/harombe.log
  max_bytes: 10485760 # 10MB
  backup_count: 5

# Tool Configuration
tools:
  enabled:
    - execute_code
    - file_read
    - file_write
    - web_search
    - http_request
  disabled:
    - dangerous_tool

# Voice Configuration (Optional)
voice:
  enabled: false
  stt_model: large-v3
  tts_model: piper
  push_to_talk_key: space
```

Load configuration in Python:

```python
from harombe.config import Config

config = Config.from_yaml("harombe.yaml")
```

## Programmatic Configuration

Configure directly in Python code:

```python
from harombe.agent.config import AgentConfig
from harombe.security.sandbox import SandboxConfig
from harombe.security.network import NetworkConfig
from harombe.security.hitl import HITLConfig

# Agent configuration
agent_config = AgentConfig(
    name="my_agent",
    model="claude-sonnet-4-5-20250929",
    max_iterations=10,
    temperature=0.7,
)

# Sandbox configuration
sandbox_config = SandboxConfig(
    runtime="runsc",
    memory_limit="2g",
    cpu_limit=2.0,
    timeout=300,
)

# Network configuration
network_config = NetworkConfig(
    egress_mode="allowlist",
    allowed_domains=[
        "api.anthropic.com",
        "api.openai.com",
    ],
    block_private_ips=True,
)

# HITL configuration
hitl_config = HITLConfig(
    high_risk_tools=[
        "execute_code",
        "file_write",
        "git_push",
    ],
    approval_timeout=300,
)
```

## Configuration Reference

### Agent Settings

| Setting          | Type   | Default                        | Description              |
| ---------------- | ------ | ------------------------------ | ------------------------ |
| `name`           | string | `"harombe"`                    | Agent name               |
| `model`          | string | `"claude-sonnet-4-5-20250929"` | LLM model to use         |
| `max_iterations` | int    | `10`                           | Max reasoning iterations |
| `temperature`    | float  | `0.7`                          | LLM temperature (0-1)    |
| `max_tokens`     | int    | `4096`                         | Max tokens per response  |

### Memory Settings

| Setting             | Type    | Default                    | Description              |
| ------------------- | ------- | -------------------------- | ------------------------ |
| `enabled`           | boolean | `true`                     | Enable semantic memory   |
| `collection_name`   | string  | `"harombe_memory"`         | ChromaDB collection name |
| `persist_directory` | string  | `"./data/memory"`          | Storage directory        |
| `embedding_model`   | string  | `"text-embedding-3-small"` | Embedding model          |
| `max_results`       | int     | `5`                        | Max search results       |

### Security Settings

#### Sandbox

| Setting        | Type    | Default   | Description                 |
| -------------- | ------- | --------- | --------------------------- |
| `enabled`      | boolean | `true`    | Enable sandboxing           |
| `runtime`      | string  | `"runsc"` | Container runtime           |
| `memory_limit` | string  | `"2g"`    | Memory limit                |
| `cpu_limit`    | float   | `2.0`     | CPU limit (cores)           |
| `timeout`      | int     | `300`     | Execution timeout (seconds) |

#### Network

| Setting             | Type    | Default       | Description                |
| ------------------- | ------- | ------------- | -------------------------- |
| `egress_mode`       | string  | `"allowlist"` | Egress filtering mode      |
| `allowed_domains`   | list    | `[]`          | Allowed domains            |
| `block_private_ips` | boolean | `true`        | Block RFC1918 addresses    |
| `dns_timeout`       | int     | `5`           | DNS resolution timeout (s) |

#### Vault

| Setting       | Type    | Default                   | Description          |
| ------------- | ------- | ------------------------- | -------------------- |
| `enabled`     | boolean | `false`                   | Enable Vault         |
| `address`     | string  | `"http://127.0.0.1:8200"` | Vault server address |
| `mount_point` | string  | `"kv"`                    | KV mount point       |
| `token_ttl`   | int     | `3600`                    | Token TTL (seconds)  |

#### Audit

| Setting          | Type    | Default             | Description          |
| ---------------- | ------- | ------------------- | -------------------- |
| `enabled`        | boolean | `true`              | Enable audit logging |
| `db_path`        | string  | `"./data/audit.db"` | SQLite database path |
| `retention_days` | int     | `90`                | Log retention (days) |
| `wal_mode`       | boolean | `true`              | Enable WAL mode      |

#### HITL

| Setting                 | Type    | Default | Description                |
| ----------------------- | ------- | ------- | -------------------------- |
| `enabled`               | boolean | `true`  | Enable HITL gates          |
| `high_risk_tools`       | list    | `[]`    | Tools requiring approval   |
| `approval_timeout`      | int     | `300`   | Approval timeout (seconds) |
| `auto_approve_low_risk` | boolean | `false` | Auto-approve low-risk ops  |

## Environment-Specific Configuration

### Development

```bash
# .env.development
ENVIRONMENT=development
LOG_LEVEL=DEBUG
DEBUG=true
ENABLE_SANDBOXING=false
HITL_AUTO_APPROVE_LOW_RISK=true
```

### Staging

```bash
# .env.staging
ENVIRONMENT=staging
LOG_LEVEL=INFO
DEBUG=false
ENABLE_SANDBOXING=true
SANDBOX_RUNTIME=runsc
HITL_AUTO_APPROVE_LOW_RISK=true
```

### Production

```bash
# .env.production
ENVIRONMENT=production
LOG_LEVEL=WARNING
DEBUG=false
ENABLE_SANDBOXING=true
SANDBOX_RUNTIME=runsc
VAULT_ADDR=https://vault.production.internal:8200
EGRESS_MODE=allowlist
HITL_AUTO_APPROVE_LOW_RISK=false
```

## Best Practices

### 1. Use Vault for Secrets

❌ **Don't**:

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-actual-key-here
GITHUB_TOKEN=ghp_actual-token-here
```

✅ **Do**:

```bash
# .env
VAULT_ADDR=https://vault.internal:8200
VAULT_TOKEN=s.abc123

# Store secrets in Vault
vault kv put secret/harombe/api \
  anthropic_api_key="sk-ant-..." \
  github_token="ghp_..."
```

### 2. Enable All Security Features in Production

```yaml
security:
  sandbox:
    enabled: true
    runtime: runsc
  network:
    egress_mode: allowlist
  vault:
    enabled: true
  audit:
    enabled: true
  hitl:
    enabled: true
```

### 3. Use Separate Configurations per Environment

```
config/
├── development.yaml
├── staging.yaml
└── production.yaml
```

### 4. Validate Configuration on Startup

```python
from harombe.config import Config

# Load and validate
config = Config.from_yaml("harombe.yaml")
config.validate()  # Raises error if invalid
```

## Next Steps

- [Quick Start](quickstart.md) - Start using Harombe
- [Security Guide](../security-quickstart.md) - Configure security features
- [Production Deployment](../production-deployment-guide.md) - Deploy to production
