# Secret Management System (Phase 4.3)

Comprehensive credential vault integration and secret management for Harombe. Ensures zero secrets reach the LLM context while maintaining secure access to required credentials.

## Table of Contents

1. [Overview](#overview)
2. [Vault Backends](#vault-backends)
3. [Secret Scanning](#secret-scanning)
4. [Environment Injection](#environment-injection)
5. [Configuration Examples](#configuration-examples)
6. [Usage Examples](#usage-examples)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

## Overview

### Why Secret Management Matters

The AI agent needs access to credentials (API keys, tokens, database passwords) to perform tasks. However, passing secrets to an LLM creates severe security risks:

1. **Memory Leakage:** LLMs may inadvertently include secrets in responses
2. **Context Pollution:** Secrets in conversation history could be extracted
3. **Log Exposure:** Credentials logged during debugging
4. **Prompt Injection:** Malicious inputs could trick the LLM into revealing secrets

### Zero Secrets in LLM Context

Harombe's security architecture ensures secrets **never** reach the LLM:

```
┌─────────────┐
│   Vault     │ ◄─── Secrets stored securely
│ (encrypted) │
└──────┬──────┘
       │
       │ Fetch at startup
       ▼
┌─────────────┐
│  Secret     │ ◄─── Inject into container environment
│  Injector   │
└──────┬──────┘
       │
       │ Environment variables
       ▼
┌─────────────┐
│ Capability  │ ◄─── Tools use env vars directly
│ Container   │      (never sent to LLM)
└──────┬──────┘
       │
       │ Tool results only
       ▼
┌─────────────┐
│     LLM     │ ◄─── Receives sanitized output
│   (Harombe) │      (no credential leakage)
└─────────────┘
```

### Architecture Components

1. **Vault Backends:** Store encrypted secrets (HashiCorp Vault, SOPS, or env vars)
2. **Secret Scanner:** Detect and redact secrets before they reach LLM
3. **Environment Injector:** Securely inject secrets into containers at startup
4. **Rotation Scheduler:** Automatically rotate credentials on schedule

## Vault Backends

Harombe supports three secret storage backends, each suited for different deployment scenarios.

### HashiCorp Vault (Production)

**Best for:** Production deployments, teams, enterprise environments

HashiCorp Vault provides enterprise-grade secret management with:

- Dynamic secrets with time-limited leases
- Automatic token renewal
- Audit logging
- Access control policies
- Secret versioning

#### Setup

1. **Install Vault:**

```bash
# macOS
brew install vault

# Linux
wget https://releases.hashicorp.com/vault/1.15.0/vault_1.15.0_linux_amd64.zip
unzip vault_1.15.0_linux_amd64.zip
sudo mv vault /usr/local/bin/
```

2. **Start Vault Server (Development Mode):**

```bash
# Start dev server (DO NOT USE IN PRODUCTION)
vault server -dev

# Output shows root token:
# Root Token: hvs.CAESIJ2UhIXGQ...
```

3. **Set Environment Variables:**

```bash
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='hvs.CAESIJ2UhIXGQ...'
```

4. **Enable KV v2 Secrets Engine:**

```bash
# Enable KV v2 at "secret" path
vault secrets enable -path=secret kv-v2

# Verify
vault secrets list
```

5. **Store Secrets:**

```bash
# Store GitHub token
vault kv put secret/github/token value=ghp_xxxxxxxxxxxxx

# Store Slack webhook
vault kv put secret/slack/webhook value=https://hooks.slack.com/services/T00/B00/xxx

# Store AWS credentials
vault kv put secret/aws/credentials \
  access_key=AKIAIOSFODNN7EXAMPLE \
  secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Store database URL
vault kv put secret/database/url value=postgresql://user:pass@localhost:5432/db
```

6. **Configure Harombe:**

```yaml
# harombe.yaml
security:
  credentials:
    provider: vault
    vault_url: http://127.0.0.1:8200
    vault_namespace: null # Enterprise feature
    mount_point: secret # KV v2 mount point
    auto_renew: true # Auto-renew token
```

#### Production Deployment

For production, use proper Vault setup (NOT dev mode):

```bash
# Create Vault configuration
cat > vault.hcl <<EOF
storage "file" {
  path = "/var/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 0
  tls_cert_file = "/etc/vault/tls/vault.crt"
  tls_key_file  = "/etc/vault/tls/vault.key"
}

ui = true
EOF

# Start Vault
vault server -config=vault.hcl

# Initialize (ONE TIME ONLY - save unseal keys and root token!)
vault operator init

# Unseal (requires threshold number of keys)
vault operator unseal <unseal-key-1>
vault operator unseal <unseal-key-2>
vault operator unseal <unseal-key-3>
```

**CRITICAL:** Store unseal keys and root token securely. Loss means permanent data loss.

#### AppRole Authentication (Recommended for Production)

Instead of using long-lived tokens, use AppRole for automated authentication:

```bash
# Enable AppRole auth
vault auth enable approle

# Create policy
vault policy write harombe - <<EOF
path "secret/data/*" {
  capabilities = ["read"]
}
path "secret/metadata/*" {
  capabilities = ["list"]
}
EOF

# Create AppRole
vault write auth/approle/role/harombe \
  token_policies="harombe" \
  token_ttl=1h \
  token_max_ttl=4h

# Get Role ID and Secret ID
vault read auth/approle/role/harombe/role-id
vault write -f auth/approle/role/harombe/secret-id
```

Use in code:

```python
from harombe.security.vault import HashiCorpVault

# Authenticate with AppRole
vault = HashiCorpVault(
    vault_addr="https://vault.example.com:8200",
    role_id="9e9a...",
    secret_id="5f8c...",
    mount_point="secret"
)

await vault.start()
token = await vault.get_secret("github/token")
```

### SOPS (Simple Deployments)

**Best for:** Small teams, simpler infrastructure, encrypted files in git

SOPS (Secrets OPerationS) encrypts files using age or GPG keys. Simpler than Vault but less feature-rich.

#### Setup

1. **Install SOPS:**

```bash
# macOS
brew install sops age

# Linux
wget https://github.com/getsops/sops/releases/download/v3.8.1/sops-v3.8.1.linux.amd64
sudo mv sops-v3.8.1.linux.amd64 /usr/local/bin/sops
chmod +x /usr/local/bin/sops

# Install age
wget https://github.com/FiloSottile/age/releases/download/v1.1.1/age-v1.1.1-linux-amd64.tar.gz
tar xzf age-v1.1.1-linux-amd64.tar.gz
sudo mv age/age /usr/local/bin/
```

2. **Generate Encryption Key:**

```bash
# Create age key
age-keygen -o ~/.config/sops/age/keys.txt

# Output shows public key:
# Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

3. **Create SOPS Configuration:**

```yaml
# .sops.yaml (in project root)
creation_rules:
  - path_regex: \.enc\.json$
    age: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

4. **Create and Encrypt Secrets File:**

```bash
# Create plaintext secrets
cat > ~/.harombe/secrets.json <<EOF
{
  "github/token": "ghp_xxxxxxxxxxxxx",
  "slack/webhook": "https://hooks.slack.com/services/T00/B00/xxx",
  "aws/access-key": "AKIAIOSFODNN7EXAMPLE",
  "database/url": "postgresql://user:pass@localhost:5432/db"
}
EOF

# Encrypt with SOPS
sops --encrypt ~/.harombe/secrets.json > ~/.harombe/secrets.enc.json

# Delete plaintext
rm ~/.harombe/secrets.json

# Verify encryption (should see encrypted content)
cat ~/.harombe/secrets.enc.json
```

5. **Configure Harombe:**

```yaml
# harombe.yaml
security:
  credentials:
    provider: sops
    secrets_file: ~/.harombe/secrets.enc.json
    key_file: ~/.config/sops/age/keys.txt # Optional, defaults to standard location
```

#### Managing Secrets with SOPS

```bash
# Edit secrets (decrypts, opens editor, re-encrypts)
sops ~/.harombe/secrets.enc.json

# View decrypted secrets
sops --decrypt ~/.harombe/secrets.enc.json

# Add new secret
sops --set '["new/secret"] "value"' ~/.harombe/secrets.enc.json

# Rotate encryption key
sops --rotate --in-place ~/.harombe/secrets.enc.json
```

#### Version Control with SOPS

SOPS-encrypted files can be safely committed to git:

```bash
# Add to git
git add ~/.harombe/secrets.enc.json .sops.yaml
git commit -m "Add encrypted secrets"

# Team members can decrypt with their age key
# (add their public key to .sops.yaml first)
```

### Environment Variables (Development Only)

**Best for:** Local development, testing, quick prototyping

**WARNING:** NOT SECURE for production. Secrets are in plaintext in environment.

#### Setup

1. **Set Environment Variables:**

```bash
# Add to ~/.bashrc or ~/.zshrc
export HAROMBE_SECRET_GITHUB_TOKEN='ghp_xxxxxxxxxxxxx'
export HAROMBE_SECRET_SLACK_WEBHOOK='https://hooks.slack.com/services/T00/B00/xxx'
export HAROMBE_SECRET_AWS_ACCESS_KEY='AKIAIOSFODNN7EXAMPLE'
export HAROMBE_SECRET_DATABASE_URL='postgresql://user:pass@localhost:5432/db'

# Reload shell
source ~/.bashrc
```

2. **Configure Harombe:**

```yaml
# harombe.yaml
security:
  credentials:
    provider: env
    secret_prefix: HAROMBE_SECRET_ # Default prefix
```

#### Convention

Secret keys use slash notation internally: `github/token`

Converted to env var: `HAROMBE_SECRET_GITHUB_TOKEN`

Conversion rules:

- Prefix with `HAROMBE_SECRET_`
- Convert to uppercase
- Replace `/` with `_`

### Backend Comparison

| Feature                | Vault      | SOPS     | Env Vars |
| ---------------------- | ---------- | -------- | -------- |
| **Security**           | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐     |
| **Setup Complexity**   | High       | Medium   | Low      |
| **Dynamic Secrets**    | ✅         | ❌       | ❌       |
| **Auto Rotation**      | ✅         | ❌       | ❌       |
| **Audit Logging**      | ✅         | ❌       | ❌       |
| **Team Collaboration** | ✅         | ✅       | ❌       |
| **Version Control**    | ❌         | ✅       | ❌       |
| **Encryption at Rest** | ✅         | ✅       | ❌       |
| **Production Ready**   | ✅         | ✅       | ❌       |
| **Cost**               | Free (OSS) | Free     | Free     |

**Recommendation:**

- **Production:** HashiCorp Vault
- **Small Teams:** SOPS
- **Development:** Environment Variables

## Secret Scanning

Harombe's secret scanner detects and redacts sensitive information before it reaches the LLM or logs.

### How It Works

Three-layer detection system:

1. **Pattern Matching:** Regex patterns for known secret formats (AWS keys, GitHub tokens, etc.)
2. **Prefix Detection:** Known secret prefixes (`sk-`, `ghp_`, `xoxb-`)
3. **Entropy Analysis:** High-randomness strings that look like secrets

### Detected Secret Types

| Type            | Examples                                      | Confidence |
| --------------- | --------------------------------------------- | ---------- |
| AWS Keys        | `AKIA...` (20 chars)                          | 95%        |
| Azure Keys      | Azure connection strings                      | 95%        |
| GCP Keys        | Service account JSON                          | 95%        |
| GitHub Tokens   | `ghp_`, `gho_`, `ghs_`, `ghr_` (36 chars)     | 95%        |
| Slack Tokens    | `xoxb-`, `xoxa-`, `xoxp-`                     | 95%        |
| Stripe Keys     | `sk_live_`, `rk_live_`                        | 95%        |
| Private Keys    | `-----BEGIN PRIVATE KEY-----`                 | 95%        |
| JWT Tokens      | `eyJ...` (three base64 segments)              | 95%        |
| Database URLs   | `postgresql://user:pass@...`                  | 95%        |
| API Keys        | Generic API key patterns                      | 80%        |
| Passwords       | `password=...` in key-value pairs             | 80%        |
| Generic Secrets | High-entropy strings with `sk-`, `pk-` prefix | 85%        |

### Entropy-Based Detection

High-entropy strings (random-looking) are flagged as potential secrets:

```python
from harombe.security.secrets import SecretScanner

scanner = SecretScanner(
    min_confidence=0.7,
    min_length=16,
    enable_entropy_detection=True
)

# This will be detected (high entropy + length)
text = "API key: 8f7a3b9c2d1e5f6a7b8c9d0e1f2a3b4c5d6e7f8a"
matches = scanner.scan(text)

# Shannon entropy: ~3.8 bits/char (typical for random strings)
# English text: ~1.5 bits/char
# Threshold: 3.5 bits/char
```

### Confidence Scoring

Each detection gets a confidence score (0.0-1.0):

- **0.95:** Regex pattern match (high confidence)
- **0.85:** Known prefix + entropy check
- **0.70-0.80:** Entropy + contextual clues
- **0.50-0.70:** Entropy alone (lower confidence)

Contextual clues boost confidence:

- Keywords nearby: `key`, `token`, `secret`, `password`, `credential`, `auth`, `api`
- Key-value format: `API_KEY=...`

### Alert System

When secrets are detected, the system logs security alerts:

```python
from harombe.security.secrets import SecretScanner

scanner = SecretScanner()

# Scan LLM response
response = "Here's the token: ghp_abcd1234..."
matches = scanner.alert_if_leaked(response, source="llm_response")

# Output:
# [SECURITY ALERT] Potential credential leakage in llm_response:
#   - Type: github_token, Confidence: 0.95
#     Context: ...Here's the token: ghp_abcd1234...
```

In production, alerts integrate with:

- Audit logging system (Phase 4.2)
- Security monitoring (SIEM)
- Incident response automation

### Redaction

Automatically redact secrets from text:

```python
from harombe.security.secrets import SecretScanner

scanner = SecretScanner()

text = """
To authenticate, use:
API_KEY=sk-1234567890abcdef
GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456
"""

redacted = scanner.redact(text, replacement="[REDACTED]")
print(redacted)

# Output:
# To authenticate, use:
# API_KEY=[REDACTED]
# GITHUB_TOKEN=[REDACTED]
```

### Performance

The scanner is optimized for fast scanning:

- **Typical response (1KB):** <10ms
- **Large response (100KB):** <100ms
- **Regex pre-compilation:** Patterns compiled once at initialization
- **Early termination:** Stops after finding high-confidence match

## Environment Injection

Secure pipeline for injecting secrets from vault into container environments.

### How It Works

```
┌─────────────────────────────────────────────┐
│ 1. Container Startup Request                │
│    harombe-gateway starts container         │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ 2. Secret Injector Fetches from Vault      │
│    - Reads secret_mapping from config       │
│    - Fetches each secret from vault backend │
│    - Creates temporary .env file            │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ 3. Secure .env File                         │
│    - Owner-only permissions (0400)          │
│    - Stored in /tmp/harombe-secrets/        │
│    - Container-specific filename            │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ 4. Container Starts with Environment       │
│    - Docker mounts .env file                │
│    - Environment variables injected         │
│    - Tools access via process.env           │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ 5. Cleanup on Container Stop                │
│    - Overwrite .env with random data        │
│    - Delete file                            │
│    - No secrets left on disk                │
└─────────────────────────────────────────────┘
```

### Vault → Container Pipeline

1. **Configuration (harombe.yaml):**

```yaml
security:
  containers:
    browser:
      image: harombe/browser:latest
      secrets:
        GITHUB_TOKEN: github/token
        SLACK_WEBHOOK: slack/webhook

    code_exec:
      image: harombe/code-exec:latest
      secrets:
        AWS_ACCESS_KEY_ID: aws/access-key
        AWS_SECRET_ACCESS_KEY: aws/secret-key
        DATABASE_URL: database/url
```

2. **Secret Mapping:**

Format: `ENV_VAR_NAME: vault/secret/key`

- Left side: Environment variable name in container
- Right side: Vault secret key

3. **Fetching Process:**

```python
from harombe.security.injection import SecretInjector
from harombe.security.vault import create_vault_backend

# Create vault backend
vault = create_vault_backend(provider="vault", vault_addr="http://localhost:8200")

# Create injector
injector = SecretInjector(vault_backend=vault)

# Inject secrets for container
secret_mapping = {
    "GITHUB_TOKEN": "github/token",
    "SLACK_WEBHOOK": "slack/webhook",
}

env_file = await injector.inject_secrets("browser-container", secret_mapping)
# Returns: /tmp/harombe-secrets/browser-container.env
```

4. **Generated .env File:**

```bash
GITHUB_TOKEN="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
SLACK_WEBHOOK="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXX"
```

File permissions: `-r-------- (0400)` (owner read-only)

5. **Docker Integration:**

```python
import docker

client = docker.from_env()

container = client.containers.run(
    "harombe/browser:latest",
    env_file=str(env_file),  # Mount .env file
    detach=True,
    # ... other container options
)
```

6. **Cleanup:**

```python
# When container stops
injector.cleanup("browser-container")

# Overwrites file with random data before deletion (paranoid security)
```

### Secure .env File Handling

Security measures for .env files:

1. **Restricted Permissions:**
   - Owner read-only (0400)
   - Created in protected directory (0700)
   - No group or other access

2. **Temporary Storage:**
   - `/tmp/harombe-secrets/` directory
   - Cleared on system reboot
   - Container-specific filenames

3. **Secure Cleanup:**
   - Overwrite with random data
   - Then delete file
   - Prevents data recovery

4. **No Plaintext in Logs:**
   - .env path logged, not contents
   - Secret values never logged
   - Redaction of any leaked secrets

### Secret Rotation Policies

Automatic secret rotation based on policies:

```python
from harombe.security.injection import SecretRotationScheduler

# Create scheduler
scheduler = SecretRotationScheduler(
    vault_backend=vault,
    injector=injector
)

# Add rotation policies
scheduler.add_policy("github/token", policy="30d")     # Rotate every 30 days
scheduler.add_policy("aws/access-key", policy="90d")   # Rotate every 90 days
scheduler.add_policy("database/url", policy="180d")    # Rotate every 180 days

# Check and rotate (run periodically)
await scheduler.check_and_rotate()
```

Rotation policies:

- `30d`: High-security credentials (API tokens)
- `90d`: Medium-security credentials (service accounts)
- `180d`: Low-security credentials (read-only access)

**Note:** Rotation requires:

1. Generating new credential value
2. Updating in vault
3. Restarting containers with new value
4. Invalidating old credential

### No Secrets in Config Files

**NEVER put secrets in harombe.yaml or other config files:**

❌ **BAD:**

```yaml
security:
  containers:
    browser:
      environment:
        GITHUB_TOKEN: ghp_abcd1234... # NEVER DO THIS
```

✅ **GOOD:**

```yaml
security:
  credentials:
    provider: vault
    vault_url: http://localhost:8200

  containers:
    browser:
      secrets:
        GITHUB_TOKEN: github/token # Reference to vault key
```

Config files should contain:

- References to secrets (vault keys)
- Configuration for vault backend
- No actual credential values

## Configuration Examples

### Example 1: Vault Backend (Production)

```yaml
# harombe.yaml
security:
  enabled: true

  # Vault configuration
  credentials:
    provider: vault
    vault_url: https://vault.company.com:8200
    vault_namespace: engineering # Enterprise feature
    mount_point: secret
    auto_renew: true

  # Container secrets
  containers:
    browser:
      image: harombe/browser:latest
      secrets:
        GITHUB_TOKEN: github/api-token
        JIRA_TOKEN: jira/api-token

    code_exec:
      image: harombe/code-exec:latest
      secrets:
        AWS_ACCESS_KEY_ID: aws/harombe/access-key
        AWS_SECRET_ACCESS_KEY: aws/harombe/secret-key
        DOCKER_REGISTRY_TOKEN: docker/registry-token

    web_search:
      image: harombe/web-search:latest
      secrets:
        SERPER_API_KEY: serper/api-key

  # Audit logging
  audit:
    enabled: true
    database: ~/.harombe/audit.db
    redact_sensitive: true
```

Store secrets in Vault:

```bash
export VAULT_ADDR='https://vault.company.com:8200'
export VAULT_TOKEN='hvs.CAESIJ...'

vault kv put secret/github/api-token value=ghp_xxxxxxxxxxxxx
vault kv put secret/jira/api-token value=jira_xxxxxxxxxxxxx
vault kv put secret/aws/harombe/access-key value=AKIAIOSFODNN7EXAMPLE
vault kv put secret/aws/harombe/secret-key value=wJalrXUtnFEMI...
vault kv put secret/docker/registry-token value=dckr_pat_xxxxx
vault kv put secret/serper/api-key value=xxxxxxxxxxxxx
```

### Example 2: SOPS Backend (Small Team)

```yaml
# harombe.yaml
security:
  enabled: true

  # SOPS configuration
  credentials:
    provider: sops
    secrets_file: ~/.harombe/secrets.enc.json
    key_file: ~/.config/sops/age/keys.txt

  # Container secrets
  containers:
    browser:
      image: harombe/browser:latest
      secrets:
        GITHUB_TOKEN: github/token
        LINEAR_API_KEY: linear/api-key

    filesystem:
      image: harombe/filesystem:latest
      secrets:
        DROPBOX_TOKEN: dropbox/token

    code_exec:
      image: harombe/code-exec:latest
      secrets:
        PYPI_TOKEN: pypi/token
        NPM_TOKEN: npm/token
```

Secrets file (`~/.harombe/secrets.enc.json` - encrypted):

```json
{
  "github/token": "ghp_xxxxxxxxxxxxx",
  "linear/api-key": "lin_api_xxxxxxxxxxxxx",
  "dropbox/token": "sl.xxxxxxxxxxxxx",
  "pypi/token": "pypi-xxxxxxxxxxxxx",
  "npm/token": "npm_xxxxxxxxxxxxx"
}
```

SOPS configuration (`.sops.yaml`):

```yaml
creation_rules:
  - path_regex: \.enc\.json$
    age: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

### Example 3: Environment Variables (Development)

```yaml
# harombe.yaml
security:
  enabled: true

  # Environment variable backend
  credentials:
    provider: env
    secret_prefix: HAROMBE_SECRET_

  # Container secrets
  containers:
    browser:
      image: harombe/browser:latest
      secrets:
        GITHUB_TOKEN: github/token

    code_exec:
      image: harombe/code-exec:latest
      secrets:
        AWS_ACCESS_KEY_ID: aws/access-key
```

Environment variables:

```bash
# ~/.bashrc or ~/.zshrc
export HAROMBE_SECRET_GITHUB_TOKEN='ghp_xxxxxxxxxxxxx'
export HAROMBE_SECRET_AWS_ACCESS_KEY='AKIAIOSFODNN7EXAMPLE'
```

### Example 4: Docker Container Integration

Complete Docker Compose with secrets:

```yaml
# docker-compose.yml
version: "3.8"

services:
  gateway:
    build: ./gateway
    ports:
      - "8100:8100"
    environment:
      VAULT_ADDR: http://vault:8200
      VAULT_TOKEN: ${VAULT_TOKEN}
    depends_on:
      - vault

  vault:
    image: vault:1.15
    ports:
      - "8200:8200"
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: root
      VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
    cap_add:
      - IPC_LOCK

  browser-container:
    build: ./containers/browser
    # Secrets injected at runtime by gateway
    # No secrets in docker-compose.yml

  code-exec-container:
    build: ./containers/code-exec
    # Secrets injected at runtime by gateway
```

### Example 5: Secret Rotation Schedule

```yaml
# harombe.yaml
security:
  credentials:
    provider: vault
    vault_url: http://localhost:8200

  # Rotation policies
  rotation:
    enabled: true
    policies:
      # High-security: Rotate monthly
      - secrets: ["github/token", "slack/webhook"]
        schedule: "30d"

      # Medium-security: Rotate quarterly
      - secrets: ["aws/access-key", "aws/secret-key"]
        schedule: "90d"

      # Low-security: Rotate annually
      - secrets: ["database/url"]
        schedule: "365d"

  # Alert on rotation
  notifications:
    email: security@company.com
    slack_webhook: rotation/slack-webhook
```

## Usage Examples

### Programmatic Usage

#### Basic Vault Operations

```python
from harombe.security.vault import HashiCorpVault

# Initialize Vault client
vault = HashiCorpVault(
    vault_addr="http://localhost:8200",
    vault_token="hvs.CAESIJ...",
    mount_point="secret",
    auto_renew=True
)

# Start (enables token auto-renewal)
await vault.start()

# Get secret
github_token = await vault.get_secret("github/token")
print(f"Token: {github_token}")

# Set secret
await vault.set_secret(
    "new/api-key",
    "sk-xxxxxxxxxxxxx",
    rotation_policy="30d"
)

# List secrets
secrets = await vault.list_secrets(prefix="github/")
print(f"GitHub secrets: {secrets}")

# Delete secret
await vault.delete_secret("old/credential")

# Rotate secret
await vault.rotate_secret("github/token")

# Clean up
await vault.stop()
```

#### Using SOPS Backend

```python
from harombe.security.vault import SOPSBackend

# Initialize SOPS backend
vault = SOPSBackend(
    secrets_file="~/.harombe/secrets.enc.json",
    key_file="~/.config/sops/age/keys.txt"
)

# Get secret (auto-decrypts)
token = await vault.get_secret("github/token")

# Set secret (auto-encrypts)
await vault.set_secret("new/secret", "value")

# List secrets
secrets = await vault.list_secrets()
```

#### Environment Variable Backend

```python
from harombe.security.vault import EnvVarBackend

# Initialize env var backend
vault = EnvVarBackend(prefix="HAROMBE_SECRET_")

# Get secret from HAROMBE_SECRET_GITHUB_TOKEN env var
token = await vault.get_secret("github/token")

# Set secret (runtime only, not persistent)
await vault.set_secret("temp/secret", "value")
```

#### Secret Scanning

```python
from harombe.security.secrets import SecretScanner, SecretType

# Create scanner
scanner = SecretScanner(
    min_confidence=0.7,
    min_length=16,
    enable_entropy_detection=True
)

# Scan text
text = """
Configuration:
GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456
AWS_KEY=AKIAIOSFODNN7EXAMPLE
DATABASE_URL=postgresql://user:pass@localhost:5432/db
"""

matches = scanner.scan(text)

for match in matches:
    print(f"Found {match.type.value}")
    print(f"  Value: {match.value[:10]}...")
    print(f"  Confidence: {match.confidence:.2f}")
    print(f"  Position: {match.start}-{match.end}")
    print(f"  Context: ...{match.context}...")

# Redact secrets
redacted = scanner.redact(text)
print(redacted)

# Alert on leakage
llm_response = "Here's the token: sk-1234567890abcdef"
matches = scanner.alert_if_leaked(llm_response, source="llm")
```

#### Environment Injection

```python
from harombe.security.injection import SecretInjector, create_injector
from harombe.security.vault import create_vault_backend

# Create vault backend
vault = create_vault_backend(
    provider="vault",
    vault_addr="http://localhost:8200",
    vault_token="hvs.CAESIJ..."
)

# Create injector
injector = SecretInjector(
    vault_backend=vault,
    temp_dir="/tmp/harombe-secrets"
)

# Define secret mapping
secret_mapping = {
    "GITHUB_TOKEN": "github/token",
    "SLACK_WEBHOOK": "slack/webhook",
    "AWS_ACCESS_KEY_ID": "aws/access-key",
}

# Inject secrets for container
env_file = await injector.inject_secrets(
    container_name="browser-container",
    secret_mapping=secret_mapping
)

print(f"Created .env file: {env_file}")

# Start container with secrets
import docker
client = docker.from_env()

container = client.containers.run(
    "harombe/browser:latest",
    env_file=str(env_file),
    detach=True,
    name="browser-container"
)

# Later: cleanup when container stops
container.stop()
injector.cleanup("browser-container")
```

#### Secret Rotation

```python
from harombe.security.injection import SecretRotationScheduler
import secrets

# Create scheduler
scheduler = SecretRotationScheduler(
    vault_backend=vault,
    injector=injector
)

# Add policies
scheduler.add_policy("github/token", policy="30d")
scheduler.add_policy("aws/access-key", policy="90d")

# Custom secret generator
def generate_api_key() -> str:
    return f"sk-{secrets.token_urlsafe(32)}"

# Rotate specific secret
await scheduler.rotate_secret(
    "github/token",
    generator=generate_api_key
)

# Periodic rotation check (run in background)
await scheduler.check_and_rotate()
```

#### Secure .env Loading

```python
from harombe.security.injection import DotEnvLoader

# Create loader
loader = DotEnvLoader(warn_on_secrets=True)

# Load .env file
variables = loader.load(
    env_file=".env",
    override=False  # Don't override existing env vars
)

print(f"Loaded {len(variables)} variables")

# Variables are automatically set in os.environ
import os
print(f"GITHUB_TOKEN: {os.getenv('GITHUB_TOKEN')}")
```

### CLI Integration

#### Vault Management Commands

```bash
# Set secret
harombe vault set github/token ghp_xxxxxxxxxxxxx

# Get secret
harombe vault get github/token

# List secrets
harombe vault list
harombe vault list github/

# Delete secret
harombe vault delete old/credential

# Rotate secret
harombe vault rotate github/token

# Import from .env file
harombe vault import .env

# Export to .env file (for backup)
harombe vault export secrets.env
```

#### Secret Scanning Commands

```bash
# Scan file for secrets
harombe secrets scan response.txt

# Scan and redact
harombe secrets redact response.txt --output clean.txt

# Scan directory recursively
harombe secrets scan --recursive ./logs/

# Check git commits for secrets
harombe secrets scan-git --commits 10
```

#### Container Secret Injection

```bash
# Start container with secrets
harombe container start browser \
  --secret GITHUB_TOKEN=github/token \
  --secret SLACK_WEBHOOK=slack/webhook

# Rotate secrets and restart container
harombe container rotate-secrets browser

# List container secrets (keys only, not values)
harombe container secrets browser
```

### Common Patterns

#### Pattern 1: MCP Server with Secrets

```python
from harombe.security.vault import create_vault_backend
from harombe.security.injection import SecretInjector
import docker

async def start_mcp_server_with_secrets(
    container_name: str,
    image: str,
    secrets: dict[str, str]
):
    """Start MCP server container with secrets from vault."""

    # Create vault backend
    vault = create_vault_backend(provider="vault")

    # Create injector
    injector = SecretInjector(vault_backend=vault)

    # Inject secrets
    env_file = await injector.inject_secrets(container_name, secrets)

    # Start container
    client = docker.from_env()
    container = client.containers.run(
        image,
        env_file=str(env_file),
        detach=True,
        name=container_name,
        network="harombe-network",
        cap_drop=["ALL"],
        security_opt=["no-new-privileges"],
    )

    return container

# Usage
container = await start_mcp_server_with_secrets(
    container_name="browser-mcp",
    image="harombe/browser:latest",
    secrets={
        "GITHUB_TOKEN": "github/token",
        "JIRA_TOKEN": "jira/token",
    }
)
```

#### Pattern 2: Secret Scanning Middleware

```python
from harombe.security.secrets import SecretScanner
from typing import Callable

class SecretScanningMiddleware:
    """Middleware to scan LLM responses for secrets."""

    def __init__(self, min_confidence: float = 0.7):
        self.scanner = SecretScanner(min_confidence=min_confidence)

    async def __call__(
        self,
        call_next: Callable,
        request: dict
    ) -> dict:
        # Process request
        response = await call_next(request)

        # Scan response for secrets
        if "content" in response:
            matches = self.scanner.alert_if_leaked(
                response["content"],
                source=f"llm_response_{request.get('id')}"
            )

            # Redact if secrets found
            if matches:
                response["content"] = self.scanner.redact(
                    response["content"]
                )
                response["_secret_detected"] = True

        return response

# Usage in FastAPI
from fastapi import FastAPI

app = FastAPI()

@app.middleware("http")
async def scan_responses(request, call_next):
    middleware = SecretScanningMiddleware()
    return await middleware(call_next, request)
```

#### Pattern 3: Periodic Secret Rotation

```python
import asyncio
from datetime import datetime, timedelta
from harombe.security.injection import SecretRotationScheduler

async def rotation_worker(scheduler: SecretRotationScheduler):
    """Background worker for secret rotation."""

    while True:
        try:
            print(f"[{datetime.now()}] Checking rotation policies...")

            # Check and rotate secrets
            await scheduler.check_and_rotate()

            # Sleep for 1 hour
            await asyncio.sleep(3600)

        except Exception as e:
            print(f"Rotation error: {e}")
            await asyncio.sleep(300)  # Retry in 5 minutes

# Start worker
asyncio.create_task(rotation_worker(scheduler))
```

## Best Practices

### Secret Rotation Frequencies

Recommended rotation schedules based on secret type and sensitivity:

| Secret Type                  | Rotation Frequency | Rationale                            |
| ---------------------------- | ------------------ | ------------------------------------ |
| **API Tokens (Third-party)** | 30 days            | High exposure risk, easy to rotate   |
| **OAuth Refresh Tokens**     | 90 days            | Medium risk, auto-refresh available  |
| **Database Credentials**     | 90-180 days        | Requires coordination, higher impact |
| **Service Account Keys**     | 180 days           | Complex rotation, limited exposure   |
| **TLS Certificates**         | 365 days           | Standard practice, automated renewal |
| **SSH Keys**                 | 180-365 days       | Manual distribution required         |
| **Encryption Keys**          | Never (versioned)  | Use key versioning instead           |

**Emergency Rotation:** Immediately rotate if:

- Credential exposed in logs or code
- Employee departure with access
- Security breach detected
- Suspicious activity observed

### Access Control

#### Principle of Least Privilege

Grant minimum necessary access to secrets:

```bash
# Vault policy for browser container
vault policy write browser-policy - <<EOF
path "secret/data/github/*" {
  capabilities = ["read"]
}
path "secret/data/jira/*" {
  capabilities = ["read"]
}
EOF

# Vault policy for code-exec container
vault policy write code-exec-policy - <<EOF
path "secret/data/aws/*" {
  capabilities = ["read"]
}
path "secret/data/pypi/*" {
  capabilities = ["read"]
}
EOF
```

#### Role-Based Access Control (RBAC)

Organize secrets by environment and team:

```
secret/
├── prod/
│   ├── github/token          # Production GitHub token
│   ├── aws/access-key        # Production AWS key
│   └── database/url          # Production DB
├── staging/
│   ├── github/token          # Staging GitHub token
│   └── database/url          # Staging DB
└── dev/
    └── github/token          # Development token (limited scope)
```

Vault policies per environment:

```bash
# Production (restricted)
vault policy write prod-read-only - <<EOF
path "secret/data/prod/*" {
  capabilities = ["read"]
}
EOF

# Staging (read/write)
vault policy write staging-full - <<EOF
path "secret/data/staging/*" {
  capabilities = ["read", "create", "update"]
}
EOF

# Development (full access)
vault policy write dev-full - <<EOF
path "secret/data/dev/*" {
  capabilities = ["read", "create", "update", "delete"]
}
EOF
```

### Audit Logging Integration

Enable audit logging for all secret access:

```yaml
# harombe.yaml
security:
  audit:
    enabled: true
    database: ~/.harombe/audit.db
    log_events:
      - secret_read
      - secret_write
      - secret_delete
      - secret_rotation
      - vault_authentication
      - injection_start
      - injection_complete
```

Query audit logs:

```python
from harombe.security.audit import AuditLogger

logger = AuditLogger(database="~/.harombe/audit.db")

# Find all secret accesses
events = await logger.query(
    event_types=["secret_read"],
    start_time=datetime.now() - timedelta(days=7)
)

# Find suspicious activity
suspicious = await logger.query(
    event_types=["secret_read"],
    metadata={"confidence": {"$lt": 0.5}}  # Low-confidence access
)

# Generate report
report = await logger.generate_report(
    start_time=datetime.now() - timedelta(days=30),
    group_by="actor"
)
```

### Emergency Procedures

#### Credential Leak Response

When a credential is exposed:

1. **Immediate Containment:**

```bash
# 1. Rotate compromised secret immediately
harombe vault rotate github/token

# 2. Revoke old credential at provider
# (GitHub, AWS, etc.)

# 3. Audit recent access
harombe audit query \
  --event secret_read \
  --secret github/token \
  --since "2024-01-01"

# 4. Check for unauthorized usage
harombe audit query \
  --event tool_call \
  --actor unknown \
  --since "2024-01-01"
```

2. **Impact Assessment:**

```python
from harombe.security.audit import AuditLogger
from datetime import datetime, timedelta

logger = AuditLogger()

# Find all uses of compromised credential
uses = await logger.query(
    event_types=["tool_call"],
    metadata={"secrets_used": {"$contains": "github/token"}},
    start_time=datetime.now() - timedelta(days=7)
)

print(f"Credential used {len(uses)} times in last 7 days")
```

3. **Notification:**

```python
# Alert security team
await send_alert(
    severity="CRITICAL",
    message="GitHub token compromised",
    details={
        "secret": "github/token",
        "exposure_time": datetime.now(),
        "rotation_status": "completed",
        "impact": "medium"
    }
)
```

4. **Post-Incident Review:**
   - How was credential exposed?
   - Update secret scanning rules
   - Improve redaction policies
   - Train team on secret handling

#### Vault Failure Scenarios

**Scenario 1: Vault Unreachable**

```python
from harombe.security.vault import HashiCorpVault

try:
    vault = HashiCorpVault(vault_addr="http://localhost:8200")
    await vault.start()
    token = await vault.get_secret("github/token")
except Exception as e:
    # Fallback to cached secrets or fail-safe mode
    print(f"Vault unavailable: {e}")

    # Option 1: Use cached secrets (if available)
    token = get_cached_secret("github/token")

    # Option 2: Fail gracefully (disable features requiring secrets)
    print("Disabling features requiring GitHub token")

    # Option 3: Use emergency backup (SOPS)
    backup_vault = SOPSBackend(secrets_file="~/.harombe/backup.enc.json")
    token = await backup_vault.get_secret("github/token")
```

**Scenario 2: Token Expiration**

```python
# Enable auto-renewal
vault = HashiCorpVault(
    vault_addr="http://localhost:8200",
    vault_token="hvs.CAESIJ...",
    auto_renew=True  # Automatically renew before expiration
)

await vault.start()  # Starts background renewal task
```

**Scenario 3: Lost Unseal Keys**

Vault sealed and unseal keys lost = **PERMANENT DATA LOSS**

Prevention:

- Store unseal keys in multiple secure locations
- Use Shamir's Secret Sharing (threshold unsealing)
- Document key holders and backup procedures
- Test backup/restore regularly

### Secret Storage Guidelines

**DO:**

- ✅ Store secrets in vault backend (Vault or SOPS)
- ✅ Use descriptive vault keys (`github/api-token`, not `token1`)
- ✅ Document what each secret is for
- ✅ Set rotation policies for each secret
- ✅ Use minimum required permissions
- ✅ Audit secret access regularly
- ✅ Test secret rotation procedures
- ✅ Have emergency backup plan

**DON'T:**

- ❌ Put secrets in config files (`harombe.yaml`)
- ❌ Commit secrets to git
- ❌ Share secrets via Slack/email
- ❌ Use same secret across environments
- ❌ Store secrets in application code
- ❌ Log secret values
- ❌ Reuse secrets across services
- ❌ Ignore rotation policies

### Container Security

When injecting secrets into containers:

```yaml
# docker-compose.yml
services:
  browser-container:
    build: ./containers/browser
    # Secrets injected by gateway, but additional hardening:
    security_opt:
      - no-new-privileges # Prevent privilege escalation
    cap_drop:
      - ALL # Drop all capabilities
    read_only: true # Read-only root filesystem
    tmpfs:
      - /tmp:noexec,nosuid # Temp dir (no execution)
    user: "1000:1000" # Non-root user
```

## Troubleshooting

### Vault Connection Issues

**Problem:** Cannot connect to Vault

```
ValueError: Failed to connect to Vault: Connection refused
```

**Solutions:**

1. **Check Vault is running:**

```bash
# Check Vault status
vault status

# If not running, start Vault
vault server -dev  # Development
# or
systemctl start vault  # Production
```

2. **Verify VAULT_ADDR:**

```bash
echo $VAULT_ADDR
# Should be: http://127.0.0.1:8200 or https://vault.company.com:8200

# Set if missing
export VAULT_ADDR='http://127.0.0.1:8200'
```

3. **Test connection:**

```bash
curl $VAULT_ADDR/v1/sys/health

# Expected response:
# {"initialized":true,"sealed":false,"standby":false,...}
```

4. **Check network connectivity:**

```bash
# From container
docker exec harombe-gateway curl http://host.docker.internal:8200/v1/sys/health

# From Python
python -c "import httpx; print(httpx.get('http://localhost:8200/v1/sys/health'))"
```

**Problem:** Authentication failed

```
ValueError: Vault error: 403 - permission denied
```

**Solutions:**

1. **Verify token:**

```bash
# Check token is set
echo $VAULT_TOKEN

# Verify token is valid
vault token lookup
```

2. **Check token permissions:**

```bash
# See what token can access
vault token capabilities secret/data/github/token

# Should include "read" for get_secret
```

3. **Renew token:**

```bash
vault token renew
```

### SOPS Setup

**Problem:** sops command not found

```
FileNotFoundError: sops binary not found
```

**Solution:**

```bash
# macOS
brew install sops age

# Linux
wget https://github.com/getsops/sops/releases/download/v3.8.1/sops-v3.8.1.linux.amd64
sudo mv sops-v3.8.1.linux.amd64 /usr/local/bin/sops
chmod +x /usr/local/bin/sops

# Verify installation
sops --version
```

**Problem:** Failed to decrypt secrets

```
ValueError: Failed to decrypt secrets with SOPS: no key could decrypt the data
```

**Solutions:**

1. **Check age key exists:**

```bash
ls -la ~/.config/sops/age/keys.txt

# If missing, generate new key
mkdir -p ~/.config/sops/age
age-keygen -o ~/.config/sops/age/keys.txt
```

2. **Verify SOPS configuration:**

```bash
# Check .sops.yaml
cat .sops.yaml

# Should contain your age public key
```

3. **Re-encrypt with correct key:**

```bash
# Get your public key
grep "public key:" ~/.config/sops/age/keys.txt

# Update .sops.yaml with your public key

# Re-encrypt file
sops --rotate --in-place ~/.harombe/secrets.enc.json
```

**Problem:** Secrets not updating

```
# Changed secret in file but code returns old value
```

**Solution:**

```bash
# SOPS caches decrypted secrets. Force reload:
```

```python
from harombe.security.vault import SOPSBackend

vault = SOPSBackend(secrets_file="~/.harombe/secrets.enc.json")
vault._cache_loaded = False  # Force reload
value = await vault.get_secret("github/token")
```

### Permission Problems

**Problem:** Permission denied on .env file

```
PermissionError: [Errno 13] Permission denied: '/tmp/harombe-secrets/container.env'
```

**Solutions:**

1. **Check directory permissions:**

```bash
ls -la /tmp/harombe-secrets/

# Should be: drwx------ (0700)

# Fix if wrong
chmod 700 /tmp/harombe-secrets/
```

2. **Check file ownership:**

```bash
ls -la /tmp/harombe-secrets/container.env

# Should be owned by your user

# Fix if wrong
sudo chown $USER:$USER /tmp/harombe-secrets/container.env
chmod 400 /tmp/harombe-secrets/container.env
```

3. **SELinux issues (Linux):**

```bash
# Check SELinux status
getenforce

# If enforcing, add exception
chcon -t container_file_t /tmp/harombe-secrets/container.env

# Or disable SELinux temporarily
sudo setenforce 0
```

**Problem:** Docker can't read .env file

```
docker: Error response from daemon: unable to read env file
```

**Solution:**

```bash
# Docker needs read access. Change from 0400 to 0440:
chmod 440 /tmp/harombe-secrets/container.env

# Or add docker group read access
chmod 440 /tmp/harombe-secrets/container.env
chgrp docker /tmp/harombe-secrets/container.env
```

### Secret Detection Issues

**Problem:** False positives (detecting non-secrets)

```
[SECURITY WARNING] Potential secret in response: commit_hash=a1b2c3d4...
```

**Solution:**

```python
from harombe.security.secrets import SecretScanner

# Increase confidence threshold
scanner = SecretScanner(
    min_confidence=0.85,  # Higher threshold = fewer false positives
    min_length=20,        # Longer minimum = fewer false positives
    enable_entropy_detection=False  # Disable entropy (most false positives)
)
```

**Problem:** False negatives (missing actual secrets)

**Solution:**

```python
# Lower confidence threshold
scanner = SecretScanner(
    min_confidence=0.6,   # Lower threshold = catch more secrets
    min_length=12,        # Shorter minimum = catch shorter secrets
    enable_entropy_detection=True  # Enable all detection methods
)

# Add custom patterns
import re
from harombe.security.secrets import SecretType

scanner.PATTERNS[SecretType.API_KEY].append(
    re.compile(r"my-custom-api-[a-z0-9]{16}")
)
```

**Problem:** Redaction breaking response format

```
# Original: {"api_key": "sk-1234..."}
# Redacted: {"api_key": "[REDACTED]"}  # Still valid JSON

# Original: API_KEY=sk-1234...
# Redacted: API_KEY=[REDACTED]  # Still valid format
```

Redaction is format-aware, but if you encounter issues:

```python
# Selective redaction
def redact_safely(text: str) -> str:
    scanner = SecretScanner()
    matches = scanner.scan(text)

    # Only redact high-confidence matches
    high_confidence = [m for m in matches if m.confidence > 0.9]

    # Redact with context preservation
    result = text
    for match in sorted(high_confidence, key=lambda m: m.start, reverse=True):
        # Preserve structure (keep first/last chars)
        redacted = match.value[:2] + "[REDACTED]" + match.value[-2:]
        result = result[:match.start] + redacted + result[match.end:]

    return result
```

### Performance Issues

**Problem:** Secret scanning slow

**Solution:**

```python
# Disable entropy detection (slowest part)
scanner = SecretScanner(enable_entropy_detection=False)

# Or use streaming for large texts
def scan_stream(text_stream):
    scanner = SecretScanner()
    chunk_size = 10000

    for chunk in text_stream:
        matches = scanner.scan(chunk)
        if matches:
            yield matches
```

**Problem:** Vault lookups slow

**Solution:**

```python
# Cache secrets in memory
class CachedVault:
    def __init__(self, backend):
        self.backend = backend
        self.cache = {}

    async def get_secret(self, key: str):
        if key not in self.cache:
            self.cache[key] = await self.backend.get_secret(key)
        return self.cache[key]
```

## Additional Resources

- **HashiCorp Vault Documentation:** https://www.vaultproject.io/docs
- **SOPS Documentation:** https://github.com/getsops/sops
- **Age Encryption:** https://age-encryption.org/
- **OWASP Secret Management Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- **Harombe Security Architecture:** [security-phase4.1-foundation.md](./security-phase4.1-foundation.md)
- **Audit Logging:** [audit-logging.md](./audit-logging.md)
- **Phase 4 Implementation Plan:** [phase4-implementation-plan.md](./phases/phase4-implementation-plan.md)

---

**Document Version:** 1.0
**Last Updated:** 2026-02-09
**Related Phase:** 4.3 - Secret Management
