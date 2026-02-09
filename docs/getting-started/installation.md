# Installation

This guide will help you install Harombe on your system.

## Prerequisites

### System Requirements

**Minimum**:

- CPU: 4 cores
- RAM: 8GB
- Disk: 20GB free space
- OS: Linux, macOS, or Windows (WSL2)

**Recommended**:

- CPU: 8+ cores
- RAM: 16GB+
- Disk: 50GB+ SSD
- OS: Linux (Ubuntu 22.04+ or similar)

### Software Requirements

- **Python**: 3.11, 3.12, or 3.13 (3.14+ not compatible with ChromaDB)
- **Git**: For cloning the repository
- **Docker**: Optional, for sandboxing (Phase 4+)
- **HashiCorp Vault**: Optional, for credential management (Phase 4+)

## Installation Methods

### Method 1: Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/smallthinkingmachines/harombe.git
cd harombe

# Install with pip
pip install -e ".[dev]"

# Verify installation
harombe --version
```

### Method 2: Using Nix (Development)

If you have Nix with flakes enabled:

```bash
# Clone the repository
git clone https://github.com/smallthinkingmachines/harombe.git
cd harombe

# Enter development shell
nix develop

# The environment will automatically:
# - Create a Python virtual environment
# - Install harombe in editable mode
# - Install all development dependencies
# - Setup pre-commit hooks
```

### Method 3: Manual Install

```bash
# Clone the repository
git clone https://github.com/smallthinkingmachines/harombe.git
cd harombe

# Create virtual environment
python3.12 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Upgrade pip
pip install --upgrade pip

# Install harombe
pip install -e ".[dev]"
```

## Optional Components

### Docker (for Sandboxing)

Required for Phase 4 security features (code sandboxing).

**Linux**:

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER

# Verify
docker --version
```

**macOS**:

```bash
# Install Docker Desktop
brew install --cask docker

# Start Docker Desktop
open -a Docker

# Verify
docker --version
```

### gVisor (for Enhanced Sandboxing)

Required for production-grade code isolation.

```bash
# Download gVisor
(
  set -e
  ARCH=$(uname -m)
  URL=https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}
  wget ${URL}/runsc ${URL}/runsc.sha512
  sha512sum -c runsc.sha512
  rm -f runsc.sha512
  chmod a+rx runsc
  sudo mv runsc /usr/local/bin
)

# Configure Docker to use gVisor
sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc"
    }
  }
}
EOF

sudo systemctl restart docker

# Verify
docker run --rm --runtime=runsc hello-world
```

### HashiCorp Vault (for Credential Management)

Required for Phase 4 security features (credential management).

**Linux**:

```bash
# Install Vault
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault

# Verify
vault --version
```

**macOS**:

```bash
# Install Vault
brew tap hashicorp/tap
brew install hashicorp/tap/vault

# Verify
vault --version
```

## Configuration

### Basic Configuration

Create a `.env` file in the project root:

```bash
# Copy example configuration
cp .env.example .env

# Edit with your settings
nano .env
```

Required environment variables:

```bash
# API Keys
ANTHROPIC_API_KEY=sk-ant-...  # Required for Claude
OPENAI_API_KEY=sk-...         # Optional for embeddings

# Application
ENVIRONMENT=development
LOG_LEVEL=INFO

# Memory (Optional)
CHROMA_PERSIST_DIR=./data/chroma
```

### Advanced Configuration

For production deployments, see the [Production Deployment Guide](../production-deployment-guide.md).

## Verify Installation

Run the test suite to verify everything is working:

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/agent/          # Agent tests
pytest tests/memory/         # Memory tests
pytest tests/security/       # Security tests

# Run with coverage
pytest --cov=harombe --cov-report=term-missing
```

## Next Steps

- [Quick Start Guide](quickstart.md) - Start using Harombe
- [Configuration](configuration.md) - Detailed configuration options
- [Development Setup](../DEVELOPMENT.md) - Set up for development

## Troubleshooting

### Import Errors

If you see import errors:

```bash
# Reinstall in editable mode
pip install -e ".[dev]"
```

### ChromaDB Installation Issues

ChromaDB requires Python 3.11-3.13 (not 3.14+):

```bash
# Check Python version
python --version

# Use compatible version
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Docker Permission Issues

If you see Docker permission errors:

```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Log out and back in, or:
newgrp docker
```

## Getting Help

- **Documentation**: [Read the docs](https://smallthinkingmachines.github.io/harombe/)
- **GitHub Issues**: [Report a bug](https://github.com/smallthinkingmachines/harombe/issues)
- **Contributing**: [Contributing guide](../CONTRIBUTING.md)
