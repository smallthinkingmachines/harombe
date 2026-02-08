# Development Guide

## Development Environment

harombe uses Nix flakes for reproducible development environments.

### Quick Start

```bash
# Enter development shell (with all dependencies)
nix develop

# This automatically:
# - Creates a Python virtual environment in .venv
# - Installs harombe in editable mode
# - Installs all dev dependencies (pytest, ruff, mypy)
# - Makes Ollama available
```

Inside the `nix develop` shell, you have:
- Python 3.14.3 with venv activated
- All dependencies from `pyproject.toml`
- Development tools: pytest, ruff, mypy
- Ollama for local inference

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_config.py

# Run with coverage
pytest --cov=src/harombe --cov-report=html

# Run with verbose output
pytest -v
```

### Code Quality

```bash
# Format code
ruff format .

# Lint code
ruff check .

# Type checking
mypy src/
```

### Project Structure

```
harombe/
├── src/harombe/          # Main package
│   ├── cli/              # CLI commands
│   ├── agent/            # ReAct agent loop
│   ├── llm/              # LLM client implementations
│   ├── tools/            # Tool registry and implementations
│   ├── config/           # Configuration management
│   ├── coordination/     # Cluster coordination (Phase 1)
│   ├── server/           # REST API server
│   └── hardware/         # Hardware detection
├── tests/                # Test suite
├── flake.nix            # Nix development environment
└── pyproject.toml       # Package configuration
```

### Making Changes

1. Enter development environment:
   ```bash
   nix develop
   ```

2. Make your changes

3. Run tests:
   ```bash
   pytest
   ```

4. Format and lint:
   ```bash
   ruff format .
   ruff check .
   ```

5. Commit:
   ```bash
   git add .
   git commit -m "description"
   ```

### Adding Dependencies

Edit `pyproject.toml` and add to the appropriate section:
- `dependencies`: Runtime dependencies
- `[project.optional-dependencies] dev`: Development dependencies

Then reinstall:
```bash
pip install -e ".[dev]"
```

### Troubleshooting

**"Command not found"**: Make sure you're in `nix develop` shell

**Import errors**: Reinstall package: `pip install -e ".[dev]"`

**Ollama not found**: Make sure Ollama is running: `ollama serve`

**Tests failing**: Check that Ollama has the required models: `ollama list`
