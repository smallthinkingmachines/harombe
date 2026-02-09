# Development Guide

## Prerequisites

- Python 3.11 or higher
- [Ollama](https://ollama.ai) installed and running
- Git

## Development Environment Setup

### Standard Setup (Recommended for most users)

```bash
# Clone the repository
git clone https://github.com/smallthinkingmachines/harombe.git
cd harombe

# Create a virtual environment
python -m venv .venv

# Activate virtual environment
# On macOS/Linux:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Verify installation
pytest tests/test_config.py
```

### Alternative: Using Nix Flakes (Optional)

If you use Nix, you can get a reproducible development environment:

```bash
# Enter development shell (automatically sets up everything)
nix develop
```

This provides Python, Ollama, and all dev dependencies pre-configured.

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

We use automated tools to maintain code quality:

```bash
# Using Makefile (recommended)
make format      # Auto-format code
make lint        # Run linting checks
make type-check  # Run type checking
make test        # Run tests
make ci          # Run all checks (lint + type-check + test)

# Or run tools directly
ruff format .           # Format code
ruff check . --fix      # Lint and auto-fix
mypy src/harombe        # Type checking
pytest                  # Run tests
```

**Pre-commit hooks** automatically run these checks before each commit:

- Code formatting (ruff format)
- Linting (ruff check)
- Type checking (mypy)
- Trailing whitespace, file endings, YAML validation

To run pre-commit hooks manually:

```bash
make pre-commit-run
# Or directly:
pre-commit run --all-files
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
   source .venv/bin/activate  # or: nix develop
   ```

2. Make your changes

3. Run quality checks:

   ```bash
   make ci  # Runs lint, type-check, and test
   ```

4. Commit (pre-commit hooks run automatically):
   ```bash
   git add .
   git commit -m "description"
   ```

If pre-commit hooks fail, fix the issues and commit again. The hooks will:

- Auto-format your code
- Check for common issues
- Run type checking
- Validate YAML/TOML files

### Adding Dependencies

Edit `pyproject.toml` and add to the appropriate section:

- `dependencies`: Runtime dependencies
- `[project.optional-dependencies] dev`: Development dependencies

Then reinstall:

```bash
pip install -e ".[dev]"
```

### Troubleshooting

**"Command not found"**: Make sure your virtual environment is activated

**Import errors**: Reinstall package: `pip install -e ".[dev]"`

**Ollama not found**:

- Install Ollama from https://ollama.ai
- Start the server: `ollama serve`
- Verify: `curl http://localhost:11434/api/tags`

**Tests failing**:

- Check that Ollama is running
- Pull a test model: `ollama pull llama3.2:3b`
- Run specific tests: `pytest tests/test_config.py -v`

**Python version issues**: harombe requires Python 3.11+

- Check version: `python --version`
- Consider using [pyenv](https://github.com/pyenv/pyenv) to manage Python versions

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `pytest`
5. Format code: `ruff format .`
6. Lint code: `ruff check .`
7. Commit: `git commit -m "description"`
8. Push: `git push origin feature/your-feature`
9. Create a Pull Request

### Development Workflow

**Quick reference:**

```bash
make help         # Show all available commands
make dev-install  # Install with dev deps + pre-commit hooks
make format       # Auto-format code
make lint         # Check code quality
make type-check   # Check types
make test         # Run tests
make test-cov     # Run tests with coverage
make ci           # Run all checks (what CI runs)
make clean        # Clean up generated files
```

**Before committing:**
Pre-commit hooks run automatically, but you can also run manually:

```bash
make ci  # Run all checks
```

**Running the development version:**

```bash
# Interactive chat
python -m harombe chat

# Start API server
python -m harombe start

# Cluster commands
python -m harombe cluster status
```
