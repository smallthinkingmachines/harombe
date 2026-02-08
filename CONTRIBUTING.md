# Contributing to harombe

Thank you for your interest in contributing to harombe!

## Getting Started

### Prerequisites

- Python 3.11+
- [Ollama](https://ollama.ai)
- Git

### Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/harombe.git
cd harombe

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Run tests to verify setup
pytest
```

## Development Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write clear, documented code
   - Follow existing code style
   - Add tests for new functionality

3. **Test your changes**
   ```bash
   # Run all tests
   pytest
   
   # Run specific tests
   pytest tests/test_your_feature.py -v
   
   # Check coverage
   pytest --cov=src/harombe
   ```

4. **Format and lint**
   ```bash
   # Auto-format code
   ruff format .
   
   # Check for issues
   ruff check .
   ```

5. **Commit with clear messages**
   ```bash
   git commit -m "feat: add new feature description"
   ```

   Use conventional commit prefixes:
   - `feat:` - New features
   - `fix:` - Bug fixes
   - `docs:` - Documentation changes
   - `test:` - Test additions or changes
   - `refactor:` - Code refactoring
   - `chore:` - Maintenance tasks

6. **Push and create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then open a Pull Request on GitHub.

## Code Style

- Follow PEP 8 guidelines
- Use type hints where possible
- Write docstrings for public functions and classes
- Keep functions focused and reasonably sized
- Use descriptive variable and function names

## Testing Guidelines

- Write tests for new features
- Maintain or improve test coverage
- Use pytest fixtures for common setup
- Mock external dependencies (Ollama, network calls)
- Test both success and error cases

Example test structure:
```python
def test_feature_name():
    """Test that feature does what it should."""
    # Arrange
    input_data = ...
    
    # Act
    result = your_function(input_data)
    
    # Assert
    assert result == expected_value
```

## Project Structure

```
harombe/
├── src/harombe/          # Main package
│   ├── cli/              # CLI commands
│   ├── agent/            # ReAct agent loop
│   ├── llm/              # LLM clients
│   ├── tools/            # Tool implementations
│   ├── config/           # Configuration
│   ├── coordination/     # Cluster management
│   ├── server/           # REST API
│   └── hardware/         # Hardware detection
├── tests/                # Test suite
│   ├── test_agent.py
│   ├── test_cluster.py
│   └── ...
├── DEVELOPMENT.md        # Development guide
└── pyproject.toml        # Package config
```

## What to Contribute

### Good First Issues

- Documentation improvements
- Additional tests
- Bug fixes
- Example configurations
- Tool implementations

### Bigger Projects

- Phase 1.2: mDNS discovery implementation
- Phase 1.3: Task complexity classification
- New LLM backend integrations (vLLM, llama.cpp)
- Additional tool implementations

## Pull Request Guidelines

- Keep PRs focused on a single feature/fix
- Include tests for new functionality
- Update documentation as needed
- Ensure all tests pass
- Add a clear description of changes
- Reference related issues if applicable

## Need Help?

- Check [DEVELOPMENT.md](DEVELOPMENT.md) for setup details
- Open a [Discussion](https://github.com/smallthinkingmachines/harombe/discussions) for questions
- Report bugs via [Issues](https://github.com/smallthinkingmachines/harombe/issues)

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
