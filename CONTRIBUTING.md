# Contributing to harombe

Thank you for your interest in contributing to harombe! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Bugs

Before creating a bug report:
- Check the [issue tracker](https://github.com/smallthinkingmachines/harombe/issues) for existing reports
- Verify you're using the latest version
- Collect relevant information (OS, Python version, harombe version, steps to reproduce)

Create a detailed bug report including:
- Clear title and description
- Steps to reproduce
- Expected vs actual behavior
- Error messages and stack traces
- System information

### Suggesting Features

Feature suggestions are welcome! Please:
- Check existing issues and discussions first
- Explain the use case and motivation
- Describe the proposed solution
- Consider backward compatibility

### Pull Requests

1. **Fork and clone** the repository
2. **Set up your environment**:
   ```bash
   cd harombe
   python -m venv .venv
   source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows
   pip install -e ".[dev]"
   ```

3. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make your changes**:
   - Write clear, self-documenting code
   - Add type hints for all function parameters and returns
   - Follow existing code style (ruff will check this)
   - Add docstrings for public APIs

5. **Write tests**:
   - Add tests for new functionality
   - Ensure existing tests pass: `pytest`
   - Aim for high coverage of new code

6. **Run quality checks**:
   ```bash
   # Format and lint
   ruff check src tests

   # Type check
   mypy src

   # Run tests
   pytest -v --cov=harombe
   ```

7. **Commit your changes**:
   - Use clear, descriptive commit messages
   - Reference issue numbers when applicable
   - Keep commits focused and atomic

8. **Push and create a PR**:
   ```bash
   git push origin feature/your-feature-name
   ```
   - Fill out the PR template
   - Link related issues
   - Describe your changes clearly

## Development Guidelines

### Code Style

- Follow PEP 8 (enforced by ruff)
- Use type hints throughout
- Maximum line length: 100 characters
- Prefer explicit over implicit
- Keep functions focused and small

### Testing

- Write tests for all new features
- Use mocks for external dependencies (Ollama, file system when appropriate)
- Test edge cases and error conditions
- Keep tests fast and deterministic

### Documentation

- Add docstrings to all public functions, classes, and modules
- Update README.md for user-facing changes
- Add inline comments for complex logic
- Update type hints when changing signatures

### Tool Development

To add a new tool:

```python
from harombe.tools.registry import tool

@tool(description="Your tool description", dangerous=False)
async def your_tool(param: str, optional: int = 10) -> str:
    """Brief description.

    Args:
        param: Description of param
        optional: Description of optional parameter

    Returns:
        Description of return value
    """
    # Implementation
    return "result"
```

The decorator automatically:
- Generates JSON Schema from type hints
- Registers the tool globally
- Extracts parameter descriptions from docstring

### Commit Message Format

```
type: brief description (50 chars or less)

More detailed explanation if needed (wrap at 72 chars).
Include motivation, context, and impact.

Fixes #123
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`

## Project Structure

```
harombe/
├── src/harombe/          # Main package
│   ├── agent/           # ReAct agent loop
│   ├── cli/             # CLI commands
│   ├── config/          # Configuration system
│   ├── llm/             # LLM client implementations
│   ├── tools/           # Tool system and built-in tools
│   ├── server/          # FastAPI server
│   └── hardware/        # Hardware detection
└── tests/               # Test suite
```

## Getting Help

- [GitHub Discussions](https://github.com/smallthinkingmachines/harombe/discussions) - Questions and discussions
- [GitHub Issues](https://github.com/smallthinkingmachines/harombe/issues) - Bug reports and feature requests

## Recognition

Contributors are recognized in release notes and the project's contributor list. Thank you for helping make harombe better!

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
