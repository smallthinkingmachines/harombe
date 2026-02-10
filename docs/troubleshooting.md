# Troubleshooting

## Ollama Not Running

If you see errors about connecting to Ollama:

```bash
# Start Ollama server
ollama serve

# In another terminal, verify it's running
curl http://localhost:11434/api/tags
```

## Model Not Found

If harombe can't find your model:

```bash
# List available models
ollama list

# Pull a model (recommended: qwen2.5:7b)
ollama pull qwen2.5:7b

# Update your config
nano ~/.harombe/harombe.yaml  # Change model.name
```

## Installation Issues

```bash
# Ensure Python 3.11+ is installed
python3 --version

# Upgrade pip
pip install --upgrade pip

# Reinstall harombe
pip install --force-reinstall harombe
```

## Permission Errors

If you get permission errors during tool execution:

1. Check that `confirm_dangerous: true` in your config
2. Review the operation before approving
3. Consider running in a sandboxed environment

## Getting Help

- Check existing [Issues](https://github.com/smallthinkingmachines/harombe/issues)
- Start a [Discussion](https://github.com/smallthinkingmachines/harombe/discussions)
- Review the [Security Policy](../SECURITY.md) for security concerns
