# Security Policy

## Reporting a Vulnerability

We take the security of harombe seriously. If you discover a security vulnerability, please help us by disclosing it responsibly.

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by opening a **private security advisory** on GitHub:

1. Go to https://github.com/smallthinkingmachines/harombe/security/advisories
2. Click "New draft security advisory"
3. Provide a detailed description of the vulnerability including:
   - Type of vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

We will respond to your report within 48 hours and work with you to understand and address the issue.

## Security Advisory Process

1. **Report received** - We acknowledge your report within 48 hours
2. **Investigation** - We investigate and validate the vulnerability
3. **Fix development** - We develop and test a fix (you may be invited to review)
4. **Release** - We release a patched version
5. **Disclosure** - We publicly disclose the vulnerability after users have had time to update

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

We recommend always using the latest version of harombe.

## Security Considerations

### Running Tools

harombe includes tools that can execute system commands and modify files. When using harombe:

- **Review tool calls** - The `confirm_dangerous` setting (enabled by default) requires approval before dangerous operations
- **Sandbox environments** - Consider running harombe in isolated environments (containers, VMs) when testing
- **API exposure** - If running the API server, ensure proper network isolation and authentication
- **Model trust** - Remember that the LLM's decisions are based on training data and prompts

### Configuration Security

- **Config files** - Keep `harombe.yaml` files secure, especially if they contain sensitive settings
- **Environment variables** - Avoid storing sensitive data in environment variables when possible
- **File permissions** - Ensure proper file permissions on config files and data directories

## Security Best Practices

1. **Keep dependencies updated** - Regularly update harombe and its dependencies
2. **Use confirmation mode** - Keep `tools.confirm_dangerous: true` in your config
3. **Review logs** - Monitor harombe logs for unexpected behavior
4. **Limit network access** - Run Ollama and harombe on localhost unless remote access is required
5. **Principle of least privilege** - Run harombe with minimal required permissions

## Contact

For any security concerns that don't require a private advisory, you can reach the maintainers through:
- GitHub Discussions: https://github.com/smallthinkingmachines/harombe/discussions
- Email: security@smallthinkingmachines.org (if available)

Thank you for helping keep harombe and its users safe!
