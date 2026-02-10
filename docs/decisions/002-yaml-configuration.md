# ADR-002: Use YAML for Declarative Configuration

**Status**: Accepted
**Date**: 2025-06

## Context

Harombe needs a configuration format for cluster definitions, agent settings, tool declarations, and other structured data. The options considered were:

1. **YAML** — human-readable data serialization, widely used in infrastructure tooling.
2. **TOML** — simpler syntax, popular in Python tooling (`pyproject.toml`).
3. **JSON** — ubiquitous but lacks comments and is verbose for hand-editing.
4. **Python code** — maximum flexibility but no separation between config and logic.

Cluster configurations in particular involve deeply nested structures (agents containing tools containing permission sets), which influenced the decision.

## Decision

Use YAML as the primary configuration format for all declarative configuration files.

## Consequences

**Positive:**

- Better suited for deeply nested structures such as cluster configs with multiple agents and tool definitions.
- Supports comments, allowing inline documentation of configuration choices.
- Familiar to infrastructure engineers and DevOps practitioners.
- Widely supported by editors and linters.

**Negative:**

- Whitespace-sensitive syntax can lead to subtle indentation errors.
- Slightly more complex parsing than TOML (requires `PyYAML` or `ruamel.yaml` dependency).
- Known gotchas with implicit type coercion (e.g., `yes`/`no` as booleans, Norway problem with `NO` as country code).
