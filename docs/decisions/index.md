# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the harombe project. ADRs capture significant architectural decisions along with their context and consequences.

We use the [MADR](https://adr.github.io/madr/) (Markdown Architectural Decision Records) format.

## Decisions

| ID                                          | Title                                             | Status   | Date    |
| ------------------------------------------- | ------------------------------------------------- | -------- | ------- |
| [001](001-ollama-openai-sdk.md)             | Use OpenAI SDK instead of Ollama's Python package | Accepted | 2025-06 |
| [002](002-yaml-configuration.md)            | Use YAML for declarative configuration            | Accepted | 2025-06 |
| [003](003-capability-container-pattern.md)  | Adopt Capability-Container security pattern       | Accepted | 2026-02 |
| [004](004-sqlite-audit-logging.md)          | Use SQLite for audit logging                      | Accepted | 2026-02 |
| [005](005-privacy-first-local-inference.md) | Default to local-first inference                  | Accepted | 2025-06 |
