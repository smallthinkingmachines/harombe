# Harombe Documentation Site Proposal

**Date**: 2026-02-09
**Status**: Proposal
**Estimated Effort**: 1-2 weeks

## Executive Summary

Harombe currently has **25 comprehensive markdown documentation files** covering architecture, security, deployment, implementation plans, and user guides. These docs would benefit significantly from a dedicated documentation website with proper navigation, search, and organization.

### Current State

```
docs/
├── Architecture (5 files)
│   ├── memory-architecture.md
│   ├── vector-store-architecture.md
│   ├── voice-architecture.md
│   ├── mcp-gateway-design.md
│   └── security-architecture.md (NEW)
│
├── Security (7 files)
│   ├── security-quickstart.md
│   ├── security-phase4.1-foundation.md
│   ├── security-credentials.md
│   ├── security-network.md
│   ├── audit-logging.md
│   ├── hitl-design.md
│   └── security-architecture.md
│
├── Implementation & Guides (8 files)
│   ├── phase0-implementation-summary.md
│   ├── phase4-implementation-plan.md
│   ├── phase4-8-integration-plan.md
│   ├── phase4-8-performance-results.md
│   ├── phase5-implementation-plan.md (NEW)
│   ├── production-deployment-guide.md (NEW)
│   ├── browser-container-design.md
│   └── code-sandbox-design.md
│
├── User Guides (3 files)
│   ├── browser-usage.md
│   ├── code-sandbox-usage.md
│   └── voice-setup.md
│
└── Contributing (2 files)
    ├── CONTRIBUTING.md
    ├── DEVELOPMENT.md
    └── README.md
```

**Total**: 25 markdown files, ~15,000+ lines of documentation

## Proposed Solution

### Option 1: MkDocs (Recommended)

**Why MkDocs**:

- ✅ Python-based (matches Harombe's stack)
- ✅ Excellent Material theme (modern, beautiful)
- ✅ Built-in search
- ✅ Easy deployment to GitHub Pages
- ✅ Minimal configuration
- ✅ Fast build times

**Features**:

- Material Design theme
- Dark mode
- Search with highlighting
- Version selector
- Mobile-responsive
- Code syntax highlighting
- Mermaid diagram support
- Social cards for SEO

**Setup Time**: 2-3 days

### Option 2: Docusaurus

**Why Docusaurus**:

- ✅ React-based (Meta's tooling)
- ✅ Rich plugin ecosystem
- ✅ Versioning built-in
- ✅ Blog support
- ✅ MDX support (React in Markdown)

**Cons**:

- ⚠️ More complex setup
- ⚠️ JavaScript dependency (different from Python)
- ⚠️ Slower build times

**Setup Time**: 1 week

### Option 3: VitePress

**Why VitePress**:

- ✅ Vue-based, very fast
- ✅ Modern, clean design
- ✅ Excellent DX
- ✅ Minimal config

**Cons**:

- ⚠️ Newer, smaller community
- ⚠️ JavaScript-based

**Setup Time**: 3-4 days

## Recommended Approach: MkDocs with Material Theme

### Proposed Site Structure

```
https://harombe.dev/
│
├── Home
│   └── Project overview, key features, quick links
│
├── Getting Started
│   ├── Installation
│   ├── Quick Start
│   ├── Configuration
│   └── First Agent
│
├── Architecture
│   ├── Overview
│   ├── Memory & RAG
│   ├── Vector Store
│   ├── Voice Interface
│   ├── MCP Gateway
│   └── Security Layer
│
├── Security
│   ├── Security Overview
│   ├── Quick Start
│   ├── Architecture
│   ├── Sandboxing (gVisor)
│   ├── Credential Management (Vault)
│   ├── Network Security
│   ├── Audit Logging
│   ├── HITL Gates
│   └── Secret Scanning
│
├── Deployment
│   ├── Production Guide
│   ├── Configuration
│   ├── Monitoring
│   ├── Troubleshooting
│   └── Performance Tuning
│
├── Development
│   ├── Contributing Guide
│   ├── Development Setup
│   ├── Code Style
│   ├── Testing
│   └── Release Process
│
├── Phase Plans
│   ├── Phase 0: Foundation
│   ├── Phase 4: Security Layer
│   ├── Phase 4.8: Integration
│   ├── Phase 5: Intelligence (Planned)
│   └── Roadmap
│
├── API Reference
│   ├── Agent API
│   ├── Security API
│   ├── Memory API
│   └── MCP API
│
└── User Guides
    ├── Browser Usage
    ├── Code Sandbox
    └── Voice Setup
```

### Implementation Plan

#### Phase 1: Setup (Week 1)

**Tasks**:

1. **Install MkDocs and Material Theme**

   ```bash
   pip install mkdocs mkdocs-material
   pip install mkdocs-mermaid2-plugin  # For diagrams
   pip install mkdocs-git-revision-date-localized-plugin  # Last updated dates
   ```

2. **Create mkdocs.yml Configuration**

   ```yaml
   site_name: Harombe Documentation
   site_url: https://harombe.dev
   site_description: Secure, intelligent AI agent framework
   site_author: Small Thinking Machines
   repo_url: https://github.com/smallthinkingmachines/harombe
   repo_name: smallthinkingmachines/harombe

   theme:
     name: material
     palette:
       # Light mode
       - media: "(prefers-color-scheme: light)"
         scheme: default
         primary: indigo
         accent: indigo
         toggle:
           icon: material/brightness-7
           name: Switch to dark mode
       # Dark mode
       - media: "(prefers-color-scheme: dark)"
         scheme: slate
         primary: indigo
         accent: indigo
         toggle:
           icon: material/brightness-4
           name: Switch to light mode
     features:
       - navigation.tabs
       - navigation.sections
       - navigation.expand
       - navigation.top
       - search.suggest
       - search.highlight
       - content.code.copy
       - content.code.annotate

   plugins:
     - search
     - mermaid2
     - git-revision-date-localized:
         enable_creation_date: true

   markdown_extensions:
     - pymdownx.highlight:
         anchor_linenums: true
     - pymdownx.inlinehilite
     - pymdownx.snippets
     - pymdownx.superfences:
         custom_fences:
           - name: mermaid
             class: mermaid
             format: !!python/name:mermaid2.fence_mermaid
     - pymdownx.tabbed:
         alternate_style: true
     - admonition
     - pymdownx.details
     - pymdownx.emoji:
         emoji_index: !!python/name:material.extensions.emoji.twemoji
         emoji_generator: !!python/name:material.extensions.emoji.to_svg
     - attr_list
     - md_in_html
     - tables

   nav:
     - Home: index.md
     - Getting Started:
         - Installation: getting-started/installation.md
         - Quick Start: getting-started/quickstart.md
         - Configuration: getting-started/configuration.md
     - Architecture:
         - Overview: architecture/overview.md
         - Memory & RAG: architecture/memory-architecture.md
         - Vector Store: architecture/vector-store-architecture.md
         - Voice Interface: architecture/voice-architecture.md
         - MCP Gateway: architecture/mcp-gateway-design.md
         - Security: architecture/security-architecture.md
     - Security:
         - Overview: security/overview.md
         - Quick Start: security/security-quickstart.md
         - Architecture: security/security-architecture.md
         - Foundation: security/security-phase4.1-foundation.md
         - Sandboxing: security/code-sandbox-design.md
         - Credentials: security/security-credentials.md
         - Network: security/security-network.md
         - Audit Logging: security/audit-logging.md
         - HITL Gates: security/hitl-design.md
     - Deployment:
         - Production Guide: deployment/production-deployment-guide.md
         - Performance: deployment/phase4-8-performance-results.md
     - Development:
         - Contributing: development/CONTRIBUTING.md
         - Development Setup: development/DEVELOPMENT.md
     - Phase Plans:
         - Phase 0: phases/phase0-implementation-summary.md
         - Phase 4: phases/phase4-implementation-plan.md
         - Phase 4.8: phases/phase4-8-integration-plan.md
         - Phase 5: phases/phase5-implementation-plan.md
     - User Guides:
         - Browser Usage: guides/browser-usage.md
         - Code Sandbox: guides/code-sandbox-usage.md
         - Voice Setup: guides/voice-setup.md
   ```

3. **Reorganize Documentation Structure**

   ```bash
   mkdir -p docs-site/docs/{getting-started,architecture,security,deployment,development,phases,guides}

   # Move files to new structure (symlinks or copies)
   # This preserves the original docs/ folder for repo
   ```

4. **Create Landing Page (index.md)**

5. **Setup GitHub Actions for Deployment**

   ```yaml
   # .github/workflows/docs.yml
   name: Deploy Documentation

   on:
     push:
       branches:
         - main
       paths:
         - "docs/**"
         - "mkdocs.yml"
         - ".github/workflows/docs.yml"

   jobs:
     deploy:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3

         - uses: actions/setup-python@v4
           with:
             python-version: 3.x

         - run: pip install mkdocs-material mkdocs-mermaid2-plugin

         - run: mkdocs gh-deploy --force
   ```

#### Phase 2: Content Organization (Week 1-2)

**Tasks**:

1. **Create Missing Documentation**
   - Installation guide
   - Quick start guide
   - Configuration reference
   - API reference

2. **Enhance Existing Documentation**
   - Add navigation hints
   - Add cross-references
   - Add search keywords
   - Add admonitions (tips, warnings, notes)

3. **Convert Diagrams to Mermaid** (where applicable)

   ````markdown
   ```mermaid
   graph TD
       A[API Gateway] --> B[Agent Runtime]
       B --> C[Sandbox Manager]
       B --> D[HITL Gateway]
       D --> E[Vault]
       C --> F[gVisor Sandbox]
   ```
   ````

   ```

   ```

4. **Add Code Examples**
   - Installation commands
   - Configuration examples
   - API usage examples
   - Security policy examples

#### Phase 3: Enhancement & Polish (Week 2)

**Tasks**:

1. **Add Search Optimization**
   - Keywords
   - Descriptions
   - Titles

2. **Create Social Cards** (for sharing)

3. **Add Version Selector** (for future releases)

4. **Test on Mobile**

5. **Add Analytics** (optional)

   ```yaml
   # mkdocs.yml
   extra:
     analytics:
       provider: google
       property: G-XXXXXXXXXX
   ```

6. **Add Feedback Widget**

   ```yaml
   extra:
     feedback:
       title: Was this page helpful?
       ratings:
         - icon: material/thumb-up-outline
           name: This page was helpful
           data: 1
           note: Thanks for your feedback!
         - icon: material/thumb-down-outline
           name: This page could be improved
           data: 0
           note: Thanks for your feedback!
   ```

### Deployment Options

#### Option 1: GitHub Pages (Recommended)

**Pros**:

- ✅ Free
- ✅ Automatic deployment with GitHub Actions
- ✅ Custom domain support
- ✅ HTTPS included

**Setup**:

```bash
# One-time setup
mkdocs gh-deploy
```

**URL**: `https://smallthinkingmachines.github.io/harombe/`

**Custom Domain**: `https://docs.harombe.dev` (if DNS configured)

#### Option 2: Netlify

**Pros**:

- ✅ Free tier generous
- ✅ Preview deployments
- ✅ Better performance (CDN)
- ✅ Custom domain easy

**Setup**:

```toml
# netlify.toml
[build]
  command = "mkdocs build"
  publish = "site"
```

**URL**: `https://harombe.netlify.app`

#### Option 3: Read the Docs

**Pros**:

- ✅ Free for open source
- ✅ Designed for documentation
- ✅ Versioning built-in

**Cons**:

- ⚠️ Less flexible

### Estimated Timeline

| Phase                 | Duration    | Deliverables                      |
| --------------------- | ----------- | --------------------------------- |
| Setup & Configuration | 2 days      | MkDocs configured, basic site     |
| Content Organization  | 3 days      | All docs moved, nav configured    |
| Missing Content       | 3 days      | Installation, quickstart, API     |
| Enhancement & Polish  | 2 days      | Search, mobile, social cards      |
| Testing & Launch      | 1 day       | Final testing, deployment         |
| **Total**             | **11 days** | **Production documentation site** |

### Benefits

1. **Improved Discoverability**
   - Search across all documentation
   - Clear navigation structure
   - Mobile-friendly

2. **Better User Experience**
   - Dark mode support
   - Code copy buttons
   - Table of contents
   - Breadcrumbs

3. **Professional Appearance**
   - Modern design
   - Consistent branding
   - Social sharing cards

4. **Developer Productivity**
   - Easy to find information
   - API reference in one place
   - Version-specific docs

5. **SEO Benefits**
   - Better search engine indexing
   - Structured data
   - Social media previews

### Cost

**Zero** - All recommended tools are free for open source:

- MkDocs: Free, open source
- Material Theme: Free
- GitHub Pages: Free
- GitHub Actions: Free for public repos

### Success Metrics

- [ ] All 25 docs integrated
- [ ] Search works across all pages
- [ ] Mobile responsive
- [ ] Loads in <2s
- [ ] Deployed to production
- [ ] Custom domain configured (optional)

## Example Documentation Sites

**Good examples using MkDocs Material**:

- FastAPI: https://fastapi.tiangolo.com/
- SQLModel: https://sqlmodel.tiangolo.com/
- Material for MkDocs: https://squidfunk.github.io/mkdocs-material/

**Similar projects**:

- LangChain: https://python.langchain.com/
- LlamaIndex: https://docs.llamaindex.ai/

## Recommendation

**Start with MkDocs + Material Theme + GitHub Pages**

This gives us:

- ✅ Free, fast, professional
- ✅ Minimal maintenance
- ✅ Easy to update
- ✅ Matches Python ecosystem
- ✅ Can migrate later if needed

### Immediate Next Steps

1. Install MkDocs locally:

   ```bash
   pip install mkdocs-material mkdocs-mermaid2-plugin
   ```

2. Create `mkdocs.yml` configuration

3. Test locally:

   ```bash
   mkdocs serve
   # Visit http://localhost:8000
   ```

4. Deploy to GitHub Pages:

   ```bash
   mkdocs gh-deploy
   ```

5. Configure custom domain (optional):
   ```
   docs.harombe.dev → GitHub Pages
   ```

## Conclusion

With 25+ markdown files already written, creating a documentation site is a **high-value, low-effort** investment that will significantly improve the user and developer experience for Harombe.

**Recommendation**: Proceed with MkDocs + Material Theme, targeting a 2-week timeline for a fully polished documentation site.

---

**Document Version**: 1.0
**Last Updated**: 2026-02-09
**Owner**: Documentation Team
**Approver**: Technical Lead
