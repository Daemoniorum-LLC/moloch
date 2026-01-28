# Moloch Documentation Index

Complete index of all documentation for the Moloch cryptographic audit chain.

## Documentation Map

```
moloch/
├── README.md                    # Project overview
├── CONTRIBUTING.md              # Contribution guidelines
├── SECURITY.md                  # Security policy & vulnerability reporting
├── CHANGELOG.md                 # Version history
├── BENCHMARK_REPORT.md          # Performance benchmarks
│
└── docs/
    ├── INDEX.md                 # This file
    ├── MASTER_SPECIFICATION.md  # Complete system specification
    │
    ├── developer/               # Developer documentation
    │   ├── quickstart.md        # Getting started guide
    │   ├── architecture.md      # System architecture & diagrams
    │   ├── api.md               # REST/WebSocket API reference
    │   ├── security.md          # Security model & threat analysis
    │   ├── SPEC_GAPS.md         # Specification gap analysis
    │   ├── OSS_RELEASE_ROADMAP.md # Release planning
    │   ├── deployment.md        # Deployment guide
    │   ├── operations.md        # Operations & monitoring
    │   └── configuration.md     # Configuration reference
    │
    ├── diagrams/                # Architecture diagrams
    │   ├── data-flow.md         # Data flow diagrams
    │   ├── consensus-sequence.md # Consensus protocol sequence
    │   ├── sync-sequence.md     # Sync protocol sequence
    │   └── anchoring-sequence.md # Anchoring protocol sequence
    │
    ├── llm/                     # Agent-optimized documentation
    │   ├── quickstart.sigil
    │   ├── architecture.sigil
    │   ├── api.sigil
    │   └── security.sigil
    │
    └── archive/                 # Historical documents
        ├── ROADMAP.md
        └── AGENT_QUICKSTART_v1.md
```

## Document Categories

### Core Documentation

| Document | Path | Description | Status |
|----------|------|-------------|--------|
| Master Specification | `docs/MASTER_SPECIFICATION.md` | Complete system specification | Complete |
| README | `README.md` | Project overview and quick start | Complete |
| Architecture | `docs/developer/architecture.md` | System design with diagrams | Complete |
| API Reference | `docs/developer/api.md` | REST/WebSocket API | Complete |
| Security | `docs/developer/security.md` | Security model | Complete |
| Quickstart | `docs/developer/quickstart.md` | Getting started guide | Complete |

### Operational Documentation

| Document | Path | Description | Status |
|----------|------|-------------|--------|
| Deployment Guide | `docs/developer/deployment.md` | Production deployment | New |
| Operations Guide | `docs/developer/operations.md` | Running and monitoring | New |
| Configuration Reference | `docs/developer/configuration.md` | All config options | New |

### Architecture Diagrams

| Document | Path | Description | Status |
|----------|------|-------------|--------|
| Data Flow | `docs/diagrams/data-flow.md` | Event lifecycle diagrams | New |
| Consensus Sequence | `docs/diagrams/consensus-sequence.md` | Block production protocol | New |
| Sync Sequence | `docs/diagrams/sync-sequence.md` | Node synchronization | New |
| Anchoring Sequence | `docs/diagrams/anchoring-sequence.md` | External anchoring flow | New |

### Planning & Process

| Document | Path | Description | Status |
|----------|------|-------------|--------|
| Spec Gaps | `docs/developer/SPEC_GAPS.md` | Dead code gap analysis | Complete |
| Release Roadmap | `docs/developer/OSS_RELEASE_ROADMAP.md` | OSS release planning | Complete |
| Benchmarks | `BENCHMARK_REPORT.md` | Performance data | Complete |

## Quick Links by Role

### For New Developers
1. [README](../README.md) - Project overview
2. [Quickstart](developer/quickstart.md) - Build and run
3. [Architecture](developer/architecture.md) - System design

### For API Consumers
1. [API Reference](developer/api.md) - REST/WebSocket endpoints
2. [Quickstart](developer/quickstart.md) - SDK examples

### For Operators
1. [Deployment Guide](developer/deployment.md) - Production setup
2. [Operations Guide](developer/operations.md) - Monitoring & maintenance
3. [Configuration Reference](developer/configuration.md) - Config options

### For Contributors
1. [CONTRIBUTING](../CONTRIBUTING.md) - Contribution guidelines
2. [Master Specification](MASTER_SPECIFICATION.md) - Complete spec
3. [Spec Gaps](developer/SPEC_GAPS.md) - Areas needing work

### For Security Auditors
1. [Security](developer/security.md) - Threat model
2. [SECURITY](../SECURITY.md) - Vulnerability reporting
3. [Master Specification](MASTER_SPECIFICATION.md) - Cryptographic specs

## Document Standards

### Markdown Conventions
- GitHub-flavored Markdown
- ASCII diagrams for inline visualization
- Code blocks with language annotations
- Tables for structured data

### Diagram Standards
- Mermaid syntax for sequence diagrams (when GitHub renders)
- ASCII art for maximum compatibility
- Include text descriptions for accessibility

### Update Policy
- Specs updated before implementation (SDD methodology)
- Tests written after spec approval (Agent-TDD)
- Diagrams updated with architecture changes
