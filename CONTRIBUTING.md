# Contributing to agent-zero-trust

We welcome contributions to strengthen zero-trust security for autonomous agent swarms!

## Development Setup

```bash
git clone https://github.com/devsoniclk/agent-zero-trust.git
cd agent-zero-trust
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v --cov=agent_zero_trust
```

## Pull Request Guidelines

1. Ensure 100% test pass rate with coverage >= 85%.
2. Add unit tests for every new caveat predicate or firewall rule.
3. Verify that token cryptographic verification remains monotonic and non-replayable.
4. Keep dependencies minimal and audit against CVSS threat vectors.
