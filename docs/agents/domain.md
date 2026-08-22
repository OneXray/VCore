# Domain Docs

This repository uses a single-context domain layout:

- `CONTEXT.md` at the repository root
- system-wide ADRs under `docs/adr/`

Before exploring a domain, read `CONTEXT.md` and relevant ADRs when they exist. If they do not exist, proceed silently; create them lazily through the domain-modeling workflow when terminology or decisions are actually resolved.

Use vocabulary defined by `CONTEXT.md` in issues, specs, tests, and code. If proposed work contradicts an ADR, identify the ADR and surface the conflict instead of silently overriding it.
