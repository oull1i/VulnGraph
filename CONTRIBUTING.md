# Contributing

Thank you for helping improve VulnGraph. Please keep changes defensive and reproducible.

1. Open an issue describing the behavior, expected evidence, and affected CycloneDX schema.
2. Create a branch named `fix/<issue>` or `feat/<feature>`.
3. Add tests for new parsing cases, scoring behavior, regressions, and API security boundaries.
4. Run `python -m pytest -q` and `python -m compileall -q vulngraph`.
5. Avoid real vulnerable customer files or internal package inventories in fixtures; use fictitious examples.
6. Submit a pull request explaining the security and privacy impact. Don't add invasive port scans or exploit modules.

Security disclosures: follow [docs/SECURITY.md](docs/SECURITY.md).
