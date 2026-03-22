# Contributing to Kairo SDK

Thanks for your interest in contributing to `@kairoguard/sdk`.

## Development setup

1. Install Node.js 18+.
2. Install dependencies:

```bash
npm install
```

3. Build and validate locally:

```bash
npm run typecheck
npm run test
npm run build
```

## Pull requests

- Open an issue first for significant changes.
- Keep PRs focused and minimal.
- Add or update tests for behavior changes.
- Update docs/README when APIs change.
- Follow the PR template.

## Commit and code style

- Use clear commit messages that explain why.
- Keep public APIs typed and documented.
- Prefer backward compatible changes unless a major release is planned.

## Reporting bugs

Use the bug report template and include:
- SDK version
- Node version
- chain/network details
- reproducible steps

## Security issues

Do not open public issues for vulnerabilities. Follow `SECURITY.md`.
