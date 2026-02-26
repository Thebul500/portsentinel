# Contributing to PortSentinel

Thanks for your interest in contributing to PortSentinel! This guide covers everything you need to get started.

## Setup

### Prerequisites

- **Node.js 18+** (tested on 18, 20, 22)
- **npm** (comes with Node.js)
- **Git**

### Clone and install

```bash
git clone https://github.com/your-org/portsentinel.git
cd portsentinel
npm install
```

### Verify your setup

```bash
npm run lint
npm test
```

Both commands should pass with no errors before you start making changes.

### Project structure

```
src/
├── scanner.js         # TCP port scanning
├── fingerprinter.js   # Banner grabbing & service ID
├── detector.js        # Change detection between scans
├── database.js        # SQLite storage (better-sqlite3)
├── exporter.js        # JSON/CSV export
├── alerts.js          # Severity calculation & alert formatting
└── index.js           # Module exports
test/                  # Mocha + Chai + Sinon unit tests
bin/portsentinel.js    # CLI entry point
```

## Code Style

The project uses ESLint with these key rules:

- **Semicolons** — always required
- **Quotes** — single quotes
- **Indentation** — 2 spaces
- **Variables** — `const`/`let` only, no `var`
- **Equality** — strict `===` only

Run `npm run lint` to check your code. Fix all lint errors before submitting a PR.

## Test

### Running the test suite

```bash
# Unit tests
npm test

# Unit tests with coverage report
npm run test:coverage
```

Tests use **Mocha** as the runner, **Chai** for assertions, and **Sinon** for mocking. Coverage is tracked by **nyc** with thresholds set at 80% for branches, lines, functions, and statements.

### Writing tests

- Place test files in `test/` with the naming pattern `<module>.test.js`
- Each source module in `src/` should have a corresponding test file
- Use `describe`/`it` blocks and keep test descriptions clear
- Mock external I/O (network, filesystem) — don't make real connections in unit tests

### What CI checks

Every push and PR triggers the CI pipeline, which runs:

1. **Lint** — `npm run lint`
2. **Tests + coverage** — `npm run test:coverage` across Node.js 18, 20, and 22
3. **Security audit** — `npm audit --audit-level=high`

All three must pass for a PR to be mergeable.

## Pull Request Process

### 1. Fork and branch

Fork the repository and create a feature branch from `main`:

```bash
git checkout -b feature/your-feature main
```

Use a descriptive branch name: `feature/add-udp-scanning`, `fix/timeout-race-condition`, `docs/update-cli-reference`.

### 2. Make your changes

- Keep commits focused — one logical change per commit
- Write clear commit messages describing *what* and *why*
- Add or update tests for any new or changed functionality
- Make sure `npm run lint` and `npm test` both pass locally

### 3. Submit the PR

- Open a pull request against `main`
- Fill in the PR description with a summary of your changes
- Reference any related issues (e.g., "Closes #42")
- Make sure CI is green before requesting review

### 4. Code review

- A maintainer will review your PR and may request changes
- Address feedback by pushing new commits to your branch
- Once approved, a maintainer will merge your PR

### What makes a good PR

- **Small and focused** — easier to review and less likely to introduce bugs
- **Tests included** — new features need tests, bug fixes need regression tests
- **Lint clean** — no ESLint errors or warnings
- **Clear description** — explain what changed and why

## Reporting Issues

Open an issue on GitHub with:

- A clear title and description
- Steps to reproduce (for bugs)
- Expected vs actual behavior
- Node.js version and OS

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
