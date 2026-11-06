# Security policy

## Reporting a vulnerability in ASVA

Please report security problems in ASVA's own code (everything outside `target-apps/`)
privately, using GitHub's **Report a vulnerability** button on the repository's
**Security** tab. Do not open a public issue.

Include what you found, how to reproduce it, and which commit or release you tested.
We will acknowledge the report and keep you updated while we work on a fix.

## The test applications are vulnerable on purpose

`target-apps/` contains deliberately vulnerable third-party applications (NodeGoat and
PyGoat) that ASVA scans and fixes. Their vulnerabilities, and the fake secrets and
credentials inside them, are intentional. Please do not report them.

- Run them only on your own machine or in an isolated test environment.
- Never expose them to the internet or to a shared network.
- The sample scan results in `samples/` describe these intentional vulnerabilities.

## Secrets

ASVA never needs real credentials committed to the repository. Local settings go in a
`.env` file, which is gitignored; CI uses GitHub Actions secrets and variables (see
[docs/ci-configuration.md](docs/ci-configuration.md)). Every fix ASVA generates passes a
gitleaks secrets gate before it is committed.
