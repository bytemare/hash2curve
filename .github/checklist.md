# GitHub repository basic setup

This is a checklist of a basic setup for your GitHub repo.

## Files
- [] Add a `LICENSE` file with the year(s) and name
- [] Add a `README.md` file at the root
  - [] State the purpose of the project
  - [] State how people can get, install, and use the project
  - [] Link to documentation
  - [] What versions are supported? What do they mean? Very often you would go with SemVer here
  - [] Refer where one can find how to contribute (e.g. link to the `CONTRIBUTING.md` file in `.github`)
  - [] Refer to the License
- [] `CITATION.cff`
- [] Use a relevant `.gitignore` file
- [] Setup the `.github` folder
  - [] `SECURITY.md`
  - [] `CONTRIBUTING.md`
  - [] `CODE_OF_CONDUCT.md`
  - [] `CODEOWNERS`
  - [] `ISSUE_TEMPLATE`
  - [] `PULL_REQUEST_TEMPLATE`
  - Makefile for neat automation
  - [] workflows
    - [] Repo Security Monitoring (e.g. scorecards)
    - [] Dependency Security Monitoring (e.g. Snyk, dependabot, renovate)
    - [] Code Security Analysis (e.g. CodeQL, SonarCloud, Coverity)
    - [] Linting (e.g. licence-header, golangci-lint, ShellCheck, YAML file linter)
    - [] Unit tests
    - [] Coverage (e.g. Codecov, Coveralls)

## Repo settings

- topics, find the right hashtags!

- [] Branch Protection
  - [] Require a pull request before merging
    - [] Require approvals
    - [] Dismiss stale pull request approvals when new commits are pushed
    - [] Require review from Code Owners
  - [] Require status checks to pass before merging
    - [] Require branches to be up to date before merging
    - e.g. of Status checks: DCO, Snyk, Tests from CI, coverage, code linting and analysis
  - [] Require signed commits
  - [] Include administrators
- [] Declare GitHub Workflow tokens as read only
- [] Tokens
  - [] Sonar
  - [] Snyk
  - [] SCORECARD_READ_TOKEN

## Git setup

- GPG sign
- auto sign-off: https://stackoverflow.com/a/46536244/6310488

## MISC

- Project description, find the right topics for better referencing
- Pin dependencies
- Cryptographically sign releases
