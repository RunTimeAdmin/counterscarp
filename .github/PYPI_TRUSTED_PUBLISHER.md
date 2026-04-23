# PyPI Trusted Publisher Setup

## One-time configuration on PyPI

1. Go to https://pypi.org/manage/project/counterscarp-engine/settings/publishing/
2. Under "Add a new publisher", fill in:
   - **Owner**: `RunTimeAdmin`
   - **Repository**: `counterscarp`
   - **Workflow name**: `publish.yml`
   - **Environment name**: `pypi`
3. Click "Add"

## One-time configuration on GitHub

1. Go to Repository Settings → Environments
2. Create environment: `pypi`
   - Optional: Add deployment protection rules (require approval)
3. Create environment: `testpypi`

## Usage

### Automatic (on release):
Create a GitHub Release → publish.yml triggers automatically

### Manual:
Actions → Publish to PyPI → Run workflow → Select target (pypi/testpypi)

## How it works

OIDC (OpenID Connect) trusted publishing eliminates API tokens:
- GitHub Actions generates a short-lived OIDC token
- PyPI verifies the token against the trusted publisher configuration
- Package is published without any stored secrets
- Tokens are scoped to the specific workflow, repo, and environment
