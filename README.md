# DEVOPS1

## DevSecOps for Python: 5 Delivery Models

This repository now documents a simple DevSecOps approach for Python projects across five common CI/CD models.

### Shared Python DevSecOps stages

Use the same checks in every model:

1. **Install dependencies**: `pip install -r requirements.txt`
2. **Lint**: `ruff check .`
3. **Unit tests**: `pytest`
4. **Security scan**: `bandit -r .`
5. **Dependency scan**: `pip-audit`

### Model 1 — GCP Options (end-to-end on Google Cloud)

- Source: Cloud Source Repositories or mirrored Git provider
- Build/scan: Cloud Build
- Images: Artifact Registry
- Deploy: Cloud Run / GKE
- Security: Secret Manager, Binary Authorization, Security Command Center

### Model 2 — Cloud Build

- Trigger Cloud Build on push/PR
- Run lint, test, Bandit, and dependency audit
- Build and push container
- Deploy to target environment after policy gates

### Model 3 — GitHub Actions

- Use workflow files in `.github/workflows`
- Run Python quality and security jobs on pull requests
- Protect main branch with required checks
- Deploy after successful approvals

### Model 4 — GitLab CI

- Use `.gitlab-ci.yml` with stages: lint, test, security, deploy
- Reuse Python cache and artifacts between stages
- Add SAST and dependency scanning templates
- Gate production deployments with protected environments

### Model 5 — Jenkins

- Define a `Jenkinsfile` pipeline
- Run isolated Python jobs inside containers/agents
- Integrate Bandit and dependency scanning plugins/tools
- Add manual approval before production rollout