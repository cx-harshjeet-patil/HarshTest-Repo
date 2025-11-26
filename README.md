# Checkmarx Azure DevOps Windows Agent - All Scans Demo

This repository is used to test:

- Azure DevOps YAML Pipelines
- Windows Self-Hosted Agent
- Checkmarx One AST Plugin
- SAST + SCA + IaC + API Security
- Pull Request Decoration

## How to Use

1. Push this repo to GitHub
2. Connect it to Azure DevOps
3. Install the Checkmarx AST ADO plugin
4. Create a Checkmarx service connection
5. Update the pipeline with your agent pool and service connection
6. Create a PR to `main` and observe PR decoration