# go-escalation-check

AWS IAM privilege escalation path analyzer written in Go.

Reads your IAM configuration, builds a directed permission graph, finds every path to administrator-level access, and generates remediation artifacts ready to deploy.

```
go-escalation-check scan --snapshot testdata/sample_snapshot.json

Loading IAM snapshot: testdata/sample_snapshot.json
Loaded  4 users  3 roles  2 groups  4 managed policies

+-----------------+------+-------------------------------------+-----------+----------+
|   PRINCIPAL     | KIND |             TECHNIQUE               |   MITRE   | SEVERITY |
+-----------------+------+-------------------------------------+-----------+----------+
| alice           | user | Create New Policy Version           | T1484.001 | CRITICAL |
| alice           | user | Attach Admin Policy to User         | T1098.003 | CRITICAL |
| alice           | user | Pass Admin Role via EC2             | T1548     | HIGH     |
| carol           | user | Backdoor Role Trust Policy          | T1078.004 | CRITICAL |
| DeployRole      | role | Put Inline Admin Policy on Role     | T1098.003 | CRITICAL |
...
37 finding(s) across 6 principal(s)
```

## What it does

- **Permission graph** — models all IAM entities (users, roles, groups, policies) and the trust relationships between them
- **Escalation detection** — checks 18 known privilege escalation techniques against each principal's effective permissions, including transitive group permissions
- **MITRE ATT&CK mapping** — every finding is tagged with the corresponding technique ID (T1078, T1098, T1484, T1548, T1136)
- **JIT restriction policies** — generates minimal deny-based IAM policies that block escalation paths without removing legitimate access
- **Terraform HCL export** — produces deployment-ready `aws_iam_policy` and attachment resources for immediate remediation

## Why this is different

[Cloudsplaining](https://github.com/salesforce/cloudsplaining) and [PMapper](https://github.com/nccgroup/PMapper) enumerate IAM misconfigurations in Python. This tool does something different: graph-based path analysis combined with JIT policy generation and Terraform output in a single binary. The JIT remediation angle comes from direct operational experience building a JIT IAM system that eliminated standing permissions for 140+ engineers.

## Install

```bash
go install github.com/francescocitti/go-escalation-check@latest
```

Or build from source:

```bash
git clone https://github.com/francescocitti/go-escalation-check
cd go-escalation-check
go build -o go-escalation-check .
```

## Usage

### Scan a snapshot (no AWS credentials needed)

```bash
go-escalation-check scan --snapshot testdata/sample_snapshot.json
```

### Scan a live AWS account

```bash
go-escalation-check scan --profile my-profile --region us-east-1
```

### Export findings as JSON

```bash
go-escalation-check scan --snapshot testdata/sample_snapshot.json --format json
```

### Generate JIT policies and Terraform HCL

```bash
go-escalation-check scan \
  --snapshot testdata/sample_snapshot.json \
  --jit \
  --terraform \
  --outdir ./remediation
```

Produces:
- `remediation/jit_policies.json` — deny-based policies with MFA and time conditions
- `remediation/iam_remediation.tf` — ready-to-apply Terraform resources

### Capture a live snapshot for offline use

```bash
go-escalation-check snapshot --profile prod --output prod_iam.json
```

Requires `iam:GetAccountAuthorizationDetails`.

## Escalation techniques detected

| ID | Technique | MITRE |
|----|-----------|-------|
| create_new_policy_version | Create New Policy Version | T1484.001 |
| set_default_policy_version | Set Default Policy Version | T1484.001 |
| attach_user_policy | Attach Admin Policy to User | T1098.003 |
| attach_group_policy | Attach Admin Policy to Group | T1098.003 |
| attach_role_policy | Attach Admin Policy to Role | T1098.003 |
| put_user_policy | Put Inline Admin Policy on User | T1098.003 |
| put_group_policy | Put Inline Admin Policy on Group | T1098.003 |
| put_role_policy | Put Inline Admin Policy on Role | T1098.003 |
| create_access_key | Create Access Key for Admin User | T1098.001 |
| create_login_profile | Create Console Login for Admin User | T1098 |
| update_login_profile | Reset Admin User Password | T1098 |
| add_user_to_group | Add Self to Admin Group | T1098 |
| update_assume_role_policy | Backdoor Role Trust Policy | T1078.004 |
| pass_role_ec2 | Pass Admin Role via EC2 | T1548 |
| pass_role_lambda | Pass Admin Role via Lambda | T1548 |
| pass_role_cloudformation | Pass Admin Role via CloudFormation | T1548 |
| pass_role_glue | Pass Admin Role via Glue | T1548 |
| create_admin_role | Create and Assume New Admin Role | T1136.003 |

## Snapshot format

The snapshot JSON format mirrors `aws iam get-account-authorization-details`. Use the `snapshot` subcommand to generate one from a live account, or write one by hand for testing. See `testdata/sample_snapshot.json` for a working example with multiple escalation paths.

## Required IAM permissions for live scan

```json
{
  "Effect": "Allow",
  "Action": "iam:GetAccountAuthorizationDetails",
  "Resource": "*"
}
```
