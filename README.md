# go-escalation-check

A command line tool that scans an AWS IAM configuration and finds every path an attacker (or a misconfigured identity) could use to gain full administrator access.

It reads the IAM users, roles, groups, and policies in an account, maps out what each identity is allowed to do, and identifies dangerous permission combinations. For every problem it finds, it generates a fix: a ready to deploy IAM policy and Terraform configuration that blocks the escalation path.

```
go-escalation-check scan --snapshot testdata/sample_snapshot.json

Loading IAM snapshot: testdata/sample_snapshot.json
Loaded  4 users  3 roles  2 groups  4 managed policies

+-----------------+------+-------------------------------------+-----------+----------+
|    PRINCIPAL    | KIND |             TECHNIQUE               |   MITRE   | SEVERITY |
+-----------------+------+-------------------------------------+-----------+----------+
| alice           | user | Create New Policy Version           | T1484.001 | CRITICAL |
| alice           | user | Attach Admin Policy to User         | T1098.003 | CRITICAL |
| alice           | user | Pass Admin Role via EC2             | T1548     | HIGH     |
| carol           | user | Backdoor Role Trust Policy          | T1078.004 | CRITICAL |
| DeployRole      | role | Put Inline Admin Policy on Role     | T1098.003 | CRITICAL |
...
37 finding(s) across 6 principal(s)
```

## The problem it solves

In AWS, a user does not need to already be an administrator to become one. Given the right combination of IAM permissions, even seemingly harmless ones, an identity can quietly grant itself full access. This is called **privilege escalation**.

For example:

* A user with `iam:AttachUserPolicy` can attach the `AdministratorAccess` policy to their own account.
* A user with `iam:PassRole` and `ec2:RunInstances` can launch a server with an admin role attached and run commands through it.
* A user with `iam:CreateRole` and `iam:AttachRolePolicy` can create a brand new admin role and assume it.

These risks are hard to spot manually, especially in large accounts with many users, roles, groups, and policies layered on top of each other.

`go-escalation-check` automates this analysis. It checks 26 known escalation techniques against every identity in an account and reports exactly which identities are at risk and why.

## What it produces

| Output | What it is |
|--------|-----------|
| **Table / JSON** | A list of every finding: which identity is affected, what technique applies, and the MITRE ATT&CK technique ID |
| **JIT policies** | Deny based IAM policies that block only the dangerous actions for each affected identity, without removing other permissions |
| **Terraform HCL** | Ready to apply infrastructure code that deploys those policies to the AWS account |

## How it works

1. Loads all IAM users, roles, groups, and policies from the account (or a saved JSON file)
2. Resolves the effective permissions for each identity, including permissions inherited through group membership
3. Checks each identity against 18 escalation techniques (see full list below)
4. For every match, generates a deny policy that blocks exactly the actions required for that technique

## Install

**From source (requires Go 1.22+):**

```bash
git clone https://github.com/FrancescoCitti/go-escalation-check
cd go-escalation-check
go build -o go-escalation-check .
```

**Using `go install`:**

```bash
go install github.com/FrancescoCitti/go-escalation-check@latest
```

## Usage

### Try it immediately, no AWS account needed

The repo includes a sample snapshot with realistic fake IAM data:

```bash
go run . scan --snapshot testdata/sample_snapshot.json
```

### Scan a live AWS account

```bash
go-escalation-check scan --profile my-profile --region us-east-1
```

This requires the `iam:GetAccountAuthorizationDetails` permission. It is read only and makes no changes to the account.

### Get findings as JSON

Useful for piping into other tools or saving for later:

```bash
go-escalation-check scan --snapshot testdata/sample_snapshot.json --format json
```

### Generate fix files

```bash
go-escalation-check scan \
  --snapshot testdata/sample_snapshot.json \
  --jit \
  --terraform \
  --outdir ./remediation
```

Writes two files to `./remediation/`:

* `jit_policies.json` — one deny policy per affected identity, listing only the specific dangerous actions. Each policy includes an MFA requirement and an 8 hour expiry condition.
* `iam_remediation.tf` — Terraform resources (`aws_iam_policy` + attachment) ready to apply.

### Save a live account to a file for offline analysis

```bash
go-escalation-check snapshot --profile prod --output prod_iam.json
```

Useful for scanning without keeping live AWS credentials available, sharing with teammates, or keeping a historical record.

## All flags

### `scan`

| Flag | Default | Description |
|------|---------|-------------|
| `--snapshot` | | Path to a JSON snapshot file. If omitted, reads from a live AWS account. |
| `--profile` | | AWS named profile to use. |
| `--region` | `us-east-1` | AWS region. |
| `--format` | `table` | Output format: `table` or `json`. |
| `--jit` | false | Write JIT restriction policies to `--outdir`. |
| `--terraform` | false | Write Terraform HCL to `--outdir`. |
| `--outdir` | `.` | Directory for generated output files. |

### `snapshot`

| Flag | Default | Description |
|------|---------|-------------|
| `--profile` | | AWS named profile to use. |
| `--region` | `us-east-1` | AWS region. |
| `--output` | `iam_snapshot.json` | Output file path. |

## Escalation techniques detected

| Technique | What it means | MITRE |
|-----------|---------------|-------|
| Create New Policy Version | Creates a new version of an attached managed policy that grants full admin access | T1484.001 |
| Set Default Policy Version | Switches an existing policy back to an older version that had admin permissions | T1484.001 |
| Attach Admin Policy to User | Attaches the `AdministratorAccess` policy directly to a user | T1098.003 |
| Attach Admin Policy to Group | Attaches `AdministratorAccess` to a group the user belongs to | T1098.003 |
| Attach Admin Policy to Role | Attaches `AdministratorAccess` to a role the identity can assume | T1098.003 |
| Put Inline Admin Policy on User | Writes an inline policy granting full admin access to a user | T1098.003 |
| Put Inline Admin Policy on Group | Writes an inline policy granting full admin access to a group | T1098.003 |
| Put Inline Admin Policy on Role | Writes an inline policy granting full admin access to a role | T1098.003 |
| Create Access Key for Admin User | Generates API credentials for a user who already has admin access | T1098.001 |
| Reactivate Disabled Access Key for Admin User | Re-enables a deactivated programmatic credential on a user with admin access | T1098.001 |
| Create Console Login for Admin User | Enables console login for a user who already has admin access | T1098 |
| Reset Admin User Password | Changes the password of a user who already has admin access | T1098 |
| Add Self to Admin Group | Adds a user to a group that has admin permissions | T1098 |
| Deactivate MFA Device on Admin User | Removes MFA from a user with admin privileges, enabling password-only console access | T1556.006 |
| Delete Virtual MFA Device from Admin User | Deletes the virtual MFA device from a user with admin privileges | T1556.006 |
| Backdoor Role Trust Policy | Modifies a role trust policy to allow an identity to assume it | T1078.004 |
| Directly Assume Admin Role | Calls sts:AssumeRole on an admin role whose trust policy already permits the caller | T1078.004 |
| Pass Admin Role via EC2 | Launches an EC2 instance with an admin role attached and runs commands through it | T1548 |
| Pass Admin Role via Lambda | Creates a Lambda function with an admin role and invokes it | T1548 |
| Pass Admin Role via CloudFormation | Creates a CloudFormation stack that uses an admin role to provision resources | T1548 |
| Pass Admin Role via Glue | Creates a Glue development endpoint with an admin role attached | T1548 |
| Pass Admin Role via SageMaker | Creates a SageMaker notebook instance with an admin role to execute arbitrary code | T1548 |
| Pass Admin Role via CodeBuild | Creates and starts a CodeBuild project with an admin role to run arbitrary build commands | T1548 |
| Pass Admin Role via ECS | Registers an ECS task definition and runs it with an admin role attached | T1548 |
| Pass Admin Role via Data Pipeline | Creates a Data Pipeline with an admin role to execute commands on provisioned resources | T1548 |
| Create and Assume New Admin Role | Creates a new IAM role, attaches admin permissions to it, then assumes it | T1136.003 |

## Snapshot file format

The JSON snapshot format matches the output of `aws iam get-account-authorization-details`. A snapshot can be generated with the `snapshot` subcommand, or written manually for testing. See `testdata/sample_snapshot.json` for a complete working example.

## Required AWS permissions

To scan a live account, the following read only permission is required:

```json
{
  "Effect": "Allow",
  "Action": "iam:GetAccountAuthorizationDetails",
  "Resource": "*"
}
```

No write permissions are needed. The tool never modifies an AWS account.
