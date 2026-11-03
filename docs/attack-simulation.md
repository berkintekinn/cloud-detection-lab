# Attack simulation execution

## Preconditions

- Work in a disposable AWS account you control. The operator needs permission to create and remove the Stratus resources; use temporary credentials and a named AWS profile.
- Configure CloudTrail management **read and write** events, multi-Region delivery, and global service events before detonation. Confirm the S3 destination and Athena table location.
- Configure VPC Flow Logs separately if network context is needed. Neither scenario requires a VPC Flow Log event to prove the IAM/EC2 API activity.
- Install the official [Stratus Red Team](https://stratus-red-team.cloud/user-guide/getting-started/) binary, AWS CLI, and Terraform required by Stratus. Review the technique pages and estimate sandbox costs. The IAM scenario does not need EC2 instances; the password scenario creates a role during warm-up and uses fictitious instance IDs.
- Capture the UTC start time, account alias, AWS profile name, chosen Region, and a unique run label in a **private** run record. Never publish credentials or raw password data.

## Execution

```bash
# Point AWS_PROFILE at a disposable sandbox profile.
export AWS_PROFILE=cloud-detection-sandbox
export AWS_REGION=us-east-1
aws sts get-caller-identity
stratus list

# Scenario A: create an IAM user, attach AdministratorAccess, create an access key.
stratus detonate aws.persistence.iam-create-admin-user
stratus status

# Scenario B: assume a low-privilege role and repeatedly attempt GetPasswordData.
stratus detonate aws.credential-access.ec2-get-password-data
stratus status
```

On PowerShell, use `$env:AWS_PROFILE = 'cloud-detection-sandbox'` and `$env:AWS_REGION = 'us-east-1'` instead of `export`. Review the exact account returned by STS before each detonation.

The [Stratus admin-user technique](https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-create-admin-user/) documents `CreateUser`, `AttachUserPolicy`, and `CreateAccessKey`. Confirm the policy ARN in `requestParameters.policyArn` and the target user in `requestParameters.userName`. An attachment with no `errorCode` is the detection event; creation and key issuance strengthen the incident narrative.

The [Stratus password-data technique](https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-get-password-data/) documents `AssumeRole` and repeated `GetPasswordData` calls with `Client.UnauthorizedOperation`. Record the role ARN, instance IDs, source IP, `eventID`, and UTC window. Do **not** describe this as recovered RDP passwords: the intended calls are denied.

## Validate and clean up

1. Wait for CloudTrail S3 delivery. Confirm log files exist under the expected account, Region, and date prefix. Search all delivered Regions for IAM global service events.
2. Run `athena/10_iam_admin_policy_hunt.sql` and `athena/20_ec2_password_spray_hunt.sql` with the actual UTC date window. If the burst falls across two fixed five-minute SQL bins, inspect adjacent raw events; the Sigma rule uses a rolling interval.
3. For each match, compare `eventID` and `userIdentity.arn` with the CloudTrail record. Record whether the Sigma backend emitted an alert, the alert ID, latency, and any misses.
4. Clean up each Stratus technique and inspect status:

```bash
stratus cleanup aws.persistence.iam-create-admin-user
stratus cleanup aws.credential-access.ec2-get-password-data
stratus status
```

5. Independently check that the lab IAM user, access key, and temporary role are gone. Keep the trail and logs until evidence is reviewed; then apply the agreed retention policy. Avoid `stratus cleanup --all` when unrelated techniques exist in the account. [Stratus cleanup](https://stratus-red-team.cloud/user-guide/commands/cleanup/) removes prerequisites as well as detonation effects; `revert` only reverses the detonation.

## Evidence record template

| Field | Record |
|---|---|
| Run ID / UTC window | |
| Sandbox account alias / Region | |
| Trail name / S3 prefix / management read-write enabled | |
| Stratus version and technique IDs | |
| Event IDs and actor ARN (redacted for public copy) | |
| Athena query IDs and result counts | |
| Sigma backend, mapping, converted query, alert IDs | |
| Detection latency and missed events | |
| Cleanup status and residual resources | |

The repository currently has no completed evidence record. Add a sanitized, dated report only after a real run.
