# Detection engineering write-up

## Hypothesis 1: unauthorized administrator grant

An attacker with IAM write access can establish a privileged identity by creating an IAM user and attaching the AWS-managed `AdministratorAccess` policy. Stratus emulates this with `aws.persistence.iam-create-admin-user`. The rule alerts on the **successful policy attachment**, because that is the privilege-changing action. It deliberately does not depend on the user name, Stratus tag, tool user agent, or the presence of a preceding `CreateUser`.

**Signal:** CloudTrail management event `iam.amazonaws.com:AttachUserPolicy`, `requestParameters.policyArn = arn:aws:iam::aws:policy/AdministratorAccess`, and no `errorCode`. Alert on the actor and target user; use `eventID` to deduplicate. The MITRE [T1098.003](https://attack.mitre.org/techniques/T1098/003/) tag describes an added cloud privilege. The adjacent `CreateUser` maps to [T1136.003](https://attack.mitre.org/techniques/T1136/003/), and `CreateAccessKey` to [T1098.001](https://attack.mitre.org/techniques/T1098/001/); neither is asserted by the single-event Sigma rule.

**Triage:** Verify change ticket, principal/session issuer, source IP, MFA context, account, target user, and policy ARN. Pivot over ±15 minutes for `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `AssumeRole`, and later API calls by the new key. Confirm whether an explicit deny or boundary limited effective permissions; policy attachment alone does not prove effective administrative access. If unauthorized, disable the key, remove the policy, preserve logs, and investigate the actor's credentials.

**False positives and misses:** Approved provisioning or break-glass access can match. A malicious actor may use `PutUserPolicy`, `AttachRolePolicy`, `PutRolePolicy`, group membership, or a custom admin policy instead; those are separate detection opportunities. If IAM global events are absent from the queried Region or management write events are excluded, this rule cannot fire.

## Hypothesis 2: denied RDP password retrieval spray

An attacker may probe `ec2:GetPasswordData` against many instances. The Stratus scenario assumes a role without this permission, then attempts the API against fictitious instance IDs. The resulting `Client.UnauthorizedOperation` events indicate **attempted** credential retrieval. Five denied calls from the same principal in five minutes is an investigation threshold; it is not a universal baseline.

**Signal:** CloudTrail management `ec2.amazonaws.com:GetPasswordData` and exact `Client.UnauthorizedOperation` error. Sigma counts events by `userIdentity.arn` over a rolling five-minute window. The Athena hunt uses fixed five-minute bins; a cluster split over a boundary may be missed until the analyst searches the raw events around the boundary. The [T1552](https://attack.mitre.org/techniques/T1552/) parent technique is used conservatively because the operation attempts to retrieve credentials. No private-key or cloud-metadata subtechnique is claimed.

**Triage:** Examine distinct target instance IDs, role session, `AssumeRole` origin, source IP, failed versus successful calls, permissions, and any subsequent `SendCommand`, `StartSession`, or network activity. Confirm the same principal was not an approved inventory or support workflow. A high number of denied calls does not establish that any Windows host existed or that a password was decrypted.

**False positives and misses:** Misconfigured support tooling can retry this API. A single successful retrieval does not meet the denied-burst rule and should be monitored by a separate high-severity analytic. Error wording or normalized field names can differ by SIEM; test the field mapping on native CloudTrail records. If the operator spreads requests across roles or time windows, the threshold may not be reached.

## Validation and acceptance criteria

| Check | Expected result |
|---|---|
| Collection | CloudTrail objects for the test window exist in the expected S3 prefix; Athena queries return the corresponding event IDs |
| IAM positive | One successful AWS-managed `AdministratorAccess` attachment produces one IAM alert; pivot finds the target user and adjacent events |
| IAM negative | A failed attachment or a different policy ARN does not produce this alert |
| EC2 positive | At least five denied calls by one principal within five minutes produce an EC2 correlation alert |
| EC2 negative | Four denied calls, or calls divided among different principals, do not produce that alert |
| Operational | Alert includes actor, UTC time, event IDs, account, Region, query or rule ID; Stratus resources are removed after validation |

These are **acceptance criteria**, not claimed test results. Before promoting the rules into a live paging policy, validate with benign and malicious CloudTrail samples, test the Sigma conversion for the chosen SIEM, measure delivery latency and false-positive rate, and document the on-call owner. For historical hunting, use Athena; for low-latency alerting, add a streaming delivery and a monitored execution schedule.

## Network evidence limits

VPC Flow Logs add instance network context only when there is an actual ENI and relevant traffic. The IAM scenario and the Stratus denied password scenario do not generate meaningful VPC evidence by themselves. `REJECT`/ `ACCEPT` are network decisions, not API authorization outcomes; `SKIPDATA` and aggregation can hide individual flows. An S3 data-theft claim would require S3 data events or another object-level source, plus correlation with principal and object identifiers. See [AWS CloudTrail data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html).
