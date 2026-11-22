# Resource availability and audit coverage in AWS CloudTrail

These three temporal correlations cover encryption keys, log forwarding, and configuration recording. They use management events delivered by the Wazuh AWS integration. The XML extends the built-in AWS rule `80200`. The replay suite uses the same JSON envelope (`integration: "aws"`, `aws.source: "cloudtrail"`), with synthetic identifiers. [Rule definitions](../rules/aws_cloudtrail.xml)

| ID | Evidence required | Scope | Window |
|---|---|---|---:|
| `110513` | A successful `DisableKey` followed by `ScheduleKeyDeletion` returning a pending deletion state | Same key ARN and recipient account | 15 min |
| `110523` | A successful `DeleteSubscriptionFilter` followed by `DeleteLogGroup` | Same log group name, recipient account, and region | 10 min |
| `110532` | Two successful `StopConfigurationRecorder` calls in different regions | Same caller ARN and recipient account | 10 min |

### 110513 · Key retirement

A planned retirement may produce this sequence. Resolve the key ARN to its owner, check the approved retirement date, and identify workloads that still depend on the key. Both events must contain the canonical ARN in `responseElements.keyId`, so a request using a bare key ID can correlate with one using an ARN. For multi-Region primary keys, the rule accepts `PendingReplicaDeletion` as well as `PendingDeletion`. An alert establishes that deletion was scheduled; the key may still exist. [DisableKey audit record](https://docs.aws.amazon.com/kms/latest/developerguide/ct-disablekey.html) · [ScheduleKeyDeletion audit records](https://docs.aws.amazon.com/kms/latest/developerguide/ct-schedule-key-deletion.html)

### 110523 · Subscription removal followed by log group deletion

Identify the removed filter and its destination, then check the last event received at that destination. A group can have more than one delivery path, and previously forwarded copies can remain available. Compare the sequence with application decommissioning records before attributing any loss of coverage. Resource identity includes both region and recipient account because log group names can recur in each. [CloudWatch Logs subscription filter API](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteSubscriptionFilter.html)

### 110532 · Configuration recording stopped across regions

Verify the recorder status in both regions and identify the owner of the IAM principal or assumed-role session. A planned infrastructure migration may stop multiple recorders within one change window. The rule uses the full caller ARN; two different session ARNs for the same role remain separate. Confirm the interval of any recording gap from the recorder histories. [AWS Config recorder API](https://docs.aws.amazon.com/config/latest/APIReference/API_StopConfigurationRecorder.html)

## Collection and interpretation

Collect CloudTrail management write events for the relevant services, accounts, and regions. This ruleset expects one decoded Wazuh AWS event per record. Raw S3 files containing a top-level `Records` array require processing by the collector. The correlation window uses manager processing time. Send related events to the same manager under the same agent identity, including events from both regions for rule `110532`. Delayed batches or reversed delivery can change the observed sequence.

The rules exclude records containing an error field (`errorCode` or `errorMessage`). Detection also requires the fields listed in the XML. For example, an older KMS event that omits the response key ARN cannot establish a key match. When investigating an alert, use the original CloudTrail event IDs and event times to reconstruct the chronology.

## Reproduction

On a test manager with the standard Wazuh AWS rules loaded, confirm that the destination filename and custom rule IDs 110510–110532 are available. Run from the repository root:

```sh
sudo install -o root -g wazuh -m 0640 rules/aws_cloudtrail.xml /var/ossec/etc/rules/aws_cloudtrail.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo python3 tests/replay.py --suite cloudtrail
```

To inspect one pair of input records, run `python3 tests/replay.py --suite cloudtrail --emit subscription-then-group`. To exercise both suites on a manager with both rule files installed, use `--suite all`. For a Docker-based manager, append `--container CONTAINER_NAME` to the replay command.

The CloudTrail suite has four positive cases and thirteen controls. The controls exercise mismatched keys, accounts, regions, log groups and session identities, denied requests, and reversed event sequences. The results characterize rule behavior on synthetic inputs; production alert volume and delivery latency require measurements from the target environment. [Wazuh Manager 4.14.10 replay transcript](../tests/cloudtrail-4.14.10.txt)
