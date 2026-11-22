# Temporal Correlation of Audit Events in Wazuh

The repository contains seven temporal correlations for two audit sources. Each suite includes Wazuh XML rules, synthetic event sequences, and a replay transcript from Wazuh Manager 4.14.10.

| Audit source | Detection coverage |
|---|---|
| [AWS CloudTrail](docs/cloudtrail.md) | KMS key retirement, CloudWatch Logs subscription and group deletion, and AWS Config recorder stops across regions |
| [Kubernetes Audit](#kubernetes-audit) | Interactive pod access, short-lived role bindings, token issuance, and network policy deletion |

## Kubernetes Audit

Four rules identify changes in access and network isolation from sequences of Kubernetes API requests. Each rule defines which fields must match or differ across events and how closely in time the events must occur. The rules use the built-in Wazuh JSON decoder and accept one Kubernetes audit event per line. The accompanying tests run on a Wazuh manager without access to a Kubernetes cluster.

## Detection criteria

| Rule ID | Observed sequence | Correlation window | Wazuh level |
|---|---|---:|---:|
| `110413` | A successful change to `pods/ephemeralcontainers` is followed by the start of a `pods/attach` stream for the same pod name and namespace. | 5 min | 9 |
| `110423` | The API server accepts the creation and subsequent deletion of a RoleBinding with the same name in the same namespace. | 3 min | 8 |
| `110432` | The same principal obtains tokens for two distinct ServiceAccounts in one namespace. The rule excludes principals whose usernames begin with `system:node:`. | 90 s | 8 |
| `110442` | The same principal successfully deletes a named NetworkPolicy in each of two distinct namespaces. | 2 min | 10 |

The [rule definitions](rules/kube_audit.xml) specify the qualifying API verbs, response codes, audit stages, and correlation fields.

## Interpretation of alerts

### 110413 · Interactive access following an ephemeral container change

Check the maintenance window, the ephemeral container image, and the `container` parameter of the attach request. The correlation identifies the pod by name and namespace. The stream may target another container in that pod, and a different operator may have made the original change. For a documented troubleshooting session, the service owner and the associated ticket can help establish the purpose of both operations.

### 110423 · Short-lived role binding

A RoleBinding may already have disappeared from the cluster by the time an analyst investigates. Locate the creation event and recover the `subjects` and `roleRef` fields from configuration history or a retained request body. Review the subjects' API activity during the interval and compare it with records from temporary access systems and continuous integration jobs. The event sequence establishes when the binding was created and deleted. Determining whether a subject exercised the permissions requires additional audit evidence.

### 110432 · Token issuance for distinct service accounts

Determine whether the requesting principal is authorized to obtain tokens for both service accounts. A credential broker may routinely act on behalf of several accounts within a namespace. Where this behavior warrants an exception, scope the exception to the principal and namespace. Audit records at the Kubernetes `Metadata` level provide the fields required for this analysis without recording token contents.

### 110442 · Network policy deletion across namespaces

Compare the deletions with namespace decommissioning records and GitOps reconciliation logs. Recover the selectors of the deleted policies and identify the policies that still apply to the affected pods. Their combined coverage determines whether the deletions changed network isolation. The rule covers individual `delete` requests. A bulk operation submitted through `deletecollection` falls outside its scope.

## Audit data and collection

The rules read `apiVersion`, `kind`, `verb`, `user.username`, `requestURI`, `objectRef`, `stage`, and `responseStatus.code`. Preserve the `ResponseStarted` stage for attach requests and `ResponseComplete` for the other operations. The object name must be available in `objectRef.name`. The `Metadata` audit level is sufficient for detection. [Kubernetes auditing documentation](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

For file-based collection, configure the Wazuh agent with the actual audit log path and the `json` log format.

```xml
<localfile>
  <location>/var/log/kubernetes/audit.log</location>
  <log_format>json</log_format>
</localfile>
```

Events in a single correlation sequence must reach the same Wazuh manager through the same agent. Use a separate source agent for each cluster. In a highly available control plane, consolidate the audit streams from the cluster's API servers and preserve event order. The manager evaluates the correlation window as it processes incoming records. Delivery delays, reordering, and accelerated replay of archived events can therefore affect the result. The rules exclude standard dry-run requests containing `dryRun=All`. [Wazuh rule syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)

## Validation method and results

On Wazuh Manager 4.14.10, all four positive cases produced their expected correlation alerts. None of the thirteen control cases triggered any of the four correlations. The controls include reversed event order, identically named pods in different namespaces, repeated token issuance for one service account, and a denied policy deletion. These synthetic cases test rule behavior under specified conditions. They provide no estimate of the false-positive rate in an operational cluster. [Replay results for all 17 cases](tests/wazuh-4.14.10.txt)

The [test runner](tests/replay.py) starts a separate `wazuh-logtest` session for each case, submits the records in order, and compares the observed correlation rule IDs with the expected sequence. A mismatch produces a nonzero exit status. The transcript also lists supporting rule IDs when Wazuh reports a rule match for an individual record.

## Reproducing the evaluation

On a test manager, verify that the rule IDs in the range 110410–110442 and the destination filename are available. From the repository root, install the rule file, validate the configuration, and run the test suite.

```sh
sudo install -o root -g wazuh -m 0640 rules/kube_audit.xml /var/ossec/etc/rules/kube_audit.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo python3 tests/replay.py
```

To inspect the two input records for the short-lived RoleBinding case, use the following command.

```sh
python3 tests/replay.py --emit short-lived-binding
```

For a containerized manager, copy the XML file to the same rules directory inside the container. From the host, run `python3 tests/replay.py --container CONTAINER_NAME`, substituting the manager container's name.

To enable the rules for live events after validation, restart the manager service during the agreed maintenance window. To roll back the deployment, remove the rule file from the local rules directory, validate the configuration again, and restart the service.
