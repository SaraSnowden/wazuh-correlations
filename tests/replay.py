"""Replay each case in its own wazuh-logtest session."""
import argparse
import copy
import json
import re
import subprocess
from uuid import NAMESPACE_URL, uuid5


def event(verb, resource, name, *, group="", sub="", code=200, stage="ResponseComplete"):
    namespace = "payments"
    ref = {"namespace": namespace, "resource": resource, "name": name}
    prefix = f"/apis/{group}/v1" if group else "/api/v1"
    uri = f"{prefix}/namespaces/{namespace}/{resource}"
    if verb != "create" or sub:
        uri += "/" + name
    if group:
        ref["apiGroup"] = group
    if sub:
        ref["subresource"] = sub
        uri += "/" + sub
    return {"apiVersion": "audit.k8s.io/v1", "kind": "Event", "stage": stage, "verb": verb,
            "requestURI": uri, "user": {"username": "oncall"}, "objectRef": ref,
            "responseStatus": {"code": code}}


def changed(e, path, value):
    result = copy.deepcopy(e)
    node = result
    keys = path.split(".")
    for key in keys[:-1]:
        node = node[key]
    old = node.get(keys[-1])
    node[keys[-1]] = value
    if path in ("objectRef.namespace", "objectRef.name"):
        result["requestURI"] = result["requestURI"].replace("/" + old, "/" + value)
    return result


def cases():
    edit = event("patch", "pods", "ledger", sub="ephemeralcontainers")
    attach = event("create", "pods", "ledger", sub="attach", stage="ResponseStarted", code=101)
    bind = event("create", "rolebindings", "support", group="rbac.authorization.k8s.io", code=201)
    drop = event("delete", "rolebindings", "support", group="rbac.authorization.k8s.io")
    token = event("create", "serviceaccounts", "reports", sub="token", code=201)
    token_b = changed(token, "objectRef.name", "billing")
    policy = event("delete", "networkpolicies", "default-deny", group="networking.k8s.io")
    policy_b = changed(policy, "objectRef.namespace", "analytics")
    return [
        ("pod-attach", [edit, attach], "110413"),
        ("unrelated-pod", [edit, changed(attach, "objectRef.name", "api")], None),
        ("same-pod-name-elsewhere", [edit, changed(attach, "objectRef.namespace", "dev")], None),
        ("attach-came-first", [attach, edit], None),
        ("attach-only", [attach, attach], None),
        ("short-lived-binding", [bind, drop], "110423"),
        ("different-binding", [bind, changed(drop, "objectRef.name", "view")], None),
        ("dry-run-grant", [changed(bind, "requestURI", bind["requestURI"] + "?dryRun=All"), drop], None),
        ("delete-only", [drop, drop], None),
        ("token-pair", [token, token_b], "110432"),
        ("same-token-target", [token, token], None),
        ("tokens-in-different-namespaces", [token, changed(token_b, "objectRef.namespace", "dev")], None),
        ("different-requester", [token, changed(token_b, "user.username", "release")], None),
        ("kubelet-rotation", [changed(t, "user.username", "system:node:worker-1") for t in (token, token_b)], None),
        ("cross-namespace-cleanup", [policy, policy_b], "110442"),
        ("same-namespace-cleanup", [policy, changed(policy, "objectRef.name", "allow-dns")], None),
        ("second-delete-denied", [policy, changed(policy_b, "responseStatus.code", 403)], None),
    ]


ALERTS = {"110413", "110423", "110432", "110442"}


def records(name, events):
    for index, entry in enumerate(events):
        yield json.dumps(dict(entry, auditID=str(uuid5(NAMESPACE_URL, f"{name}/{index}"))))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", help="run logtest via docker exec")
    parser.add_argument("--emit", help="print one named JSONL fixture")
    args = parser.parse_args()
    cmd = ["/var/ossec/bin/wazuh-logtest"]
    if args.container:
        cmd = ["docker", "exec", "-i", args.container] + cmd
    scenarios = cases()
    if args.emit:
        for name, events, _ in scenarios:
            if name == args.emit:
                print(*records(name, events), sep="\n")
                return
        parser.error("unknown case")
    failures = 0
    for name, events, target in scenarios:
        batch = "\n".join(records(name, events)) + "\n"
        result = subprocess.run(cmd, input=batch, capture_output=True, text=True, timeout=60)
        output = result.stdout + result.stderr
        hits = re.findall(r"^\s*id: '([0-9]+)'", output, re.MULTILINE)
        actual = [sid for sid in hits if sid in ALERTS]
        expected = [target] if target else []
        if result.returncode or output.count("Phase 2: Completed decoding.") != len(events) or actual != expected:
            print(f"FAIL {name}: expected {expected}, got {hits}\n{output}")
            failures += 1
        else:
            print(f"PASS {name}: {', '.join(hits)}")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
