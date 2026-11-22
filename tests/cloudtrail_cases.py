"""Synthetic CloudTrail records in the Wazuh AWS integration envelope."""
from copy import deepcopy

ACCOUNT = "111122223333"
OTHER_ACCOUNT = "444455556666"
REGION = "us-east-1"
KEY = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-000000000001"
ACTOR = "arn:aws:sts::111122223333:assumed-role/Operations/session-a"


def event(service, name, request, response=None):
    return {"integration": "aws", "aws": {
        "source": "cloudtrail", "eventType": "AwsApiCall", "eventName": name,
        "eventSource": service + ".amazonaws.com", "recipientAccountId": ACCOUNT,
        "awsRegion": REGION, "userIdentity": {"type": "AssumedRole", "arn": ACTOR},
        "requestParameters": request, "responseElements": response or {}
    }}


def variant(record, **fields):
    record = deepcopy(record)
    record["aws"].update(fields)
    return record


def cases():
    disable = event("kms", "DisableKey", {"keyId": KEY.split("/")[-1]}, {"keyId": KEY})
    schedule = event("kms", "ScheduleKeyDeletion", {"keyId": KEY, "pendingWindowInDays": 7},
                     {"keyId": KEY, "keyState": "PendingDeletion"})
    group = {"logGroupName": "/services/billing"}
    unlink = event("logs", "DeleteSubscriptionFilter", dict(group, filterName="archive"))
    delete = event("logs", "DeleteLogGroup", group)
    stop = event("config", "StopConfigurationRecorder", {"configurationRecorderName": "default"})
    west = variant(stop, awsRegion="us-west-2")
    return [
        ("key-retirement", [disable, schedule], "110513"),
        ("replica-pending", [disable, variant(schedule, responseElements={
            "keyId": KEY, "keyState": "PendingReplicaDeletion"})], "110513"),
        ("different-key", [disable, variant(schedule, responseElements={
            "keyId": KEY[:-1] + "2", "keyState": "PendingDeletion"})], None),
        ("key-reversed", [schedule, disable], None),
        ("key-denied", [variant(disable, errorCode="AccessDenied", responseElements={}), schedule], None),
        ("key-missing-arn", [variant(disable, responseElements={}), schedule], None),
        ("subscription-then-group", [unlink, delete], "110523"),
        ("logs-cross-account", [unlink, variant(delete, recipientAccountId=OTHER_ACCOUNT)], None),
        ("logs-cross-region", [unlink, variant(delete, awsRegion="us-west-2")], None),
        ("logs-other-group", [unlink, variant(delete, requestParameters={"logGroupName": "/services/cart"})], None),
        ("logs-denied", [unlink, variant(delete, errorCode="AccessDeniedException")], None),
        ("logs-reversed", [delete, unlink], None),
        ("config-cross-region", [stop, west], "110532"),
        ("config-one-region", [stop, stop], None),
        ("config-other-account", [stop, variant(west, recipientAccountId=OTHER_ACCOUNT)], None),
        ("config-other-session", [stop, variant(west, userIdentity={"arn": ACTOR[:-1] + "b"})], None),
        ("config-denied", [variant(stop, errorCode="AccessDenied"), west], None),
    ]
