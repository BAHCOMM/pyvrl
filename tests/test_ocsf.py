import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
import yaml

import pyvrl.ocsf.mapping as mapping_module
from pyvrl.ocsf import (
    InvalidEventError,
    Mapping,
    MappingError,
    NoRouteError,
    OCSF_VERSION,
    validate,
)
from pyvrl.ocsf.__main__ import main
from pyvrl.ocsf.editor import mapping_schema
from pyvrl.ocsf.schema import catalogue

FIXTURES = Path(__file__).parent / "fixtures" / "ocsf"
BUILTIN = sorted(mapping_module.BUILTIN_DIR.glob("*.yaml"))


def fixture(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def minimal_fields(**overrides):
    fields = {
        "activity_id": 1,
        "severity_id": 1,
        "time": "1000",
        "user": {"name": '"alice"'},
        "service": {"name": '"sshd"'},
        "metadata": {"product": {"name": '"sshd"'}},
    }
    return {**fields, **overrides}


def document(**fields):
    return {"source": "test", "routes": [{"class": "authentication",
                                          "fields": minimal_fields(**fields)}]}


# Catalogue

def test_catalogue_is_the_expected_version():
    data = catalogue()
    assert data["version"] == OCSF_VERSION == "1.9.0"
    assert len(data["classes"]) == 80
    assert len(data["objects"]) == 190

def test_profile_fields_are_tagged():
    attributes = catalogue()["classes"]["authentication"]["attributes"]
    assert attributes["osint"]["profiles"] == ["osint"]
    assert "profiles" not in attributes["user"]


# Compiling mappings

def test_generated_fields_are_filled_in():
    event = Mapping(document(), on_invalid="raise").convert({})
    assert event["class_uid"] == 3002
    assert event["class_name"] == "Authentication"
    assert event["category_uid"] == 3
    assert event["type_uid"] == 300201
    assert event["metadata"]["version"] == "1.9.0"

def test_type_uid_follows_activity_expression():
    mapping = Mapping(document(activity_id="if .x == 1 { 1 } else { 2 }"), on_invalid="raise")
    assert mapping.convert({"x": 2})["type_uid"] == 300202

def test_null_fields_are_dropped():
    event = Mapping(document(status_detail=".missing", src_endpoint={"ip": ".missing"})).convert({})
    assert "status_detail" not in event
    assert "src_endpoint" not in event

def test_empty_strings_are_dropped():
    event = Mapping(document(status_detail='""', src_endpoint={"ip": '""'}), on_invalid="raise").convert({})
    assert "status_detail" not in event
    assert "src_endpoint" not in event

def test_false_and_zero_are_kept():
    event = Mapping(document(is_mfa=False, status_id=0), on_invalid="raise").convert({})
    assert event["is_mfa"] is False
    assert event["status_id"] == 0

def test_let_variables_are_available():
    doc = document(status_detail="note")
    doc["let"] = {"note": '"hello"'}
    assert Mapping(doc).convert({})["status_detail"] == "hello"

def test_source_event_is_not_included_in_output():
    assert "password" not in Mapping(document()).convert({"password": "secret"})

def test_first_matching_route_wins():
    doc = {"source": "test", "routes": [
        {"when": ".x == 1", "class": "authentication", "fields": minimal_fields(activity_id=1)},
        {"when": ".x == 2", "class": "authentication", "fields": minimal_fields(activity_id=2)},
        {"class": "authentication", "fields": minimal_fields(activity_id=99)},
    ]}
    mapping = Mapping(doc, on_invalid="raise")
    assert [mapping.convert({"x": x})["activity_id"] for x in (1, 2, 3)] == [1, 2, 99]

def test_no_matching_route_raises():
    doc = document()
    doc["routes"][0]["when"] = ".x == 1"
    with pytest.raises(NoRouteError):
        Mapping(doc).convert({"x": 2})

def test_arrays_of_objects():
    doc = {"source": "test", "routes": [{"class": "detection_finding", "fields": {
        "activity_id": 1, "severity_id": 1, "time": "1000",
        "finding_info": {"uid": '"f1"'},
        "resources": [{"uid": '"a"'}, {"uid": '"b"'}],
        "metadata": {"product": {"name": '"p"'}},
    }}]}
    event = Mapping(doc, on_invalid="raise").convert({})
    assert event["resources"] == [{"uid": "a"}, {"uid": "b"}]

def test_profiles_are_declared_in_metadata():
    doc = document(cloud={"provider": '"AWS"'})
    doc["routes"][0]["profiles"] = ["cloud"]
    assert Mapping(doc, on_invalid="raise").convert({})["metadata"]["profiles"] == ["cloud"]


@pytest.mark.parametrize("change, message", [
    (lambda d: d["routes"][0].update({"class": "authentcation"}), "unknown OCSF class"),
    (lambda d: d["routes"][0]["fields"].update({"usr": {"name": ".x"}}), "unknown field usr"),
    (lambda d: d["routes"][0]["fields"]["user"].update({"nmae": ".x"}), "unknown field nmae"),
    (lambda d: d["routes"][0]["fields"].pop("severity_id"), "missing required field severity_id"),
    (lambda d: d["routes"][0]["fields"].update({"status_id": 77}), "invalid value 77"),
    (lambda d: d["routes"][0]["fields"].update({"cloud": {"provider": ".x"}}), "needs one of the profiles"),
    (lambda d: d["routes"][0].update({"profiles": ["nope"]}), "unknown OCSF profile"),
    (lambda d: d["routes"][0]["fields"].update({"status_id": {"a": ".x"}}), "is not an object"),
    (lambda d: d["routes"][0]["fields"].update({"user": [{"name": ".x"}]}), "is not an array"),
    (lambda d: d.update({"routes": []}), "at least one route"),
])
def test_bad_mappings_fail_at_load(change, message):
    doc = document()
    change(doc)
    with pytest.raises(MappingError, match=message):
        Mapping(doc)

def test_route_without_when_must_be_last():
    route = {"class": "authentication", "fields": minimal_fields()}
    with pytest.raises(MappingError, match="later routes can't match"):
        Mapping({"source": "test", "routes": [route, route]})

def test_invalid_vrl_fails_at_load():
    with pytest.raises(ValueError):
        Mapping(document(status_detail="upcase("))

def test_deprecated_class_warns():
    doc = {"source": "test", "routes": [{"class": "account_change", "fields": {
        "activity_id": 1, "severity_id": 1, "time": "1000", "user": {"name": '"a"'},
        "metadata": {"product": {"name": '"p"'}},
    }}]}
    with pytest.warns(DeprecationWarning, match="account_change"):
        Mapping(doc)

def test_unknown_builtin_raises():
    with pytest.raises(MappingError, match="no built-in mapping"):
        Mapping.builtin("nope")

def test_bad_on_invalid_raises():
    with pytest.raises(ValueError, match="on_invalid"):
        Mapping(document(), on_invalid="explode")


# Invalid events at runtime

def wrong_type_mapping(**options):
    return Mapping(document(status_detail="1"), **options)

def test_invalid_event_is_kept_with_a_warning_by_default(caplog):
    with caplog.at_level(logging.WARNING, logger="pyvrl.ocsf"):
        event = wrong_type_mapping().convert({})
    assert event["status_detail"] == 1
    assert "status_detail must be string" in caplog.text

def test_invalid_event_raises_when_asked():
    with pytest.raises(InvalidEventError, match="status_detail must be string"):
        wrong_type_mapping(on_invalid="raise").convert({})

def test_invalid_event_ignored_when_asked(caplog):
    with caplog.at_level(logging.WARNING, logger="pyvrl.ocsf"):
        wrong_type_mapping(on_invalid="ignore").convert({})
    assert not caplog.text


# Validation

def valid_event():
    return Mapping(document(), on_invalid="raise").convert({})

def test_valid_event_has_no_problems():
    assert validate(valid_event()) == []

@pytest.mark.parametrize("change, problem", [
    (lambda e: e.update({"usr": 1}), "unknown field usr"),
    (lambda e: e["user"].update({"nmae": "x"}), "unknown field user.nmae"),
    (lambda e: e.pop("metadata"), "missing required metadata"),
    (lambda e: e.update({"status_id": 77}), "status_id has invalid value 77"),
    (lambda e: e.update({"time": "soon"}), "time must be long"),
    (lambda e: e.update({"is_mfa": 1}), "is_mfa must be boolean"),
    (lambda e: e.update({"time": True}), "time must be long"),
    (lambda e: e.update({"user": "alice"}), "user must be an object"),
    (lambda e: e.update({"observables": {}}), "observables must be an array"),
    (lambda e: e.update({"src_endpoint": {"ip": "ec2.amazonaws.com"}}), "not an IP address"),
    (lambda e: e.pop("service"), "needs at least one of service, dst_endpoint"),
    (lambda e: e["user"].pop("name"), "user needs at least one of account, name, uid"),
])
def test_validate_finds_problems(change, problem):
    event = valid_event()
    change(event)
    assert any(problem in found for found in validate(event))

def test_profile_required_field_only_applies_with_the_profile():
    event = valid_event()
    assert not any("cloud" in problem for problem in validate(event))
    event["metadata"]["profiles"] = ["cloud"]
    assert "missing required cloud" in validate(event)

def test_validate_rejects_non_events():
    assert validate("nope") == ["event is str, not an object"]
    assert validate({"class_uid": 1}) == ["unknown class_uid 1"]

def test_generic_object_accepts_anything():
    event = valid_event()
    event["unmapped"] = {"anything": {"at": ["all"]}}
    assert validate(event) == []


# Built-in mappings

@pytest.mark.parametrize("path", BUILTIN, ids=lambda p: p.stem)
def test_builtin_mappings_load_without_warnings(path, recwarn):
    assert Mapping.load(path).source == path.stem
    assert not recwarn.list

@pytest.mark.parametrize("name", fixture("aws_cloudtrail"))
def test_cloudtrail_events_are_valid(name):
    event = Mapping.builtin("aws_cloudtrail", on_invalid="raise").convert(fixture("aws_cloudtrail")[name])
    assert validate(event) == []

def test_cloudtrail_console_login():
    mapping = Mapping.builtin("aws_cloudtrail", on_invalid="raise")
    event = mapping.convert(fixture("aws_cloudtrail")["console_login_success"])
    assert event["class_uid"] == 3002
    assert event["status_id"] == 1
    assert event["is_mfa"] is True
    assert event["user"]["name"] == "alice"
    assert event["src_endpoint"] == {"ip": "203.0.113.10"}
    assert event["time"] == 1772600767000

def test_cloudtrail_failed_login():
    mapping = Mapping.builtin("aws_cloudtrail", on_invalid="raise")
    event = mapping.convert(fixture("aws_cloudtrail")["console_login_failure"])
    assert event["status_id"] == 2
    assert event["status_detail"] == "Failed authentication"
    assert event["is_mfa"] is False

@pytest.mark.parametrize("name, activity, status", [
    ("read_call", 2, 1),
    ("denied_delete", 4, 2),
    ("service_call", 3, 1),
])
def test_cloudtrail_api_calls(name, activity, status):
    mapping = Mapping.builtin("aws_cloudtrail", on_invalid="raise")
    event = mapping.convert(fixture("aws_cloudtrail")[name])
    assert event["class_uid"] == 6003
    assert event["activity_id"] == activity
    assert event["status_id"] == status
    assert event["type_uid"] == 600300 + activity

@pytest.mark.parametrize("operation, read_only, activity", [
    ("DescribeInstances", None, 2),
    ("ListBuckets", None, 2),
    ("GetPolicy", False, 2),
    ("SomeNewRead", True, 2),
    ("RunInstances", None, 1),
    ("TerminateInstances", None, 4),
    ("DeleteRestApi", True, 4),
    ("CreateDeployment", True, 1),
    ("AssumeRole", None, 99),
    ("AuthorizeSecurityGroupIngress", None, 3),
])
def test_cloudtrail_activity_comes_from_the_operation(operation, read_only, activity):
    record = {**fixture("aws_cloudtrail")["denied_delete"], "eventName": operation}
    record.pop("readOnly")
    if read_only is not None:
        record["readOnly"] = read_only
    event = Mapping.builtin("aws_cloudtrail", on_invalid="raise").convert(record)
    assert event["activity_id"] == activity

def test_cloudtrail_insight_is_a_finding():
    record = {"eventVersion": "1.07", "eventTime": "2026-03-04T05:06:07Z", "eventID": "insight-1",
              "eventType": "AwsCloudTrailInsight", "awsRegion": "us-east-1",
              "recipientAccountId": "111122223333",
              "insightDetails": {"state": "End", "eventName": "AttachUserPolicy",
                                 "insightType": "ApiCallRateInsight"}}
    event = Mapping.builtin("aws_cloudtrail", on_invalid="raise").convert(record)
    assert event["class_uid"] == 2004
    assert event["activity_id"] == 3
    assert event["finding_info"]["title"] == "CloudTrail Insight: ApiCallRateInsight"

def test_cloudtrail_digest_has_no_route():
    with pytest.raises(NoRouteError):
        Mapping.builtin("aws_cloudtrail").convert({"awsAccountId": "1", "digestEndTime": "x"})

def test_guardduty_empty_batch_has_no_route():
    with pytest.raises(NoRouteError):
        Mapping.builtin("aws_guardduty").convert({"findings": []})

def test_cloudtrail_role_user_name():
    mapping = Mapping.builtin("aws_cloudtrail", on_invalid="raise")
    event = mapping.convert(fixture("aws_cloudtrail")["read_call"])
    assert event["actor"]["user"]["name"] == "deploy-role"

def test_cloudtrail_service_address_is_not_an_ip():
    mapping = Mapping.builtin("aws_cloudtrail", on_invalid="raise")
    event = mapping.convert(fixture("aws_cloudtrail")["service_call"])
    assert event["src_endpoint"] == {"svc_name": "kms.amazonaws.com"}
    assert event["actor"]["application"]["name"] == "kms.amazonaws.com"
    assert event["actor"]["user"]["name"] == "kms.amazonaws.com"

VPC_ACCEPT = ("2 123456789010 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 "
              "20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK")
VPC_REJECT = ("2 123456789010 eni-1235b8ca123456789 172.31.9.69 172.31.9.12 "
              "49761 3389 6 20 4249 1418530010 1418530070 REJECT OK")
VPC_NODATA = "2 123456789010 eni-11111111aaaaaaaaa - - - - - - - 1431280876 1431280934 - NODATA"

def test_vpc_flow_accepted():
    event = Mapping.builtin("aws_vpc_flow", on_invalid="raise").convert({"message": VPC_ACCEPT})
    assert event["class_uid"] == 4001
    assert event["action_id"] == 1
    assert event["src_endpoint"]["ip"] == "172.31.16.139"
    assert event["src_endpoint"]["port"] == 20641
    assert event["dst_endpoint"] == {"ip": "172.31.16.21", "port": 22}
    assert event["traffic"] == {"packets": 20, "bytes": 4249}
    assert event["connection_info"]["protocol_num"] == 6
    assert event["time"] == 1418530070000
    assert validate(event) == []

def test_vpc_flow_rejected():
    event = Mapping.builtin("aws_vpc_flow", on_invalid="raise").convert({"message": VPC_REJECT})
    assert event["action_id"] == 2

CUSTOM_FORMAT = "version srcaddr dstaddr end start action log-status flow-direction region bytes"

def test_vpc_flow_custom_format_reads_columns_by_name():
    line = "5 10.0.0.1 10.0.0.2 200 100 REJECT OK egress us-west-2 77"
    event = Mapping.builtin("aws_vpc_flow", on_invalid="raise").convert(
        {"message": line, "log_format": CUSTOM_FORMAT})
    assert event["src_endpoint"] == {"ip": "10.0.0.1"}
    assert event["action_id"] == 2
    assert event["start_time"] == 100_000
    assert event["time"] == 200_000
    assert event["connection_info"]["direction_id"] == 2
    assert event["cloud"]["region"] == "us-west-2"
    assert event["traffic"] == {"bytes": 77}

def test_vpc_flow_dash_means_no_value():
    line = "5 10.0.0.1 - 200 100 ACCEPT OK - - 77"
    event = Mapping.builtin("aws_vpc_flow", on_invalid="raise").convert(
        {"message": line, "log_format": CUSTOM_FORMAT})
    assert "dst_endpoint" not in event
    assert event["connection_info"]["direction_id"] == 0

def test_vpc_flow_missing_numbers_stay_missing():
    columns = "version srcaddr dstaddr srcport dstport bytes end start action log-status"
    line = "5 10.0.0.1 10.0.0.2 - - - 200 100 ACCEPT OK"
    event = Mapping.builtin("aws_vpc_flow", on_invalid="raise").convert(
        {"message": line, "log_format": columns})
    assert event["src_endpoint"] == {"ip": "10.0.0.1"}
    assert "traffic" not in event

def test_vpc_flow_missing_time_fails_rather_than_becoming_1970():
    line = "5 10.0.0.1 10.0.0.2 - 100 ACCEPT OK - - 77"
    with pytest.raises(ValueError, match="remap failure"):
        Mapping.builtin("aws_vpc_flow").convert({"message": line, "log_format": CUSTOM_FORMAT})

def test_vpc_flow_wrong_column_count_has_no_route():
    with pytest.raises(NoRouteError):
        Mapping.builtin("aws_vpc_flow").convert({"message": "5 10.0.0.1", "log_format": CUSTOM_FORMAT})

def test_vpc_flow_line_with_trailing_newline():
    event = Mapping.builtin("aws_vpc_flow", on_invalid="raise").convert({"message": VPC_ACCEPT + "\n"})
    assert event["time"] == 1418530070000

def test_vpc_flow_bad_timestamp_fails_rather_than_becoming_1970():
    line = VPC_ACCEPT.replace("1418530070", "soon")
    with pytest.raises(ValueError, match="remap failure"):
        Mapping.builtin("aws_vpc_flow").convert({"message": line})

@pytest.mark.parametrize("line", [VPC_NODATA, "", "version account-id"])
def test_vpc_flow_without_traffic_has_no_route(line):
    with pytest.raises(NoRouteError):
        Mapping.builtin("aws_vpc_flow").convert({"message": line})

@pytest.mark.parametrize("name, severity", [("ec2_finding", 4), ("s3_finding", 2)])
def test_guardduty_findings(name, severity):
    mapping = Mapping.builtin("aws_guardduty", on_invalid="raise")
    event = mapping.convert(fixture("aws_guardduty")[name])
    assert event["class_uid"] == 2004
    assert event["severity_id"] == severity
    assert validate(event) == []

def test_guardduty_finding_details():
    mapping = Mapping.builtin("aws_guardduty", on_invalid="raise")
    event = mapping.convert(fixture("aws_guardduty")["ec2_finding"])
    assert event["finding_info"]["uid"] == "finding-1"
    assert event["finding_info"]["types"] == ["UnauthorizedAccess:EC2/SSHBruteForce"]
    assert event["resources"][0]["uid"] == "i-0123456789abcdef0"

@pytest.mark.parametrize("resource, name", [
    ({"resourceType": "EKSCluster", "eksClusterDetails": {"name": "prod"}}, "prod"),
    ({"resourceType": "RDSDBInstance", "rdsDbInstanceDetails": {"dbInstanceIdentifier": "db1"}}, "db1"),
    ({"resourceType": "S3Bucket", "s3BucketDetails": [{"name": "logs"}]}, "logs"),
    ({"resourceType": "AccessKey", "accessKeyDetails": {"userName": "alice"}}, "alice"),
    ({"resourceType": "Instance", "instanceDetails": {"instanceId": "i-1"}}, "i-1"),
    ({"resourceType": "Lambda"}, "Lambda"),
])
def test_guardduty_names_the_affected_resource(resource, name):
    finding = {**fixture("aws_guardduty")["ec2_finding"], "resource": resource}
    event = Mapping.builtin("aws_guardduty", on_invalid="raise").convert(finding)
    assert event["resources"][0]["name"] == name
    assert event["resources"][0]["type"] == resource["resourceType"]

def test_guardduty_inside_eventbridge():
    mapping = Mapping.builtin("aws_guardduty", on_invalid="raise")
    finding = fixture("aws_guardduty")["ec2_finding"]
    wrapped = {"source": "aws.guardduty", "detail": finding}
    assert mapping.convert(wrapped)["finding_info"]["uid"] == "finding-1"

@pytest.mark.parametrize("score, severity", [
    (0, 0), (0.5, 0), (1, 2), (3.9, 2), (4, 3), (6.9, 3), (7, 4), (8.9, 4), (9, 5), (10, 5),
])
def test_guardduty_severity_bands(score, severity):
    mapping = Mapping.builtin("aws_guardduty", on_invalid="raise")
    finding = {**fixture("aws_guardduty")["ec2_finding"], "severity": score}
    assert mapping.convert(finding)["severity_id"] == severity


def auth0_event(code, **fields):
    return {"log_id": "log-1", "data": {
        "date": "2026-03-04T05:06:07.000Z", "type": code, "ip": "203.0.113.10",
        "user_agent": "Mozilla/5.0", "client_id": "client-1", "client_name": "Portal",
        "user_id": "auth0|abc", "user_name": "alice@example.com", "description": "Something",
        **fields,
    }}

@pytest.mark.parametrize("code, class_uid, activity, status", [
    ("s", 3002, 1, 1),
    ("f", 3002, 1, 2),
    ("fp", 3002, 1, 2),
    ("slo", 3002, 2, 1),
    ("seacft", 3002, 99, 1),
    ("ferrt", 3002, 99, 2),
    ("gd_auth_succeed", 3002, 99, 1),
    ("gd_auth_failed", 3002, 99, 2),
    ("ss", 3007, 1, 1),
    ("fs", 3007, 1, 2),
    ("sdu", 3007, 3, 1),
    ("scp", 3007, 8, 1),
    ("scpr", 3007, 9, 1),
    ("ublkdu", 3007, 7, 1),
    ("gd_enrollment_complete", 3007, 12, 1),
    ("gd_unenroll", 3007, 13, 1),
    ("sce", 3007, 2, 1),
])
def test_auth0_codes(code, class_uid, activity, status):
    event = Mapping.builtin("auth0", on_invalid="raise").convert(auth0_event(code))
    assert event["class_uid"] == class_uid
    assert event["activity_id"] == activity
    assert event["status_id"] == status
    assert event["metadata"]["event_code"] == code
    assert event["metadata"]["uid"] == "log-1"
    assert event["src_endpoint"]["ip"] == "203.0.113.10"
    assert event["time"] == 1772600767000

@pytest.mark.parametrize("method, activity", [
    ("get", 2), ("POST", 1), ("patch", 3), ("put", 3), ("delete", 4), ("OPTIONS", 0),
])
def test_auth0_api_activity_comes_from_the_method(method, activity):
    log = auth0_event("sapi", details={"request": {"method": method, "path": "/api/v2/users"}})
    event = Mapping.builtin("auth0", on_invalid="raise").convert(log)
    assert event["class_uid"] == 6003
    assert event["activity_id"] == activity
    assert event["api"]["operation"] == "Something"

def test_auth0_failed_api_call():
    event = Mapping.builtin("auth0", on_invalid="raise").convert(auth0_event("fapi"))
    assert event["status_id"] == 2

@pytest.mark.parametrize("code, severity", [("limit_wc", 3), ("limit_mu", 3), ("pwd_leak", 4)])
def test_auth0_detections(code, severity):
    event = Mapping.builtin("auth0", on_invalid="raise").convert(auth0_event(code))
    assert event["class_uid"] == 2004
    assert event["severity_id"] == severity
    assert event["finding_info"]["uid"] == "log-1"
    assert event["evidences"][0]["src_endpoint"]["ip"] == "203.0.113.10"

@pytest.mark.parametrize("code", ["sys_os_update_start", "gd_send_sms", "fn", "brand_new_code"])
def test_auth0_noise_has_no_route(code):
    with pytest.raises(NoRouteError):
        Mapping.builtin("auth0").convert(auth0_event(code))

def test_auth0_without_the_log_stream_wrapper():
    event = Mapping.builtin("auth0", on_invalid="raise").convert(auth0_event("s")["data"] | {"log_id": "log-2"})
    assert event["metadata"]["uid"] == "log-2"

def test_auth0_keeps_user_id_without_inventing_a_name():
    log = auth0_event("sapi", user_name="", client_name="")
    event = Mapping.builtin("auth0", on_invalid="raise").convert(log)
    assert event["actor"]["user"] == {"uid": "auth0|abc"}

def test_auth0_with_no_identity_at_all():
    log = auth0_event("f", user_name="", client_name="", user_id="")
    event = Mapping.builtin("auth0", on_invalid="raise").convert(log)
    assert event["user"] == {"name": "unknown"}

def test_auth0_email_only_when_user_name_is_one():
    mapping = Mapping.builtin("auth0", on_invalid="raise")
    assert mapping.convert(auth0_event("s"))["user"]["email_addr"] == "alice@example.com"
    assert "email_addr" not in mapping.convert(auth0_event("s", user_name="alice"))["user"]

def test_auth0_bad_date_fails():
    with pytest.raises(ValueError, match="remap failure"):
        Mapping.builtin("auth0").convert(auth0_event("s", date="soon"))


def azure_signin(category="SignInLogs", error_code=0, **properties):
    return {
        "time": "2026-03-04T05:06:07.1234567Z", "category": category, "tenantId": "tenant-1",
        "correlationId": "corr-1", "operationName": "Sign-in activity", "resultType": str(error_code),
        "properties": {
            "id": "signin-1", "ipAddress": "203.0.113.10", "status": {"errorCode": error_code},
            "userPrincipalName": "alice@example.com", "userId": "user-1", "appId": "app-1",
            "appDisplayName": "Portal", "resourceDisplayName": "Microsoft Graph", "resourceId": "res-1",
            "isInteractive": True, "authenticationProtocol": "none",
            "location": {"city": "Paris", "state": "Ile-de-France", "countryOrRegion": "FR"},
            **properties,
        },
    }

def test_azure_signin_success():
    event = Mapping.builtin("azure_signin", on_invalid="raise").convert(azure_signin())
    assert event["class_uid"] == 3002
    assert event["status_id"] == 1
    assert event["time"] == 1772600767123
    assert event["user"]["name"] == "alice@example.com"
    assert event["user"]["uid"] == "user-1"
    assert event["user"]["type_id"] == 1
    assert event["service"] == {"name": "Microsoft Graph", "uid": "res-1"}
    assert event["src_endpoint"]["location"]["country"] == "FR"
    assert event["metadata"]["correlation_uid"] == "corr-1"
    assert event["logon_type_id"] == 2

@pytest.mark.parametrize("code, status_id", [
    (0, 1), (50126, 2), (50053, 2), (7000215, 2), (50140, 99), (50074, 99), (50076, 99),
])
def test_azure_signin_outcomes(code, status_id):
    event = Mapping.builtin("azure_signin", on_invalid="raise").convert(azure_signin(error_code=code))
    assert event["status_id"] == status_id
    assert event["status_code"] == str(code)

def test_azure_signin_interrupted_is_named():
    event = Mapping.builtin("azure_signin", on_invalid="raise").convert(azure_signin(error_code=50140))
    assert event["status"] == "Interrupted"

@pytest.mark.parametrize("category", ["ServicePrincipalSignInLogs", "ManagedIdentitySignInLogs"])
def test_azure_signin_without_a_user(category):
    log = azure_signin(category, userPrincipalName="", userId=None, servicePrincipalName="deploy-bot",
                       servicePrincipalId="sp-1", ipAddress="", isInteractive=False)
    event = Mapping.builtin("azure_signin", on_invalid="raise").convert(log)
    assert event["user"]["name"] == "deploy-bot"
    assert event["user"]["uid"] == "sp-1"
    assert event["user"]["type_id"] == 4
    assert event["logon_type_id"] == 99
    assert "ip" not in event.get("src_endpoint", {})

@pytest.mark.parametrize("risk, severity", [("high", 4), ("medium", 3), ("low", 2), ("none", 1)])
def test_azure_signin_severity_follows_risk(risk, severity):
    log = azure_signin(riskLevelDuringSignIn=risk)
    assert Mapping.builtin("azure_signin", on_invalid="raise").convert(log)["severity_id"] == severity

@pytest.mark.parametrize("protocol, protocol_id", [
    ("oAuth2", 6), ("ropc", 6), ("deviceCode", 6), ("saml20", 5), ("wsFederation", 99), ("none", 0),
])
def test_azure_signin_protocols(protocol, protocol_id):
    log = azure_signin(authenticationProtocol=protocol)
    event = Mapping.builtin("azure_signin", on_invalid="raise").convert(log)
    assert event["auth_protocol_id"] == protocol_id

def test_azure_signin_device():
    log = azure_signin(deviceDetail={"deviceId": "dev-1", "displayName": "LAPTOP", "isCompliant": True,
                                     "isManaged": False})
    device = Mapping.builtin("azure_signin", on_invalid="raise").convert(log)["device"]
    assert device == {"type_id": 0, "uid": "dev-1", "name": "LAPTOP", "is_compliant": True,
                      "is_managed": False}

def test_azure_signin_empty_device_is_dropped():
    log = azure_signin(deviceDetail={"deviceId": "", "displayName": ""})
    assert "device" not in Mapping.builtin("azure_signin", on_invalid="raise").convert(log)

def test_azure_signin_mfa_only_when_stated():
    mapping = Mapping.builtin("azure_signin", on_invalid="raise")
    assert "is_mfa" not in mapping.convert(azure_signin())
    required = azure_signin(authenticationRequirement="multiFactorAuthentication")
    assert mapping.convert(required)["is_mfa"] is True
    single = azure_signin(authenticationRequirement="singleFactorAuthentication")
    assert mapping.convert(single)["is_mfa"] is False

def test_azure_signin_lowercase_export_keys():
    log = azure_signin(ipAddress="")
    del log["correlationId"]
    log.update(calleripaddress="203.0.113.20", correlationid="corr-2")
    event = Mapping.builtin("azure_signin", on_invalid="raise").convert(log)
    assert event["src_endpoint"]["ip"] == "203.0.113.20"
    assert event["metadata"]["correlation_uid"] == "corr-2"

@pytest.mark.parametrize("log", [
    {"category": "AuditLogs", "properties": {}, "time": "2026-03-04T05:06:07Z"},
    {"category": "SignInLogs", "time": "2026-03-04T05:06:07Z"},
    {},
])
def test_azure_signin_other_logs_have_no_route(log):
    with pytest.raises(NoRouteError):
        Mapping.builtin("azure_signin").convert(log)

@pytest.mark.parametrize("value, expected", [
    ("2026-03-04T05:06:07Z", 1772600767000),
    ("2026-03-04 05:06:07.123", 1772600767123),
    ("3/4/2026 5:06:07 AM", 1772600767000),
])
def test_azure_signin_time_formats(value, expected):
    log = {**azure_signin(), "time": value}
    assert Mapping.builtin("azure_signin", on_invalid="raise").convert(log)["time"] == expected

def test_azure_signin_bad_time_fails():
    with pytest.raises(ValueError, match="remap failure"):
        Mapping.builtin("azure_signin").convert({**azure_signin(), "time": "soon"})

ZONELESS_DATE_PROGRAM = """
from pyvrl.ocsf import Mapping
log = {"date": "2026-03-04 05:06:07.000000000", "type": "s", "log_id": "x", "user_id": "u", "ip": "203.0.113.10"}
print(Mapping.builtin("auth0").convert(log)["time"])
azure = {"time": "2026-03-04 05:06:07.000", "category": "SignInLogs", "properties": {"userId": "u"}}
print(Mapping.builtin("azure_signin").convert(azure)["time"])
"""

@pytest.mark.parametrize("zone", ["UTC", "Asia/Tokyo", "America/New_York"])
def test_dates_without_a_zone_are_utc_on_any_server(zone):
    result = subprocess.run([sys.executable, "-c", ZONELESS_DATE_PROGRAM], capture_output=True,
                            text=True, check=True, env={**os.environ, "TZ": zone})
    assert result.stdout.split() == ["1772600767000", "1772600767000"]


# Editor schema

def test_editor_schema_is_valid_json_schema():
    jsonschema.Draft7Validator.check_schema(mapping_schema())

@pytest.mark.parametrize("path", BUILTIN, ids=lambda p: p.stem)
def test_builtin_mappings_match_the_editor_schema(path):
    jsonschema.validate(yaml.safe_load(path.read_text()), mapping_schema())

@pytest.mark.parametrize("change", [
    lambda d: d["routes"][0]["fields"].update({"usr": ".x"}),
    lambda d: d["routes"][0]["fields"]["user"].update({"nmae": ".x"}),
    lambda d: d["routes"][0].update({"class": "authentcation"}),
    lambda d: d["routes"][0]["fields"].update({"status_id": 77}),
    lambda d: d["routes"][0]["fields"].pop("severity_id"),
])
def test_editor_schema_catches_mistakes(change):
    doc = document()
    jsonschema.validate(doc, mapping_schema())
    change(doc)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, mapping_schema())

def test_editor_schema_offers_nested_fields_and_enum_values():
    schema = mapping_schema()
    authentication = schema["$defs"]["class_authentication"]["properties"]
    assert authentication["user"]["anyOf"][0] == {"$ref": "#/$defs/object_user"}
    assert "name" in schema["$defs"]["object_user"]["properties"]
    assert 2 in authentication["status_id"]["anyOf"][0]["enum"]
    assert "2 = Failure" in authentication["status_id"]["description"]

def test_editor_schema_hides_generated_and_deprecated():
    schema = mapping_schema()
    assert "class_uid" not in schema["$defs"]["class_authentication"]["properties"]
    assert "account_change" not in schema["properties"]["routes"]["items"]["properties"]["class"]["enum"]

def test_cli_writes_the_committed_schema(tmp_path):
    output = tmp_path / "schema.json"
    assert main(["schema", str(output)]) == 0
    committed = Path(__file__).parent.parent / "schemas" / "ocsf-mapping.schema.json"
    assert output.read_text() == committed.read_text()

def test_cli_rejects_bad_arguments(capsys):
    assert main([]) == 2
    assert "schema FILE" in capsys.readouterr().err
