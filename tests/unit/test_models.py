"""Unit tests for core data models."""

from dast.models import (
    AttackPayload,
    Endpoint,
    EndpointParameter,
    Finding,
    HttpRequest,
    HttpResponse,
    Severity,
    AttackVerdict,
)


def test_endpoint_has_parameters():
    ep = Endpoint(
        url="https://app.example.com/api/users",
        method="GET",
        parameters=[
            EndpointParameter(name="id", location="query", value="1")
        ],
    )
    assert len(ep.parameters) == 1
    assert ep.parameters[0].name == "id"


def test_finding_severity_enum():
    assert Severity.CRITICAL.value == "CRITICAL"
    assert Severity.HIGH.value == "HIGH"


def test_attack_verdict_enum():
    assert AttackVerdict.VULNERABLE.value == "VULNERABLE"
    assert AttackVerdict.NEEDS_RETRY.value == "NEEDS_RETRY"


def test_http_request_defaults():
    req = HttpRequest(method="GET", url="https://example.com")
    assert req.body is None
    assert req.headers == {}
