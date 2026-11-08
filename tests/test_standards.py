"""Synthetic checks for bounded, evidence-linked reference handling."""

import pytest
from aegistrace.standards import (
    FRAMEWORKS,
    ReportStandardReferenceCreate,
    framework_register,
    source_references,
    validate_mapping,
)


def test_versioned_catalogue_has_all_required_framework_families():
    assert {value["key"] for value in FRAMEWORKS} == {
        "nist-sp-800-115",
        "owasp-top-10-2025",
        "cve",
        "cvss",
        "cwe",
        "mitre-attack-enterprise",
        "nist-csf-2.0",
    }


def test_mapping_ids_are_curated_and_must_trace_to_the_finding():
    base = {
        "framework": "owasp-top-10-2025",
        "status": "applicable",
        "identifier": "A02:2025",
        "supporting_observation_ids": ["obs-test"],
        "rationale": "TEST ONLY reviewer mapping rationale.",
    }
    reference = ReportStandardReferenceCreate.model_validate(base)
    validate_mapping(reference, {"obs-test"})
    with pytest.raises(ValueError, match="versioned supported catalogue"):
        validate_mapping(
            ReportStandardReferenceCreate.model_validate(base | {"identifier": "A99:2025"}),
            {"obs-test"},
        )
    with pytest.raises(ValueError, match="among this finding"):
        validate_mapping(reference, {"different-observation"})


def test_source_identifiers_are_copied_not_invented_and_incomplete_cvss_stays_unknown():
    references = source_references(
        [
            {
                "id": "obs-test",
                "cve": "CVE-2024-12345",
                "cwe": "CWE-79",
                "cvss_score": 7.1,
                "cvss_version": "4.0",
                "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            },
            {
                "id": "obs-incomplete",
                "cve": None,
                "cwe": None,
                "cvss_score": 8.0,
                "cvss_version": "4.0",
                "cvss_vector": None,
            },
        ]
    )
    assert {value["identifier"] for value in references} == {
        "CVE-2024-12345",
        "CWE-79",
        "7.1 / 4.0",
    }
    assert all(value["relation"] == "source-reported" for value in references)


def test_malformed_source_identifiers_and_unsupported_cvss_stay_unmapped():
    references = source_references(
        [
            {
                "id": "obs-invalid",
                "cve": "CVE-not-an-id",
                "cwe": "CWE-0",
                "cvss_score": 11,
                "cvss_version": "4.0",
                "cvss_vector": "CVSS:4.0/AV:N",
            }
        ]
    )
    assert references == []


def test_framework_register_keeps_unsupported_mappings_unknown():
    register = framework_register([])
    statuses = {value["framework"]: value["status"] for value in register}
    assert len(statuses) == 7
    assert statuses["nist-sp-800-115"] == "methodology-reference"
    assert statuses["owasp-top-10-2025"] == "unknown"
    assert statuses["cve"] == "unknown"
    assert statuses["mitre-attack-enterprise"] == "unknown"
    assert statuses["nist-csf-2.0"] == "unknown"
