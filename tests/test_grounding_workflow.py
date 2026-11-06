"""Synthetic claim -> proposal -> frozen JSON/PDF checks; never genuine evidence."""

from uuid import UUID

from aegistrace.evidence import EvidenceStore
from aegistrace.evidence_schema import objects
from aegistrace.schema_v1 import observations
from sqlalchemy import select
from test_nmap import source

pytest_plugins = ("test_ingestion",)


def test_structured_claims_are_grounded_before_export_and_prose_is_excluded(import_context):
    client, config = import_context
    base, headers, imported, _, _, evidence = source(import_context)
    normalized = client.post(
        base + "/imports/" + imported["id"] + "/normalize-nmap", json={}, headers=headers()
    )
    assert normalized.status_code == 201, normalized.text
    assessment_id = UUID(base.rsplit("/", 1)[-1])
    with client.app.state.engine.begin() as connection:
        EvidenceStore(config).redact(connection, assessment_id, UUID(evidence["id"]), "owner")
        connection.execute(
            objects.update().where(objects.c.id == evidence["id"]).values(redaction_reviewed=True)
        )
        observation = dict(
            connection.execute(
                select(observations.c.payload).where(
                    observations.c.assessment_id == str(assessment_id)
                )
            )
            .scalars()
            .first()
        )
    citation = {
        "observation_id": observation["id"],
        "asset_id": observation["asset_id"],
        "evidence_id": evidence["id"],
    }
    proposal = client.post(
        base + "/reasoning/proposals",
        headers=headers(),
        json={
            "purpose": "report-narrative",
            "narrative": "UNSUPPORTED_MODEL_PROSE claims the host is compromised.",
            "source_evidence_ids": [evidence["id"]],
            "claims": [
                citation | {"type": "title", "value": observation["title"]},
                citation | {"type": "confirmation", "value": "confirmed"},
                citation | {"type": "remediation", "value": "UNSUPPORTED_REMEDIATION"},
                citation | {"type": "cve", "value": "CVE-2099-9999"},
                citation
                | {"type": "title", "value": observation["title"], "asset_id": "wrong-asset"},
                citation
                | {
                    "type": "title",
                    "value": observation["title"],
                    "requires_external_validation": True,
                },
            ],
        },
    )
    assert proposal.status_code == 201, proposal.text
    value = proposal.json()
    assert value["claims"][0]["state"] == "source-supported"
    assert all(
        row["state"] == "unknown" and row["value"] is None and row["reasons"]
        for row in value["claims"][1:]
    )
    assert value["reportable_narrative"] is None and value["findings_created"] == 0
    frozen = client.post(
        base + "/result-exports",
        headers=headers(),
        json={"revision_ids": [normalized.json()["result_revision_id"]]},
    )
    assert frozen.status_code == 201, frozen.text
    snapshot = frozen.json()["snapshot"]
    assert len(snapshot["content"]["grounded_claims"]) == 6
    assert (
        "external-advisory-validation-unavailable"
        in snapshot["content"]["grounded_claims"][-1]["reasons"]
    )
    assert "UNSUPPORTED_MODEL_PROSE" not in str(snapshot)
    assert "UNSUPPORTED_REMEDIATION" not in str(snapshot)
    assert "CVE-2099-9999" not in str(snapshot)
    pdf = client.get(base + "/result-exports/" + frozen.json()["id"] + "/pdf", headers=headers())
    assert pdf.status_code == 200 and b"Structured claim checks" in pdf.content
    assert b"UNSUPPORTED_MODEL_PROSE" not in pdf.content
    assert b"claim-type-not-supported" in pdf.content
    # Later proposal records never rewrite a previously frozen report.
    again = client.get(base + "/result-exports/" + frozen.json()["id"], headers=headers())
    assert again.json()["sha256"] == frozen.json()["sha256"]
