# Genuine scanner fixtures and ground truth - T05

**Current corpus:** zero genuine captures, zero labelled outcomes. No organizer permission is available; no target was scanned. The empty manifests are intentional and the readiness check returns not-ready. T05 remains open for actual permitted capture and independent review.

## Input required to complete T05

After T04 obtains genuine organizer permission, capture supported Nmap/ZAP/Nikto outputs and available optional tool exports. Keep original private bytes, hashes, exact tool version/output format, UTC/offset capture time, target pseudonym, capture/assessment reference and organizer authorization reference. Document ownership/redistribution basis and redaction review before any artifact is committed publicly. If the organizer supplies recorded native exports, retain their provenance and label them recorded imports, not live runs by this project.

Never fill the gap with model-generated scan output, fabricated CVEs or invented independent labels. Handcrafted malformed/parser test inputs remain `handcrafted_test` in `parser_test` only. They cannot become benchmark evidence or ground-truth outcomes.

## Corpus contract and verification

`tests/fixtures/manifest.json` and `evaluation/ground-truth.json` are versioned metadata. Each fixture records source kind, split, path/hash, tool/version/format, capture/authorization references, rights basis, redaction review and tuning use. Genuine data requires timezone-aware capture time and references. Public fixture paths require a redistribution record; unshareable originals belong under ignored `data/fixtures/`.

```powershell
uv run python scripts/check_fixture_corpus.py
```

The offline command checks bounded metadata, directory confinement, original byte hashes, unique IDs, split separation, independent-label associations and minimum source/scenario readiness. No metadata assertion proves a capture is authentic or legally shareable: a reviewer must inspect source provenance and rights. The command sends no traffic and produces no accuracy or calibrated-probability claim.

Required independent cases include true cross-tool duplicates, the same issue on distinct assets, contradictory evidence and clean controls. Label confirmed/suspected/false-positive/clean/contradictory outcomes with reviewer identity and supporting references. Use a reviewer independent of model/prompt tuning; if none is available, state that limitation and leave independent review pending.

## Training and held-out handling

Assign splits before tuning. The same artifact hash cannot appear in both training and held-out sets; held-out entries cannot be marked used-for-tuning. Keep all source-linked variants of one captured scenario in one split to avoid leakage; byte hashes alone cannot detect semantic duplicates, so the reviewer must inspect related captures too. Track reviewed scenario grouping when genuine data exists.

Report real fixture counts by source/tool/split, capture scope, limitations and known sampling bias. Small lab cases do not justify broad-world false-positive or calibration claims. T48 owns representative held-out evaluation and sample-size/uncertainty reporting. No minimum accuracy percentage is asserted by this workflow.

## Acceptance status

- [x] Schema and validator distinguish genuine captures, recorded imports and handcrafted parser tests.
- [x] Test-only metadata cases reject tampered hashes, traversal, false held-out use and synthetic ground truth.
- [ ] Genuine permitted tool outputs collected with complete provenance and rights.
- [ ] Independent labelled duplicate/distinct-asset/contradiction/clean cases inspected.
- [ ] Genuine training/held-out split counts and sampling bias recorded.

These unchecked items require organizer authorization, actual captures and human reviewer work. CI does not fabricate them merely to make the readiness command exit successfully.
