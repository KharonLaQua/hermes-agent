from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace

import pytest

from hermes_cli.scoped_terminal_permits import (
    ScopedTerminalPermitError,
    ScopedTerminalPermitIssuer,
)


_HEX_A = "a" * 64
_HEX_B = "b" * 64
_HEX_C = "c" * 64


def _contract(tmp_path):
    profile_home = tmp_path / "profile"
    workspace = tmp_path / "workspace"
    source = tmp_path / "source.bin"
    manifest = tmp_path / "manifest.json"
    for path in (profile_home, workspace):
        path.mkdir(exist_ok=True)
    source.write_bytes(b"reviewed")
    manifest.write_text("[]", encoding="utf-8")
    operation = {
        "index": 0,
        "kind": "rclone_copy",
        "argv": ["rclone", "copyto", str(source), "vault:reviewed/source.bin"],
        "cwd": str(workspace),
        "background": False,
        "pty": False,
        "source_ref": "source",
        "destination_ref": "destination",
        "manifest_ref": None,
        "execution_context_digest": _HEX_C,
    }
    return {
        "profile": "bookkeeper",
        "profile_home": str(profile_home),
        "workspace": str(workspace),
        "source": {
            "kind": "file",
            "canonical_path": str(source),
            "expected_size_bytes": len(b"reviewed"),
            "content_sha256": hashlib.sha256(b"reviewed").hexdigest(),
            "manifest_path": str(manifest),
            "manifest_sha256": _HEX_A,
        },
        "destination": {
            "kind": "rclone_remote",
            "canonical_uri": "vault:reviewed/source.bin",
        },
        "operation_sequence": [operation],
        "authorized_operation_index": 0,
        "predecessor_receipt_digest": None,
        "command_digest": _HEX_B,
    }


@pytest.fixture
def permit_factory(monkeypatch, tmp_path):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    monkeypatch.delenv("HERMES_DELEGATED_CHILD_CONTEXT", raising=False)
    now = [1_800_000_000]
    events = []
    lock_owned = [True]
    issuer = ScopedTerminalPermitIssuer(
        issuer_profile="default",
        max_ttl_seconds=120,
        lock_owner_check=lambda: lock_owned[0],
        clock=lambda: now[0],
        audit_writer=lambda kind, payload: events.append((kind, payload)),
    )

    def issue(*, audit_writer=None):
        active = issuer
        active.arm_next_run(
            board_slug="default",
            task_id="t_storage",
            contract=_contract(tmp_path),
            ttl_seconds=60,
            evidence_task_id="t_evidence",
            evidence_artifact_digest=_HEX_A,
        )
        envelope = active.activate_for_spawn(
            board_slug="default",
            task_id="t_storage",
            run_id=17,
            profile="bookkeeper",
            profile_home=str(tmp_path / "profile"),
            workspace=str(tmp_path / "workspace"),
        )
        payload = json.loads(envelope.payload)
        context = {
            key: copy.deepcopy(payload[key])
            for key in (
                "board_slug",
                "task_id",
                "run_id",
                "profile",
                "profile_home",
                "workspace",
                "source",
                "destination",
                "operation_sequence",
                "authorized_operation_index",
                "predecessor_receipt_digest",
                "command_digest",
            )
        }
        return active, envelope, context, payload

    return issue, issuer, now, events, lock_owned


def test_worker_process_cannot_arm_or_sign_permit(monkeypatch):
    monkeypatch.setenv("HERMES_KANBAN_TASK", "t_worker")
    with pytest.raises(PermissionError, match="worker"):
        ScopedTerminalPermitIssuer(
            issuer_profile="default",
            lock_owner_check=lambda: True,
        )


def test_delegated_child_cannot_create_issuer(monkeypatch):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    monkeypatch.setenv("HERMES_DELEGATED_CHILD_CONTEXT", "1")
    with pytest.raises(PermissionError, match="delegated"):
        ScopedTerminalPermitIssuer(
            issuer_profile="default",
            lock_owner_check=lambda: True,
        )


def test_issuer_rejects_missing_profile(monkeypatch):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    with pytest.raises(PermissionError, match="issuer profile"):
        ScopedTerminalPermitIssuer(
            issuer_profile="   ",
            lock_owner_check=lambda: True,
        )


@pytest.mark.parametrize("ttl", [True, 0, -1, 301, 1.5, "60"])
def test_issuer_rejects_invalid_ttl(monkeypatch, ttl):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    with pytest.raises(ValueError, match="ttl"):
        ScopedTerminalPermitIssuer(
            issuer_profile="default",
            max_ttl_seconds=ttl,
            lock_owner_check=lambda: True,
        )


def test_issuer_requires_and_retains_dispatcher_ownership(monkeypatch, tmp_path):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    with pytest.raises(PermissionError, match="lock owner"):
        ScopedTerminalPermitIssuer(
            issuer_profile="default",
            lock_owner_check=lambda: False,
        )

    owned = [True]
    issuer = ScopedTerminalPermitIssuer(
        issuer_profile="default",
        lock_owner_check=lambda: owned[0],
    )
    owned[0] = False
    with pytest.raises(ScopedTerminalPermitError) as exc:
        issuer.arm_next_run(
            board_slug="default",
            task_id="t_storage",
            contract=_contract(tmp_path),
            ttl_seconds=60,
            evidence_task_id="t_evidence",
            evidence_artifact_digest=_HEX_A,
        )
    assert exc.value.failure_class == "issuer_unavailable"


def test_arm_copies_an_immutable_normalized_contract(permit_factory, tmp_path):
    _, issuer, _, _, _ = permit_factory
    contract = _contract(tmp_path)
    original_path = contract["source"]["canonical_path"]
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_immutable",
        contract=contract,
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    contract["source"]["canonical_path"] = "/tampered"
    envelope = issuer.activate_for_spawn(
        board_slug="default",
        task_id="t_immutable",
        run_id=18,
        profile="bookkeeper",
        profile_home=str(tmp_path / "profile"),
        workspace=str(tmp_path / "workspace"),
    )
    assert json.loads(envelope.payload)["source"]["canonical_path"] == original_path


def test_activate_binds_claimed_run_profile_home_and_workspace(permit_factory):
    issue, _, _, _, _ = permit_factory
    _, envelope, _, payload = issue()
    assert payload["version"] == 1
    assert payload["run_id"] == 17
    assert payload["profile"] == "bookkeeper"
    assert payload["profile_home"].endswith("/profile")
    assert payload["workspace"].endswith("/workspace")
    assert len(bytes.fromhex(payload["nonce"])) == 32
    assert envelope.signature
    assert not ({"private_key", "signing_key", "key_material"} & set(payload))


def test_exact_permit_consumes_once_and_replay_is_denied(permit_factory):
    issue, _, _, events, _ = permit_factory
    issuer, envelope, context, payload = issue()
    allowed = issuer.consume(envelope, context=context, challenge="fresh-challenge")
    replay = issuer.consume(envelope, context=context, challenge="new-challenge")
    assert allowed.allowed is True
    assert allowed.failure_class is None
    assert issuer.permit_status(payload["permit_id"]) == "consumed"
    assert replay.allowed is False
    assert replay.failure_class == "replay"
    assert [kind for kind, _ in events][-2:] == [
        "terminal_permit_consumed",
        "terminal_permit_rejected",
    ]


@pytest.mark.parametrize(
    ("field", "mutation", "failure_class"),
    [
        ("task_id", "other", "task_mismatch"),
        ("run_id", 99, "run_mismatch"),
        ("profile", "other", "profile_mismatch"),
        ("profile_home", "/other/profile", "profile_home_mismatch"),
        ("workspace", "/other/workspace", "workspace_mismatch"),
        ("source.canonical_path", "/other/source", "source_mismatch"),
        ("source.expected_size_bytes", 999, "size_mismatch"),
        ("source.content_sha256", _HEX_C, "hash_mismatch"),
        ("destination.canonical_uri", "vault:other", "destination_mismatch"),
        ("operation_sequence", [], "operation_sequence_mismatch"),
        ("command_digest", _HEX_C, "command_mismatch"),
    ],
)
def test_binding_mutation_fails_closed(permit_factory, field, mutation, failure_class):
    issue, _, _, _, _ = permit_factory
    issuer, envelope, context, payload = issue()
    if "." in field:
        outer, inner = field.split(".")
        context[outer][inner] = mutation
    else:
        context[field] = mutation
    decision = issuer.consume(envelope, context=context, challenge="fresh")
    assert decision.allowed is False
    assert decision.failure_class == failure_class
    assert issuer.permit_status(payload["permit_id"]) == "rejected"


def test_lifecycle_and_envelope_failures_are_stable(permit_factory):
    issue, _, now, _, _ = permit_factory
    issuer, envelope, context, _ = issue()
    now[0] += 61
    assert issuer.consume(envelope, context=context, challenge="fresh").failure_class == "expired"

    issuer2, envelope2, context2, _ = issue()
    malformed = replace(envelope2, payload=b"not-json")
    assert issuer2.consume(malformed, context=context2, challenge="fresh").failure_class == "malformed"

    issuer3, envelope3, context3, _ = issue()
    payload3 = json.loads(envelope3.payload)
    payload3["task_id"] = "tampered"
    tampered = replace(
        envelope3,
        payload=json.dumps(payload3, sort_keys=True, separators=(",", ":")).encode(),
    )
    assert issuer3.consume(tampered, context=context3, challenge="fresh").failure_class == "signature_invalid"


def test_not_yet_valid_and_unknown_payload_fields_fail_closed(permit_factory):
    issue, _, now, _, _ = permit_factory
    issuer, envelope, context, _ = issue()
    now[0] -= 1
    assert issuer.consume(envelope, context=context, challenge="fresh").failure_class == "not_yet_valid"

    now[0] += 1
    issuer2, envelope2, context2, _ = issue()
    payload = json.loads(envelope2.payload)
    payload["unknown"] = "field"
    malformed = replace(
        envelope2,
        payload=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
    )
    assert issuer2.consume(malformed, context=context2, challenge="fresh").failure_class == "malformed"


def test_consume_marks_terminal_before_allow_response(monkeypatch, tmp_path):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    holder = {}
    observed = []

    def audit(kind, payload):
        if kind == "terminal_permit_consumed":
            observed.append(holder["issuer"].permit_status_from_digest(payload["permit_id_digest"]))

    issuer = ScopedTerminalPermitIssuer(
        issuer_profile="default",
        lock_owner_check=lambda: True,
        clock=lambda: 1_800_000_000,
        audit_writer=audit,
    )
    holder["issuer"] = issuer
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_storage",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    envelope = issuer.activate_for_spawn(
        board_slug="default",
        task_id="t_storage",
        run_id=17,
        profile="bookkeeper",
        profile_home=str(tmp_path / "profile"),
        workspace=str(tmp_path / "workspace"),
    )
    payload = json.loads(envelope.payload)
    context = {key: copy.deepcopy(payload[key]) for key in issuer.CONTEXT_FIELDS}
    assert issuer.consume(envelope, context=context, challenge="fresh").allowed is True
    assert observed == ["consumed"]


def test_audit_failure_spends_permit_and_denies(monkeypatch, tmp_path):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)

    def audit(kind, payload):
        if kind == "terminal_permit_consumed":
            raise OSError("audit unavailable")

    issuer = ScopedTerminalPermitIssuer(
        issuer_profile="default",
        lock_owner_check=lambda: True,
        clock=lambda: 1_800_000_000,
        audit_writer=audit,
    )
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_storage",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    envelope = issuer.activate_for_spawn(
        board_slug="default",
        task_id="t_storage",
        run_id=17,
        profile="bookkeeper",
        profile_home=str(tmp_path / "profile"),
        workspace=str(tmp_path / "workspace"),
    )
    payload = json.loads(envelope.payload)
    context = {key: copy.deepcopy(payload[key]) for key in issuer.CONTEXT_FIELDS}
    denied = issuer.consume(envelope, context=context, challenge="fresh")
    assert denied.allowed is False
    assert denied.failure_class == "audit_failed"
    assert issuer.permit_status(payload["permit_id"]) == "rejected"
    assert issuer.consume(envelope, context=context, challenge="again").failure_class == "replay"


def test_audit_payload_is_secret_and_content_free(permit_factory, tmp_path):
    issue, _, _, events, _ = permit_factory
    issuer, envelope, context, _ = issue()
    assert issuer.consume(envelope, context=context, challenge="fresh").allowed is True
    allowed_keys = issuer.AUDIT_FIELDS
    raw_forbidden = {
        str(tmp_path / "source.bin"),
        str(tmp_path / "workspace"),
        "vault:reviewed/source.bin",
        "fresh",
        envelope.signature.hex(),
    }
    for _, payload in events:
        assert set(payload) <= allowed_keys
        serialized = json.dumps(payload, sort_keys=True)
        assert all(value not in serialized for value in raw_forbidden)


def test_close_erases_authority_and_rejects_future_actions(permit_factory, tmp_path):
    _, issuer, _, _, _ = permit_factory
    issuer.close()
    assert issuer.closed is True
    assert issuer.public_key_bytes is None
    with pytest.raises(ScopedTerminalPermitError) as exc:
        issuer.arm_next_run(
            board_slug="default",
            task_id="t_storage",
            contract=_contract(tmp_path),
            ttl_seconds=60,
            evidence_task_id="t_evidence",
            evidence_artifact_digest=_HEX_A,
        )
    assert exc.value.failure_class == "issuer_unavailable"
