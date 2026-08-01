from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
from dataclasses import replace

import pytest

import hermes_cli.scoped_terminal_permits as permits
from hermes_cli.scoped_terminal_permits import (
    PreparedPermitTicket,
    ScopedTerminalPermitError,
    ScopedTerminalPermitIssuer,
    claim_worker_permit_channel,
    prepare_scoped_terminal_permit,
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


@pytest.mark.parametrize(
    ("kind", "argv"),
    [
        ("rclone_copy", ["sh", "-c", "rclone copyto source destination"]),
        ("rclone_copy", ["bash", "-c", "rclone copyto source destination"]),
        ("rclone_copy", ["rclone", "copyto", "source", "destination", "&&", "rm"]),
        ("rclone_copy", ["rclone", "copyto", "source", "destination", "|"]),
        ("rclone_copy", ["rclone", "copyto", "source", "destination", ">", "out"]),
        ("rclone_copy", ["rclone", "copyto", "$(touch", "source)", "destination"]),
        ("rclone_copy", ["rclone", "purge", "source"]),
        ("rclone_copy", ["rclone", "delete", "source"]),
        ("rclone_copy", ["rclone", "copyto", "*.bin", "vault:reviewed/source.bin"]),
        ("unlink_manifest_batch", ["rm", "-r", "--", "/tmp/source.bin"]),
        ("unlink_manifest_batch", ["rm", "--", "/tmp/unrelated.bin"]),
        ("unknown_operation", ["anything"]),
    ],
)
def test_arm_rejects_forbidden_operation_before_pending_arm(
    permit_factory, tmp_path, kind, argv
):
    _, issuer, _, events, _ = permit_factory
    contract = _contract(tmp_path)
    contract["operation_sequence"][0]["kind"] = kind
    contract["operation_sequence"][0]["argv"] = argv

    with pytest.raises(ScopedTerminalPermitError) as exc:
        issuer.arm_next_run(
            board_slug="default",
            task_id="t_forbidden",
            contract=contract,
            ttl_seconds=60,
            evidence_task_id="t_evidence",
            evidence_artifact_digest=_HEX_A,
        )

    assert exc.value.failure_class == "operation_forbidden"
    assert events == []
    with pytest.raises(ScopedTerminalPermitError) as missing:
        issuer.activate_for_spawn(
            board_slug="default",
            task_id="t_forbidden",
            run_id=17,
            profile="bookkeeper",
            profile_home=str(tmp_path / "profile"),
            workspace=str(tmp_path / "workspace"),
        )
    assert missing.value.failure_class == "missing"


@pytest.mark.parametrize(
    "path_mutation",
    [
        lambda contract, tmp_path: contract["operation_sequence"][0].update(
            cwd=str(tmp_path / "workspace" / ".." / "workspace")
        ),
        lambda contract, tmp_path: contract["operation_sequence"][0]["argv"].__setitem__(
            2, "relative/source.bin"
        ),
    ],
)
def test_arm_rejects_relative_or_traversal_operation_paths(
    permit_factory, tmp_path, path_mutation
):
    _, issuer, _, events, _ = permit_factory
    contract = _contract(tmp_path)
    path_mutation(contract, tmp_path)

    with pytest.raises(ScopedTerminalPermitError) as exc:
        issuer.arm_next_run(
            board_slug="default",
            task_id="t_path_forbidden",
            contract=contract,
            ttl_seconds=60,
            evidence_task_id="t_evidence",
            evidence_artifact_digest=_HEX_A,
        )

    assert exc.value.failure_class == "operation_forbidden"
    assert events == []


def test_arm_accepts_exact_rclone_verify_argv(permit_factory, tmp_path):
    _, issuer, _, _, _ = permit_factory
    contract = _contract(tmp_path)
    source = contract["source"]["canonical_path"]
    destination = contract["destination"]["canonical_uri"]
    contract["operation_sequence"][0]["kind"] = "rclone_verify"
    contract["operation_sequence"][0]["argv"] = ["rclone", "check", source, destination]
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_verify",
        contract=contract,
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    envelope = issuer.activate_for_spawn(
        board_slug="default",
        task_id="t_verify",
        run_id=17,
        profile="bookkeeper",
        profile_home=str(tmp_path / "profile"),
        workspace=str(tmp_path / "workspace"),
    )
    assert json.loads(envelope.payload)["operation_sequence"][0]["kind"] == "rclone_verify"


@pytest.mark.parametrize("kind", ["unlink_manifest_batch", "rmdir_manifest_batch"])
def test_arm_accepts_manifest_bounded_batch_forms(permit_factory, tmp_path, kind):
    _, issuer, _, _, _ = permit_factory
    contract = _contract(tmp_path)
    root = str(tmp_path)
    contract["source"]["kind"] = "directory"
    contract["source"]["canonical_path"] = root
    contract["operation_sequence"][0]["kind"] = kind
    contract["operation_sequence"][0]["manifest_ref"] = "manifest"
    if kind == "unlink_manifest_batch":
        targets = [str(tmp_path / "file-a.bin"), str(tmp_path / "nested" / "file-b.bin")]
        executable = "rm"
    else:
        targets = [str(tmp_path / "nested" / "empty"), str(tmp_path / "nested")]
        executable = "rmdir"
    contract["operation_sequence"][0]["argv"] = [executable, "--", *targets]
    issuer.arm_next_run(
        board_slug="default",
        task_id=f"t_{kind}",
        contract=contract,
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )


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


def test_active_issuer_registry_installs_one_and_uninstalls_by_identity(monkeypatch):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    monkeypatch.delenv("HERMES_DELEGATED_CHILD_CONTEXT", raising=False)
    issuers = [
        ScopedTerminalPermitIssuer(
            issuer_profile="default",
            lock_owner_check=lambda: True,
        )
        for _ in range(2)
    ]
    barrier = threading.Barrier(3)
    results: list[tuple[ScopedTerminalPermitIssuer, bool]] = []

    def install(issuer):
        barrier.wait()
        results.append((issuer, permits.install_active_issuer(issuer)))

    threads = [threading.Thread(target=install, args=(issuer,)) for issuer in issuers]
    try:
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()

        assert sorted(installed for _, installed in results) == [False, True]
        winner = next(issuer for issuer, installed in results if installed)
        loser = next(issuer for issuer, installed in results if not installed)
        assert permits.get_active_issuer() is winner
        assert permits.uninstall_active_issuer(loser) is False
        assert permits.get_active_issuer() is winner
        assert permits.uninstall_active_issuer(winner) is True
        assert permits.get_active_issuer() is None

        assert permits.install_active_issuer(loser) is True
        assert permits.uninstall_active_issuer(winner) is False
        assert permits.get_active_issuer() is loser
    finally:
        for issuer in issuers:
            permits.uninstall_active_issuer(issuer)
            issuer.close()


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


@pytest.mark.parametrize(
    ("activation", "failure_class"),
    [
        ({"profile": "other"}, "profile_mismatch"),
        ({"profile_home": "other-profile"}, "profile_home_mismatch"),
        ({"workspace": "other-workspace"}, "workspace_mismatch"),
    ],
)
def test_activation_identity_mismatch_cancels_pending_arm(
    permit_factory, tmp_path, activation, failure_class
):
    _, issuer, _, events, _ = permit_factory
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_activation_mismatch",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    args = {
        "board_slug": "default",
        "task_id": "t_activation_mismatch",
        "run_id": 19,
        "profile": "bookkeeper",
        "profile_home": str(tmp_path / "profile"),
        "workspace": str(tmp_path / "workspace"),
    }
    args.update(
        {
            key: value if key == "profile" else str(tmp_path / value)
            for key, value in activation.items()
        }
    )

    with pytest.raises(ScopedTerminalPermitError) as exc:
        issuer.activate_for_spawn(**args)

    assert exc.value.failure_class == failure_class
    assert issuer._permits == {}
    assert events[-1][0] == "terminal_permit_cancelled"
    assert events[-1][1]["failure_class"] == failure_class
    with pytest.raises(ScopedTerminalPermitError) as missing:
        issuer.activate_for_spawn(**args)
    assert missing.value.failure_class == "missing"


def test_pending_arm_expiry_cancels_and_requires_fresh_arm(permit_factory, tmp_path):
    _, issuer, now, events, _ = permit_factory
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_expiring_arm",
        contract=_contract(tmp_path),
        ttl_seconds=5,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    now[0] += 6
    activation = {
        "board_slug": "default",
        "task_id": "t_expiring_arm",
        "run_id": 19,
        "profile": "bookkeeper",
        "profile_home": str(tmp_path / "profile"),
        "workspace": str(tmp_path / "workspace"),
    }

    with pytest.raises(ScopedTerminalPermitError) as exc:
        issuer.activate_for_spawn(**activation)

    assert exc.value.failure_class == "expired"
    assert issuer._permits == {}
    assert events[-1][0] == "terminal_permit_cancelled"
    assert events[-1][1]["failure_class"] == "expired"
    with pytest.raises(ScopedTerminalPermitError) as missing:
        issuer.activate_for_spawn(**activation)
    assert missing.value.failure_class == "missing"

    issuer.arm_next_run(
        board_slug="default",
        task_id="t_expiring_arm",
        contract=_contract(tmp_path),
        ttl_seconds=5,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    fresh = issuer.activate_for_spawn(**activation)
    assert issuer.permit_status(fresh.permit_id) == "issued"


def test_activation_audit_failure_rejects_permit_and_requires_fresh_arm(
    permit_factory, tmp_path, monkeypatch
):
    _, issuer, _, _, _ = permit_factory
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_activation_audit",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    original_audit_writer = issuer._audit_writer

    def fail_activation(kind, payload):
        if kind == "terminal_permit_activated":
            raise OSError("activation audit unavailable")
        original_audit_writer(kind, payload)

    monkeypatch.setattr(issuer, "_audit_writer", fail_activation)
    activation = {
        "board_slug": "default",
        "task_id": "t_activation_audit",
        "run_id": 19,
        "profile": "bookkeeper",
        "profile_home": str(tmp_path / "profile"),
        "workspace": str(tmp_path / "workspace"),
    }

    with pytest.raises(ScopedTerminalPermitError) as exc:
        issuer.activate_for_spawn(**activation)

    assert exc.value.failure_class == "audit_failed"
    permit_id, = issuer._permits
    assert issuer.permit_status(permit_id) == "rejected"
    with pytest.raises(ScopedTerminalPermitError) as missing:
        issuer.activate_for_spawn(**activation)
    assert missing.value.failure_class == "missing"

    monkeypatch.setattr(issuer, "_audit_writer", original_audit_writer)
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_activation_audit",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    fresh = issuer.activate_for_spawn(**activation)
    assert fresh.permit_id != permit_id
    assert issuer.permit_status(fresh.permit_id) == "issued"


def test_spawn_channel_creation_failure_cancels_issued_permit(
    permit_factory, tmp_path, monkeypatch
):
    _, issuer, _, _, _ = permit_factory
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_spawn_channel_failure",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )

    def fail_socketpair():
        raise OSError("socketpair unavailable")

    monkeypatch.setattr(permits.socket, "socketpair", fail_socketpair)
    activation = {
        "board_slug": "default",
        "task_id": "t_spawn_channel_failure",
        "run_id": 19,
        "profile": "bookkeeper",
        "profile_home": str(tmp_path / "profile"),
        "workspace": str(tmp_path / "workspace"),
    }
    with pytest.raises(ScopedTerminalPermitError) as exc:
        issuer.activate_spawn_channel(**activation)

    assert exc.value.failure_class == "channel_failed"
    permit_id, = issuer._permits
    assert issuer.permit_status(permit_id) == "cancelled"
    with pytest.raises(ScopedTerminalPermitError) as missing:
        issuer.activate_spawn_channel(**activation)
    assert missing.value.failure_class == "missing"


def test_spawn_channel_is_one_fd_and_cancellation_spends_fresh_arm(
    permit_factory, tmp_path
):
    _, issuer, _, _, _ = permit_factory
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_spawn",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    channel = issuer.activate_spawn_channel(
        board_slug="default",
        task_id="t_spawn",
        run_id=19,
        profile="bookkeeper",
        profile_home=str(tmp_path / "profile"),
        workspace=str(tmp_path / "workspace"),
    )
    permit_id = channel.permit.permit_id
    assert set(channel.env_bridge) == {permits.PERMIT_FD_ENV}
    assert channel.child_fd >= 0
    assert channel.parent_endpoint.fileno() >= 0

    issuer.cancel_spawn_channel(channel)

    assert issuer.permit_status(permit_id) == "cancelled"
    assert channel.child_endpoint.fileno() == -1
    assert channel.parent_endpoint.fileno() == -1

    with pytest.raises(ScopedTerminalPermitError) as missing:
        issuer.activate_spawn_channel(
            board_slug="default",
            task_id="t_spawn",
            run_id=20,
            profile="bookkeeper",
            profile_home=str(tmp_path / "profile"),
            workspace=str(tmp_path / "workspace"),
        )
    assert missing.value.failure_class == "missing"

    issuer.arm_next_run(
        board_slug="default",
        task_id="t_spawn",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    fresh_channel = issuer.activate_spawn_channel(
        board_slug="default",
        task_id="t_spawn",
        run_id=20,
        profile="bookkeeper",
        profile_home=str(tmp_path / "profile"),
        workspace=str(tmp_path / "workspace"),
    )
    assert fresh_channel.permit.permit_id != permit_id
    issuer.cancel_spawn_channel(fresh_channel)


def test_worker_bootstrap_claims_bridge_once_and_hides_envelope(
    permit_factory, tmp_path, monkeypatch
):
    monkeypatch.setattr(permits, "_WORKER_CHANNEL_CLAIMED", False)
    monkeypatch.setattr(permits, "_WORKER_PERMIT_CLIENT", None)
    _, issuer, now, _, _ = permit_factory
    monkeypatch.setattr(permits.time, "time", lambda: now[0])
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_worker_bootstrap",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    channel = issuer.activate_spawn_channel(
        board_slug="default",
        task_id="t_worker_bootstrap",
        run_id=23,
        profile="bookkeeper",
        profile_home=str(tmp_path / "profile"),
        workspace=str(tmp_path / "workspace"),
    )
    channel.send_envelope()
    child_fd = channel.child_fd
    client_fd = os.dup(child_fd)
    monkeypatch.setenv(permits.PERMIT_FD_ENV, str(client_fd))

    client = claim_worker_permit_channel()

    assert client is not None
    assert permits.PERMIT_FD_ENV not in os.environ
    assert client.permit_id_digest == permits._digest(channel.permit.permit_id)
    with pytest.raises(ScopedTerminalPermitError) as exc:
        claim_worker_permit_channel()
    assert exc.value.failure_class == "missing"
    channel.close()


def test_phase_a_returns_opaque_ticket_only_after_exact_binding(
    permit_factory, tmp_path, monkeypatch
):
    monkeypatch.setattr(permits, "_WORKER_CHANNEL_CLAIMED", False)
    monkeypatch.setattr(permits, "_WORKER_PERMIT_CLIENT", None)
    _, issuer, now, _, _ = permit_factory
    monkeypatch.setattr(permits.time, "time", lambda: now[0])
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_phase_a",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    channel = issuer.activate_spawn_channel(
        board_slug="default",
        task_id="t_phase_a",
        run_id=24,
        profile="bookkeeper",
        profile_home=str(tmp_path / "profile"),
        workspace=str(tmp_path / "workspace"),
    )
    channel.send_envelope()
    client_fd = os.dup(channel.child_fd)
    monkeypatch.setenv(permits.PERMIT_FD_ENV, str(client_fd))
    client = claim_worker_permit_channel()
    payload = json.loads(channel.permit.payload)
    context = {key: copy.deepcopy(payload[key]) for key in issuer.CONTEXT_FIELDS}
    command = " ".join(payload["operation_sequence"][0]["argv"])

    ticket = prepare_scoped_terminal_permit(
        command, "local", context, client=client
    )

    assert isinstance(ticket, PreparedPermitTicket)
    assert ticket.permit_id_digest == permits._digest(channel.permit.permit_id)
    assert "payload" not in repr(ticket)
    assert "signature" not in repr(ticket)
    with pytest.raises(ScopedTerminalPermitError) as exc:
        prepare_scoped_terminal_permit(
            "sh -c 'rclone copyto source destination'",
            "local",
            context,
            client=client,
        )
    assert exc.value.failure_class == "operation_forbidden"
    channel.close()
