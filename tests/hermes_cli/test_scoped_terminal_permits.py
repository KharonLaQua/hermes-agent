from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import threading
from dataclasses import replace

import pytest

import hermes_cli.scoped_terminal_permits as permits
from hermes_cli.scoped_terminal_permits import (
    PreparedPermitTicket,
    ScopedTerminalPermitError,
    ScopedTerminalPermitIssuer,
    claim_worker_permit_channel,
    consume_scoped_terminal_permit,
    prepare_scoped_terminal_contract,
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
            "manifest_sha256": hashlib.sha256(b"[]").hexdigest(),
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


def _directory_content_digest(root):
    """Canonical content identity expected for a reviewed directory tree."""
    entries = []

    def visit(directory):
        for child in sorted(directory.iterdir(), key=lambda item: item.name):
            relative_path = child.relative_to(root).as_posix()
            if child.is_dir():
                entries.append({"kind": "directory", "path": relative_path})
                visit(child)
            else:
                contents = child.read_bytes()
                entries.append(
                    {
                        "kind": "file",
                        "path": relative_path,
                        "size": len(contents),
                        "sha256": hashlib.sha256(contents).hexdigest(),
                    }
                )

    visit(root)
    return hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _directory_contract(tmp_path, *, with_content_identity=True):
    root = tmp_path / "reviewed-directory"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (root / "root.bin").write_bytes(b"root-data")
    (nested / "child.bin").write_bytes(b"child-data")

    contract = _contract(tmp_path)
    manifest = tmp_path / "directory-manifest.json"
    manifest.write_text("[]", encoding="utf-8")
    contract["source"] = {
        "kind": "directory",
        "canonical_path": str(root),
        "expected_size_bytes": sum(
            path.stat().st_size for path in root.rglob("*") if path.is_file()
        ),
        "content_sha256": _directory_content_digest(root)
        if with_content_identity
        else None,
        "manifest_path": str(manifest),
        "manifest_sha256": hashlib.sha256(b"[]").hexdigest(),
    }
    contract["operation_sequence"][0]["argv"] = [
        "rclone",
        "copyto",
        str(root),
        "vault:reviewed/source.bin",
    ]
    return contract, root


def test_prepare_scoped_terminal_contract_returns_canonical_digest_only_artifact(
    tmp_path,
):
    contract = _contract(tmp_path)
    prepared = prepare_scoped_terminal_contract(contract)

    assert prepared.contract_digest == hashlib.sha256(prepared.canonical_bytes).hexdigest()
    assert json.loads(prepared.canonical_bytes) == prepared.contract
    assert prepared.operation_sequence_digest == hashlib.sha256(
        json.dumps(
            contract["operation_sequence"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    assert prepared.source_size_bytes == len(b"reviewed")
    assert prepared.source_content_sha256 == hashlib.sha256(b"reviewed").hexdigest()
    assert "reviewed" not in prepared.readback_json


def test_prepare_directory_contract_returns_canonical_content_identity(tmp_path):
    contract, root = _directory_contract(tmp_path)

    prepared = prepare_scoped_terminal_contract(contract)

    assert prepared.source_size_bytes == sum(
        path.stat().st_size for path in root.rglob("*") if path.is_file()
    )
    assert prepared.source_content_sha256 == contract["source"]["content_sha256"]


def test_directory_preparation_rejects_same_content_root_swap_before_open(
    monkeypatch, tmp_path
):
    contract, root = _directory_contract(tmp_path)
    replacement = tmp_path / "same-content-replacement"
    displaced = tmp_path / "displaced-reviewed-directory"
    shutil.copytree(root, replacement)
    original_open = permits._open_preparation_directory
    swapped = False

    def swap_before_root_open(path, *, dir_fd=None, **kwargs):
        nonlocal swapped
        if path == str(root) and dir_fd is None and not swapped:
            root.rename(displaced)
            replacement.rename(root)
            swapped = True
        return original_open(path, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(permits, "_open_preparation_directory", swap_before_root_open)
    with pytest.raises(ScopedTerminalPermitError) as exc:
        prepare_scoped_terminal_contract(contract)

    assert swapped is True
    assert exc.value.failure_class == "preparation_source_changed"


def test_directory_preparation_rejects_same_content_root_swap_after_traversal(
    monkeypatch, tmp_path
):
    contract, root = _directory_contract(tmp_path)
    replacement = tmp_path / "same-content-replacement"
    displaced = tmp_path / "displaced-reviewed-directory"
    shutil.copytree(root, replacement)
    original_lstat = permits._preparation_lstat
    root_observations = 0
    swapped = False

    def swap_before_final_root_lstat(path, *, dir_fd=None):
        nonlocal root_observations, swapped
        if path == str(root) and dir_fd is None:
            root_observations += 1
            if root_observations == 2:
                root.rename(displaced)
                replacement.rename(root)
                swapped = True
        return original_lstat(path, dir_fd=dir_fd)

    monkeypatch.setattr(permits, "_preparation_lstat", swap_before_final_root_lstat)
    with pytest.raises(ScopedTerminalPermitError) as exc:
        prepare_scoped_terminal_contract(contract)

    assert root_observations == 2
    assert swapped is True
    assert exc.value.failure_class == "preparation_source_changed"


def test_directory_preparation_rejects_manifest_only_identity_after_same_size_mutation(
    tmp_path,
):
    contract, root = _directory_contract(tmp_path, with_content_identity=False)
    child = root / "nested" / "child.bin"
    child.write_bytes(b"other-data")

    with pytest.raises(ScopedTerminalPermitError):
        prepare_scoped_terminal_contract(contract)


def test_directory_preparation_rejects_same_size_child_content_hash_mismatch(tmp_path):
    contract, root = _directory_contract(tmp_path)
    child = root / "nested" / "child.bin"
    child.write_bytes(b"other-data")

    with pytest.raises(ScopedTerminalPermitError) as exc:
        prepare_scoped_terminal_contract(contract)

    assert exc.value.failure_class == "preparation_hash_mismatch"


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_directory_preparation_rejects_missing_or_extra_child(tmp_path, mutation):
    contract, root = _directory_contract(tmp_path)
    if mutation == "missing":
        (root / "nested" / "child.bin").unlink()
    else:
        (root / "extra.bin").write_bytes(b"extra-data")

    with pytest.raises(ScopedTerminalPermitError):
        prepare_scoped_terminal_contract(contract)


@pytest.mark.parametrize("mutation", ["symlink", "non_regular"])
def test_directory_preparation_rejects_symlink_or_non_regular_child(tmp_path, mutation):
    contract, root = _directory_contract(tmp_path)
    child = root / "nested" / "child.bin"
    child.unlink()
    if mutation == "symlink":
        child.symlink_to(root / "root.bin")
    else:
        os.mkfifo(child)

    with pytest.raises(ScopedTerminalPermitError) as exc:
        prepare_scoped_terminal_contract(contract)

    assert exc.value.failure_class == "preparation_source_unreadable"


def test_directory_preparation_rejects_child_mutated_during_read(monkeypatch, tmp_path):
    contract, root = _directory_contract(tmp_path)
    child = root / "nested" / "child.bin"
    initial = b"a" * (2 * 1024 * 1024)
    replacement = b"b" * len(initial)
    child.write_bytes(initial)
    contract["source"]["expected_size_bytes"] += len(initial) - len(b"child-data")
    contract["source"]["content_sha256"] = _directory_content_digest(root)
    original_read = permits.os.read
    mutated = False

    def mutate_after_first_chunk(fd, size):
        nonlocal mutated
        chunk = original_read(fd, size)
        if chunk and not mutated:
            mutated = True
            child.write_bytes(replacement)
        return chunk

    monkeypatch.setattr(permits.os, "read", mutate_after_first_chunk)
    with pytest.raises(ScopedTerminalPermitError) as exc:
        prepare_scoped_terminal_contract(contract)

    assert mutated is True
    assert exc.value.failure_class == "preparation_source_changed"


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


def test_arm_and_resume_cancels_pending_arm_when_resume_fails(permit_factory, tmp_path):
    _, issuer, _, events, _ = permit_factory

    with pytest.raises(ScopedTerminalPermitError) as exc:
        issuer.arm_and_resume(
            board_slug="default",
            task_id="t_resume_failed",
            contract=_contract(tmp_path),
            ttl_seconds=60,
            evidence_task_id="t_evidence",
            evidence_artifact_digest=_HEX_A,
            resume=lambda: False,
        )

    assert exc.value.failure_class == "resume_failed"
    assert issuer._pending == {}
    assert events[-1][0] == "terminal_permit_cancelled"
    assert events[-1][1]["failure_class"] == "resume_failed"


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


def test_phase_a_rechecks_expiry_after_worker_claim(
    permit_factory, tmp_path, monkeypatch
):
    monkeypatch.setattr(permits, "_WORKER_CHANNEL_CLAIMED", False)
    monkeypatch.setattr(permits, "_WORKER_PERMIT_CLIENT", None)
    _, issuer, now, _, _ = permit_factory
    monkeypatch.setattr(permits.time, "time", lambda: now[0])
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_phase_a_expired",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    channel = issuer.activate_spawn_channel(
        board_slug="default",
        task_id="t_phase_a_expired",
        run_id=25,
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
    now[0] = payload["expires_at"] + 1

    with pytest.raises(ScopedTerminalPermitError) as exc:
        prepare_scoped_terminal_permit(command, "local", context, client=client)

    assert exc.value.failure_class == "expired"
    assert issuer.permit_status(payload["permit_id"]) == "issued"
    channel.close()


def test_phase_a_rechecks_not_yet_valid_after_worker_claim(
    permit_factory, tmp_path, monkeypatch
):
    monkeypatch.setattr(permits, "_WORKER_CHANNEL_CLAIMED", False)
    monkeypatch.setattr(permits, "_WORKER_PERMIT_CLIENT", None)
    _, issuer, now, _, _ = permit_factory
    monkeypatch.setattr(permits.time, "time", lambda: now[0])
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_phase_a_not_yet_valid",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    channel = issuer.activate_spawn_channel(
        board_slug="default",
        task_id="t_phase_a_not_yet_valid",
        run_id=26,
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
    now[0] = payload["not_before"] - 1

    with pytest.raises(ScopedTerminalPermitError) as exc:
        prepare_scoped_terminal_permit(command, "local", context, client=client)

    assert exc.value.failure_class == "not_yet_valid"
    assert issuer.permit_status(payload["permit_id"]) == "issued"
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
    assert issuer.permit_status(payload["permit_id"]) == "issued"
    with pytest.raises(ScopedTerminalPermitError) as exc:
        prepare_scoped_terminal_permit(
            "sh -c 'rclone copyto source destination'",
            "local",
            context,
            client=client,
        )
    assert exc.value.failure_class == "operation_forbidden"
    channel.close()


def test_worker_execution_context_combines_live_identity_with_signed_scope(
    permit_factory, tmp_path, monkeypatch
):
    monkeypatch.setattr(permits, "_WORKER_CHANNEL_CLAIMED", False)
    monkeypatch.setattr(permits, "_WORKER_PERMIT_CLIENT", None)
    _, issuer, now, _, _ = permit_factory
    monkeypatch.setattr(permits.time, "time", lambda: now[0])
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_context_builder",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    channel = issuer.activate_spawn_channel(
        board_slug="default",
        task_id="t_context_builder",
        run_id=35,
        profile="bookkeeper",
        profile_home=str(tmp_path / "profile"),
        workspace=str(tmp_path / "workspace"),
    )
    channel.send_envelope()
    client_fd = os.dup(channel.child_fd)
    monkeypatch.setenv(permits.PERMIT_FD_ENV, str(client_fd))
    client = claim_worker_permit_channel()
    issuer.release_spawn_child(channel)
    payload = json.loads(channel.permit.payload)
    monkeypatch.setenv("HERMES_KANBAN_BOARD", "default")
    monkeypatch.setenv("HERMES_KANBAN_TASK", "t_context_builder")
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", "35")
    monkeypatch.setenv("HERMES_PROFILE", "bookkeeper")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile"))
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", str(tmp_path / "workspace"))

    context = permits.build_worker_permit_execution_context(
        cwd=str(tmp_path / "workspace"),
        background=False,
        pty=False,
        stdin=False,
        force=False,
        notify_on_complete=False,
        watch_patterns=None,
        client=client,
    )

    assert {key: context[key] for key in issuer.CONTEXT_FIELDS} == {
        key: copy.deepcopy(payload[key]) for key in issuer.CONTEXT_FIELDS
    }
    assert context["source"] is not client._payload["source"]
    assert context["operation_sequence"] is not client._payload["operation_sequence"]
    assert context["cwd"] == str(tmp_path / "workspace")
    assert context["background"] is False
    assert context["pty"] is False
    assert context["stdin"] is False
    assert context["force"] is False
    assert context["notify_on_complete"] is False
    assert context["watch_patterns"] is None
    assert isinstance(
        prepare_scoped_terminal_permit(
            " ".join(payload["operation_sequence"][0]["argv"]),
            "local",
            context,
            client=client,
        ),
        PreparedPermitTicket,
    )
    client.close()
    channel.close()


@pytest.mark.parametrize(
    "ticket_kind",
    ("forged", "substituted", "metadata_mutated", "cross_client"),
)
def test_authenticated_consume_rejects_unprepared_ticket_forms_and_spends_channel(
    permit_factory, tmp_path, monkeypatch, ticket_kind
):
    """Only the exact ticket retained by ``prepare`` may consume the channel."""
    monkeypatch.setattr(permits, "_WORKER_CHANNEL_CLAIMED", False)
    monkeypatch.setattr(permits, "_WORKER_PERMIT_CLIENT", None)
    _, issuer, now, _, _ = permit_factory
    monkeypatch.setattr(permits.time, "time", lambda: now[0])
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_ticket_identity",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    channel = issuer.activate_spawn_channel(
        board_slug="default",
        task_id="t_ticket_identity",
        run_id=33,
        profile="bookkeeper",
        profile_home=str(tmp_path / "profile"),
        workspace=str(tmp_path / "workspace"),
    )
    channel.send_envelope()
    client_fd = os.dup(channel.child_fd)
    monkeypatch.setenv(permits.PERMIT_FD_ENV, str(client_fd))
    client = claim_worker_permit_channel()
    issuer.release_spawn_child(channel)
    payload = json.loads(channel.permit.payload)
    context = {key: copy.deepcopy(payload[key]) for key in issuer.CONTEXT_FIELDS}
    command = " ".join(payload["operation_sequence"][0]["argv"])
    prepared = prepare_scoped_terminal_permit(command, "local", context, client=client)

    if ticket_kind == "forged":
        ticket = PreparedPermitTicket(client, _HEX_A, 99, _HEX_C)
    elif ticket_kind == "substituted":
        ticket = replace(prepared)
    elif ticket_kind == "metadata_mutated":
        object.__setattr__(prepared, "_command_digest", _HEX_C)
        ticket = prepared
    else:
        assert client._endpoint is not None
        foreign_client = permits._WorkerPermitClient(
            client._envelope,
            client._public_key,
            client._payload,
            client._endpoint,
        )
        ticket = PreparedPermitTicket(
            foreign_client,
            prepared.permit_id_digest,
            prepared.operation_index,
            prepared.command_digest,
        )

    consume_observed = threading.Event()
    original_consume = issuer.consume

    def record_consume(*args, **kwargs):
        try:
            return original_consume(*args, **kwargs)
        finally:
            consume_observed.set()

    monkeypatch.setattr(issuer, "consume", record_consume)
    with pytest.raises(ScopedTerminalPermitError) as exc:
        consume_scoped_terminal_permit(ticket, context)

    assert exc.value.failure_class == "malformed"
    assert client._closed is True
    assert consume_observed.wait(timeout=1)
    assert issuer.permit_status(payload["permit_id"]) == "rejected"


def test_public_consume_client_mutation_terminalizes_prepared_origin(
    permit_factory, tmp_path, monkeypatch
):
    """Public dispatch resolves the private Phase-A origin, not ticket metadata."""
    monkeypatch.setattr(permits, "_WORKER_CHANNEL_CLAIMED", False)
    monkeypatch.setattr(permits, "_WORKER_PERMIT_CLIENT", None)
    _, issuer, now, _, _ = permit_factory
    monkeypatch.setattr(permits.time, "time", lambda: now[0])
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_ticket_client_mutation",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    channel = issuer.activate_spawn_channel(
        board_slug="default",
        task_id="t_ticket_client_mutation",
        run_id=34,
        profile="bookkeeper",
        profile_home=str(tmp_path / "profile"),
        workspace=str(tmp_path / "workspace"),
    )
    channel.send_envelope()
    client_fd = os.dup(channel.child_fd)
    monkeypatch.setenv(permits.PERMIT_FD_ENV, str(client_fd))
    origin = claim_worker_permit_channel()
    issuer.release_spawn_child(channel)
    payload = json.loads(channel.permit.payload)
    context = {key: copy.deepcopy(payload[key]) for key in issuer.CONTEXT_FIELDS}
    command = " ".join(payload["operation_sequence"][0]["argv"])
    prepared = prepare_scoped_terminal_permit(command, "local", context, client=origin)

    foreign_endpoint, foreign_peer = permits.socket.socketpair()
    foreign = permits._WorkerPermitClient(
        origin._envelope,
        origin._public_key,
        origin._payload,
        foreign_endpoint,
    )
    consume_observed = threading.Event()
    original_consume = issuer.consume

    def record_consume(*args, **kwargs):
        try:
            return original_consume(*args, **kwargs)
        finally:
            consume_observed.set()

    monkeypatch.setattr(issuer, "consume", record_consume)
    try:
        object.__setattr__(prepared, "_client", foreign)
        with pytest.raises(ScopedTerminalPermitError) as first:
            consume_scoped_terminal_permit(prepared, context)
        assert first.value.failure_class == "malformed"

        object.__setattr__(prepared, "_client", origin)
        with pytest.raises(ScopedTerminalPermitError) as replay:
            consume_scoped_terminal_permit(prepared, context)
        assert replay.value.failure_class == "missing"

        assert origin._closed is True
        assert foreign._closed is False
        assert consume_observed.wait(timeout=1)
        assert issuer.permit_status(payload["permit_id"]) == "rejected"
    finally:
        foreign.close()
        foreign_peer.close()
        channel.close()


def test_public_consume_wrong_type_terminalizes_prepared_authority(
    permit_factory, tmp_path, monkeypatch
):
    monkeypatch.setattr(permits, "_WORKER_CHANNEL_CLAIMED", False)
    monkeypatch.setattr(permits, "_WORKER_PERMIT_CLIENT", None)
    monkeypatch.setattr(permits, "_PREPARED_TICKET_ORIGINS", {})
    _, issuer, now, _, _ = permit_factory
    monkeypatch.setattr(permits.time, "time", lambda: now[0])
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_wrong_type_consume",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    channel = issuer.activate_spawn_channel(
        board_slug="default",
        task_id="t_wrong_type_consume",
        run_id=36,
        profile="bookkeeper",
        profile_home=str(tmp_path / "profile"),
        workspace=str(tmp_path / "workspace"),
    )
    channel.send_envelope()
    client_fd = os.dup(channel.child_fd)
    monkeypatch.setenv(permits.PERMIT_FD_ENV, str(client_fd))
    client = claim_worker_permit_channel()
    issuer.release_spawn_child(channel)
    payload = json.loads(channel.permit.payload)
    context = {key: copy.deepcopy(payload[key]) for key in issuer.CONTEXT_FIELDS}
    command = " ".join(payload["operation_sequence"][0]["argv"])
    prepared = prepare_scoped_terminal_permit(command, "local", context, client=client)
    consume_observed = threading.Event()
    original_consume = issuer.consume

    def record_consume(*args, **kwargs):
        try:
            return original_consume(*args, **kwargs)
        finally:
            consume_observed.set()

    monkeypatch.setattr(issuer, "consume", record_consume)
    try:
        with pytest.raises(ScopedTerminalPermitError) as wrong_type:
            consume_scoped_terminal_permit(object(), context)
        assert wrong_type.value.failure_class == "malformed"
        assert client._closed is True
        assert consume_observed.wait(timeout=1)
        assert issuer.permit_status(payload["permit_id"]) == "rejected"
        assert permits._PREPARED_TICKET_ORIGINS == {}

        with pytest.raises(ScopedTerminalPermitError) as restored:
            consume_scoped_terminal_permit(prepared, context)
        assert restored.value.failure_class == "missing"
        with pytest.raises(ScopedTerminalPermitError) as later_prepare:
            prepare_scoped_terminal_permit(command, "local", context, client=client)
        assert later_prepare.value.failure_class == "missing"
    finally:
        channel.close()


def test_public_consume_without_prepare_terminalizes_claimed_authority(
    permit_factory, tmp_path, monkeypatch
):
    monkeypatch.setattr(permits, "_WORKER_CHANNEL_CLAIMED", False)
    monkeypatch.setattr(permits, "_WORKER_PERMIT_CLIENT", None)
    monkeypatch.setattr(permits, "_PREPARED_TICKET_ORIGINS", {})
    _, issuer, now, _, _ = permit_factory
    monkeypatch.setattr(permits.time, "time", lambda: now[0])
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_no_prepare_consume",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    channel = issuer.activate_spawn_channel(
        board_slug="default",
        task_id="t_no_prepare_consume",
        run_id=37,
        profile="bookkeeper",
        profile_home=str(tmp_path / "profile"),
        workspace=str(tmp_path / "workspace"),
    )
    channel.send_envelope()
    client_fd = os.dup(channel.child_fd)
    monkeypatch.setenv(permits.PERMIT_FD_ENV, str(client_fd))
    client = claim_worker_permit_channel()
    issuer.release_spawn_child(channel)
    payload = json.loads(channel.permit.payload)
    context = {key: copy.deepcopy(payload[key]) for key in issuer.CONTEXT_FIELDS}
    command = " ".join(payload["operation_sequence"][0]["argv"])
    unprepared = PreparedPermitTicket(
        client,
        permits._digest(channel.permit.permit_id),
        payload["authorized_operation_index"],
        payload["command_digest"],
    )
    consume_observed = threading.Event()
    original_consume = issuer.consume

    def record_consume(*args, **kwargs):
        try:
            return original_consume(*args, **kwargs)
        finally:
            consume_observed.set()

    monkeypatch.setattr(issuer, "consume", record_consume)
    try:
        with pytest.raises(ScopedTerminalPermitError) as missing:
            consume_scoped_terminal_permit(unprepared, context)
        assert missing.value.failure_class == "missing"
        assert client._closed is True
        assert consume_observed.wait(timeout=1)
        assert issuer.permit_status(payload["permit_id"]) == "rejected"
        assert permits._PREPARED_TICKET_ORIGINS == {}

        with pytest.raises(ScopedTerminalPermitError) as later_prepare:
            prepare_scoped_terminal_permit(command, "local", context, client=client)
        assert later_prepare.value.failure_class == "missing"
    finally:
        channel.close()


def test_authenticated_consume_uses_inherited_channel_once_and_closes_endpoints(
    permit_factory, tmp_path, monkeypatch
):
    monkeypatch.setattr(permits, "_WORKER_CHANNEL_CLAIMED", False)
    monkeypatch.setattr(permits, "_WORKER_PERMIT_CLIENT", None)
    issue, issuer, now, _, _ = permit_factory
    monkeypatch.setattr(permits.time, "time", lambda: now[0])
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_channel_consume",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    channel = issuer.activate_spawn_channel(
        board_slug="default",
        task_id="t_channel_consume",
        run_id=31,
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
    ticket = prepare_scoped_terminal_permit(command, "local", context, client=client)

    decision = consume_scoped_terminal_permit(ticket, context)

    assert decision.allowed is True
    assert issuer.permit_status(payload["permit_id"]) == "consumed"
    assert channel.parent_endpoint.fileno() == -1
    assert channel.child_endpoint.fileno() == -1
    with pytest.raises(ScopedTerminalPermitError) as replay:
        consume_scoped_terminal_permit(ticket, context)
    assert replay.value.failure_class == "missing"


def test_authenticated_consume_rejects_tampered_context_and_spends_channel(
    permit_factory, tmp_path, monkeypatch
):
    monkeypatch.setattr(permits, "_WORKER_CHANNEL_CLAIMED", False)
    monkeypatch.setattr(permits, "_WORKER_PERMIT_CLIENT", None)
    issue, issuer, now, _, _ = permit_factory
    monkeypatch.setattr(permits.time, "time", lambda: now[0])
    issuer.arm_next_run(
        board_slug="default",
        task_id="t_channel_tamper",
        contract=_contract(tmp_path),
        ttl_seconds=60,
        evidence_task_id="t_evidence",
        evidence_artifact_digest=_HEX_A,
    )
    channel = issuer.activate_spawn_channel(
        board_slug="default",
        task_id="t_channel_tamper",
        run_id=32,
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
    ticket = prepare_scoped_terminal_permit(command, "local", context, client=client)
    context["task_id"] = "t_other"

    decision = consume_scoped_terminal_permit(ticket, context)

    assert decision.allowed is False
    assert decision.failure_class == "task_mismatch"
    assert issuer.permit_status(payload["permit_id"]) == "rejected"
    assert channel.parent_endpoint.fileno() == -1
    assert channel.child_endpoint.fileno() == -1
