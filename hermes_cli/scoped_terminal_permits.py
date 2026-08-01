"""Process-local authenticated permits for one exact Kanban terminal operation.

This module deliberately contains no file, environment, database, CLI, or socket
issuance surface. The ephemeral Ed25519 key and all pending/terminal state stay
inside the dispatcher-lock-owning gateway process.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_DOMAIN = b"HERMES-KANBAN-TERMINAL-PERMIT\x00v1\x00"
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_BOARD = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")

_PAYLOAD_FIELDS = frozenset(
    {
        "version",
        "permit_id",
        "issuer_key_id",
        "board_slug",
        "task_id",
        "run_id",
        "profile",
        "profile_home",
        "workspace",
        "source",
        "destination",
        "operation_sequence",
        "operation_sequence_digest",
        "authorized_operation_index",
        "predecessor_receipt_digest",
        "command_digest",
        "issued_at",
        "not_before",
        "expires_at",
        "nonce",
    }
)
_CONTRACT_FIELDS = frozenset(
    {
        "profile",
        "profile_home",
        "workspace",
        "source",
        "destination",
        "operation_sequence",
        "authorized_operation_index",
        "predecessor_receipt_digest",
        "command_digest",
    }
)
_SOURCE_FIELDS = frozenset(
    {
        "kind",
        "canonical_path",
        "expected_size_bytes",
        "content_sha256",
        "manifest_path",
        "manifest_sha256",
    }
)
_DESTINATION_FIELDS = frozenset({"kind", "canonical_uri"})
_OPERATION_FIELDS = frozenset(
    {
        "index",
        "kind",
        "argv",
        "cwd",
        "background",
        "pty",
        "source_ref",
        "destination_ref",
        "manifest_ref",
        "execution_context_digest",
    }
)


class ScopedTerminalPermitError(RuntimeError):
    """Stable fail-closed permit error without secret-bearing detail."""

    def __init__(self, failure_class: str):
        super().__init__(failure_class)
        self.failure_class = failure_class


@dataclass(frozen=True)
class ArmReceipt:
    arm_id_digest: str
    task_id: str
    contract_digest: str
    issuer_profile: str
    expires_at: int


@dataclass(frozen=True)
class SignedPermit:
    permit_id: str
    payload: bytes
    signature: bytes


@dataclass(frozen=True)
class PermitDecision:
    allowed: bool
    failure_class: str | None
    permit_id_digest: str | None


@dataclass(frozen=True)
class _PendingArm:
    arm_id: str
    board_slug: str
    task_id: str
    contract_bytes: bytes
    contract_digest: str
    ttl_seconds: int
    armed_at: int
    evidence_task_id: str
    evidence_artifact_digest: str


@dataclass
class _PermitRecord:
    envelope: SignedPermit
    status: str
    evidence_task_id: str
    evidence_artifact_digest: str
    arm_contract_digest: str


def _canonical_bytes(value: Any) -> bytes:
    _reject_non_json_types(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ScopedTerminalPermitError("malformed") from exc


def _reject_non_json_types(value: Any) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, list):
        for item in value:
            _reject_non_json_types(item)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for item in value.values():
            _reject_non_json_types(item)
        return
    raise ScopedTerminalPermitError("malformed")


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ScopedTerminalPermitError("malformed")
        result[key] = value
    return result


def _parse_canonical(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_no_duplicate_object,
            parse_float=lambda _: (_ for _ in ()).throw(ScopedTerminalPermitError("malformed")),
            parse_constant=lambda _: (_ for _ in ()).throw(ScopedTerminalPermitError("malformed")),
        )
    except ScopedTerminalPermitError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
        raise ScopedTerminalPermitError("malformed") from exc
    if not isinstance(value, dict) or _canonical_bytes(value) != data:
        raise ScopedTerminalPermitError("malformed")
    return value


def _digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _require_text(value: Any) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise ScopedTerminalPermitError("malformed")
    return value


def _require_int(value: Any, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ScopedTerminalPermitError("malformed")
    return value


def _require_digest(value: Any, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ScopedTerminalPermitError("malformed")
    return value


def _canonical_path(value: Any) -> str:
    path = _require_text(value)
    if not os.path.isabs(path):
        raise ScopedTerminalPermitError("malformed")
    return os.path.realpath(path)


def _validate_source(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _SOURCE_FIELDS:
        raise ScopedTerminalPermitError("malformed")
    normalized = dict(value)
    if normalized["kind"] not in {"file", "directory", "manifest"}:
        raise ScopedTerminalPermitError("malformed")
    normalized["canonical_path"] = _canonical_path(normalized["canonical_path"])
    normalized["expected_size_bytes"] = _require_int(normalized["expected_size_bytes"])
    normalized["content_sha256"] = _require_digest(normalized["content_sha256"], nullable=True)
    normalized["manifest_path"] = (
        None if normalized["manifest_path"] is None else _canonical_path(normalized["manifest_path"])
    )
    normalized["manifest_sha256"] = _require_digest(normalized["manifest_sha256"], nullable=True)
    if normalized["content_sha256"] is None and normalized["manifest_sha256"] is None:
        raise ScopedTerminalPermitError("malformed")
    if (normalized["manifest_path"] is None) != (normalized["manifest_sha256"] is None):
        raise ScopedTerminalPermitError("malformed")
    return normalized


def _validate_destination(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _DESTINATION_FIELDS:
        raise ScopedTerminalPermitError("malformed")
    kind = _require_text(value["kind"])
    uri = _require_text(value["canonical_uri"])
    if "?" in uri or "#" in uri or "://" in uri and "@" in uri.split("://", 1)[1].split("/", 1)[0]:
        raise ScopedTerminalPermitError("malformed")
    return {"kind": kind, "canonical_uri": uri}


def _validate_operations(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ScopedTerminalPermitError("malformed")
    normalized: list[dict[str, Any]] = []
    for expected_index, operation in enumerate(value):
        if not isinstance(operation, dict) or set(operation) != _OPERATION_FIELDS:
            raise ScopedTerminalPermitError("malformed")
        item = dict(operation)
        if _require_int(item["index"]) != expected_index:
            raise ScopedTerminalPermitError("malformed")
        item["kind"] = _require_text(item["kind"])
        if not isinstance(item["argv"], list) or not item["argv"]:
            raise ScopedTerminalPermitError("malformed")
        item["argv"] = [_require_text(arg) for arg in item["argv"]]
        item["cwd"] = _canonical_path(item["cwd"])
        if item["background"] is not False or item["pty"] is not False:
            raise ScopedTerminalPermitError("malformed")
        for field in ("source_ref", "destination_ref"):
            item[field] = _require_text(item[field])
        if item["manifest_ref"] is not None:
            item["manifest_ref"] = _require_text(item["manifest_ref"])
        item["execution_context_digest"] = _require_digest(item["execution_context_digest"])
        normalized.append(item)
    return normalized


def _normalize_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(contract, Mapping):
        raise ScopedTerminalPermitError("malformed")
    copied = _parse_canonical(_canonical_bytes(dict(contract)))
    if set(copied) != _CONTRACT_FIELDS:
        raise ScopedTerminalPermitError("malformed")
    copied["profile"] = _require_text(copied["profile"]).strip().lower()
    copied["profile_home"] = _canonical_path(copied["profile_home"])
    copied["workspace"] = _canonical_path(copied["workspace"])
    copied["source"] = _validate_source(copied["source"])
    copied["destination"] = _validate_destination(copied["destination"])
    copied["operation_sequence"] = _validate_operations(copied["operation_sequence"])
    index = _require_int(copied["authorized_operation_index"])
    if index >= len(copied["operation_sequence"]):
        raise ScopedTerminalPermitError("malformed")
    copied["authorized_operation_index"] = index
    copied["predecessor_receipt_digest"] = _require_digest(
        copied["predecessor_receipt_digest"], nullable=True
    )
    if index > 0 and copied["predecessor_receipt_digest"] is None:
        raise ScopedTerminalPermitError("malformed")
    copied["command_digest"] = _require_digest(copied["command_digest"])
    return copied


def _validate_payload(payload: dict[str, Any]) -> None:
    if set(payload) != _PAYLOAD_FIELDS or payload.get("version") != 1:
        raise ScopedTerminalPermitError("malformed")
    for field in ("permit_id", "board_slug", "task_id", "profile"):
        _require_text(payload[field])
    if not _BOARD.fullmatch(payload["board_slug"]):
        raise ScopedTerminalPermitError("malformed")
    _require_digest(payload["issuer_key_id"])
    _require_int(payload["run_id"], minimum=1)
    _canonical_path(payload["profile_home"])
    _canonical_path(payload["workspace"])
    _validate_source(payload["source"])
    _validate_destination(payload["destination"])
    operations = _validate_operations(payload["operation_sequence"])
    if _digest(_canonical_bytes(operations)) != payload["operation_sequence_digest"]:
        raise ScopedTerminalPermitError("malformed")
    index = _require_int(payload["authorized_operation_index"])
    if index >= len(operations):
        raise ScopedTerminalPermitError("malformed")
    _require_digest(payload["predecessor_receipt_digest"], nullable=True)
    if index > 0 and payload["predecessor_receipt_digest"] is None:
        raise ScopedTerminalPermitError("malformed")
    _require_digest(payload["command_digest"])
    issued = _require_int(payload["issued_at"])
    not_before = _require_int(payload["not_before"])
    expires = _require_int(payload["expires_at"])
    if not_before < issued or expires <= issued or expires - issued > 300:
        raise ScopedTerminalPermitError("malformed")
    _require_digest(payload["nonce"])


class ScopedTerminalPermitIssuer:
    """Ephemeral issuer owned by the embedded gateway dispatcher."""

    CONTEXT_FIELDS = frozenset(
        {
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
        }
    )
    AUDIT_FIELDS = frozenset(
        {
            "permit_id_digest",
            "nonce_digest",
            "issuer_key_id",
            "arm_contract_digest",
            "evidence_task_id",
            "evidence_artifact_digest",
            "task_id",
            "run_id",
            "profile",
            "profile_home_digest",
            "workspace_digest",
            "source_digest",
            "destination_digest",
            "operation_sequence_digest",
            "operation_index",
            "command_digest",
            "decision",
            "failure_class",
            "issued_at",
            "expires_at",
            "decided_at",
        }
    )

    def __init__(
        self,
        *,
        issuer_profile: str,
        max_ttl_seconds: int = 300,
        lock_owner_check: Callable[[], bool],
        clock: Callable[[], float] | None = None,
        audit_writer: Callable[[str, Mapping[str, Any]], None] | None = None,
    ) -> None:
        if os.environ.get("HERMES_KANBAN_TASK"):
            raise PermissionError("Kanban worker processes cannot create a terminal permit issuer")
        try:
            from agent.delegation_context import is_delegated_child_process_context

            if is_delegated_child_process_context():
                raise PermissionError("delegated worker processes cannot create a terminal permit issuer")
        except ImportError:
            pass
        if not isinstance(issuer_profile, str) or not issuer_profile.strip():
            raise PermissionError("terminal permit issuer requires an issuer profile")
        if not callable(lock_owner_check):
            raise PermissionError("terminal permit issuer requires the active dispatcher lock owner")
        try:
            owns_lock = lock_owner_check()
        except Exception:
            owns_lock = False
        if not owns_lock:
            raise PermissionError("terminal permit issuer requires the active dispatcher lock owner")
        if (
            isinstance(max_ttl_seconds, bool)
            or not isinstance(max_ttl_seconds, int)
            or not 1 <= max_ttl_seconds <= 300
        ):
            raise ValueError("max ttl must be an integer from 1 to 300 seconds")
        self.issuer_profile = issuer_profile.strip().lower()
        self.max_ttl_seconds = max_ttl_seconds
        self._lock_owner_check = lock_owner_check
        self._clock = clock or time.time
        self._audit_writer = audit_writer or (lambda _kind, _payload: None)
        self._lock = threading.RLock()
        self._closed = False
        self._signing_key: Ed25519PrivateKey | None = Ed25519PrivateKey.generate()
        public = self._signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._public_key: Ed25519PublicKey | None = self._signing_key.public_key()
        self._public_key_bytes: bytes | None = public
        self._issuer_key_id = _digest(public)
        self._pending: dict[tuple[str, str], _PendingArm] = {}
        self._permits: dict[str, _PermitRecord] = {}
        self._nonces: set[str] = set()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def public_key_bytes(self) -> bytes | None:
        return self._public_key_bytes

    def _assert_available(self) -> None:
        try:
            owns_lock = self._lock_owner_check()
        except Exception:
            owns_lock = False
        if self._closed or not owns_lock or self._signing_key is None:
            raise ScopedTerminalPermitError("issuer_unavailable")

    def arm_next_run(
        self,
        *,
        board_slug: str,
        task_id: str,
        contract: Mapping[str, Any],
        ttl_seconds: int,
        evidence_task_id: str,
        evidence_artifact_digest: str,
    ) -> ArmReceipt:
        with self._lock:
            self._assert_available()
            board = _require_text(board_slug).strip().lower()
            if not _BOARD.fullmatch(board):
                raise ScopedTerminalPermitError("malformed")
            task = _require_text(task_id)
            evidence_task = _require_text(evidence_task_id)
            evidence_digest = _require_digest(evidence_artifact_digest)
            if (
                isinstance(ttl_seconds, bool)
                or not isinstance(ttl_seconds, int)
                or not 1 <= ttl_seconds <= self.max_ttl_seconds
            ):
                raise ScopedTerminalPermitError("malformed")
            key = (board, task)
            if key in self._pending:
                raise ScopedTerminalPermitError("already_armed")
            normalized = _normalize_contract(contract)
            contract_bytes = _canonical_bytes(normalized)
            now = int(self._clock())
            arm = _PendingArm(
                arm_id=secrets.token_hex(16),
                board_slug=board,
                task_id=task,
                contract_bytes=contract_bytes,
                contract_digest=_digest(contract_bytes),
                ttl_seconds=ttl_seconds,
                armed_at=now,
                evidence_task_id=evidence_task,
                evidence_artifact_digest=evidence_digest or "",
            )
            self._pending[key] = arm
            try:
                self._write_audit("terminal_permit_armed", self._audit_for_arm(arm, now))
            except Exception:
                self._pending.pop(key, None)
                raise ScopedTerminalPermitError("audit_failed") from None
            return ArmReceipt(
                arm_id_digest=_digest(arm.arm_id),
                task_id=task,
                contract_digest=arm.contract_digest,
                issuer_profile=self.issuer_profile,
                expires_at=now + ttl_seconds,
            )

    def activate_for_spawn(
        self,
        *,
        board_slug: str,
        task_id: str,
        run_id: int,
        profile: str,
        profile_home: str,
        workspace: str,
    ) -> SignedPermit:
        with self._lock:
            self._assert_available()
            board = _require_text(board_slug).strip().lower()
            task = _require_text(task_id)
            key = (board, task)
            arm = self._pending.pop(key, None)
            if arm is None:
                raise ScopedTerminalPermitError("missing")
            contract = _parse_canonical(arm.contract_bytes)
            now = int(self._clock())
            failure: str | None = None
            if now > arm.armed_at + arm.ttl_seconds:
                failure = "expired"
            elif _require_text(profile).strip().lower() != contract["profile"]:
                failure = "profile_mismatch"
            elif _canonical_path(profile_home) != contract["profile_home"]:
                failure = "profile_home_mismatch"
            elif _canonical_path(workspace) != contract["workspace"]:
                failure = "workspace_mismatch"
            if failure:
                try:
                    self._write_audit(
                        "terminal_permit_cancelled",
                        self._audit_for_arm(arm, now, failure),
                    )
                except Exception:
                    raise ScopedTerminalPermitError("audit_failed") from None
                raise ScopedTerminalPermitError(failure)
            run = _require_int(run_id, minimum=1)
            nonce = secrets.token_hex(32)
            while nonce in self._nonces:
                nonce = secrets.token_hex(32)
            self._nonces.add(nonce)
            operations = contract["operation_sequence"]
            payload = {
                "version": 1,
                "permit_id": secrets.token_hex(16),
                "issuer_key_id": self._issuer_key_id,
                "board_slug": board,
                "task_id": task,
                "run_id": run,
                "profile": contract["profile"],
                "profile_home": contract["profile_home"],
                "workspace": contract["workspace"],
                "source": contract["source"],
                "destination": contract["destination"],
                "operation_sequence": operations,
                "operation_sequence_digest": _digest(_canonical_bytes(operations)),
                "authorized_operation_index": contract["authorized_operation_index"],
                "predecessor_receipt_digest": contract["predecessor_receipt_digest"],
                "command_digest": contract["command_digest"],
                "issued_at": now,
                "not_before": now,
                "expires_at": now + arm.ttl_seconds,
                "nonce": nonce,
            }
            payload_bytes = _canonical_bytes(payload)
            signing_key = self._signing_key
            if signing_key is None:
                raise ScopedTerminalPermitError("issuer_unavailable")
            envelope = SignedPermit(
                permit_id=payload["permit_id"],
                payload=payload_bytes,
                signature=signing_key.sign(_DOMAIN + payload_bytes),
            )
            record = _PermitRecord(
                envelope=envelope,
                status="issued",
                evidence_task_id=arm.evidence_task_id,
                evidence_artifact_digest=arm.evidence_artifact_digest,
                arm_contract_digest=arm.contract_digest,
            )
            self._permits[envelope.permit_id] = record
            try:
                self._write_audit(
                    "terminal_permit_activated",
                    self._audit_for_record(record, payload, "issued", None, now),
                )
            except Exception:
                record.status = "rejected"
                raise ScopedTerminalPermitError("audit_failed") from None
            return envelope

    def consume(
        self,
        envelope: SignedPermit,
        *,
        context: Mapping[str, Any],
        challenge: str,
    ) -> PermitDecision:
        with self._lock:
            try:
                self._assert_available()
            except ScopedTerminalPermitError as exc:
                return PermitDecision(False, exc.failure_class, None)
            if not isinstance(envelope, SignedPermit):
                return PermitDecision(False, "malformed", None)
            record = self._permits.get(envelope.permit_id)
            if record is None:
                return PermitDecision(False, "malformed", _digest(envelope.permit_id))
            if record.status != "issued":
                return self._finish_replay(record)
            failure: str | None = None
            payload: dict[str, Any]
            try:
                payload = _parse_canonical(envelope.payload)
                _validate_payload(payload)
                if payload["permit_id"] != envelope.permit_id:
                    raise ScopedTerminalPermitError("malformed")
                if payload["issuer_key_id"] != self._issuer_key_id or self._public_key is None:
                    raise ScopedTerminalPermitError("unknown_key_generation")
                try:
                    self._public_key.verify(envelope.signature, _DOMAIN + envelope.payload)
                except (InvalidSignature, TypeError):
                    raise ScopedTerminalPermitError("signature_invalid") from None
                if not isinstance(challenge, str) or not challenge:
                    raise ScopedTerminalPermitError("malformed")
                now = int(self._clock())
                if now < payload["not_before"]:
                    raise ScopedTerminalPermitError("not_yet_valid")
                if now > payload["expires_at"]:
                    raise ScopedTerminalPermitError("expired")
                failure = self._binding_failure(payload, context)
            except ScopedTerminalPermitError as exc:
                payload = _parse_canonical(record.envelope.payload)
                failure = exc.failure_class
            except Exception:
                payload = _parse_canonical(record.envelope.payload)
                failure = "malformed"
            now = int(self._clock())
            if failure:
                record.status = "rejected"
                return self._audit_decision(record, payload, False, failure, now)
            record.status = "consumed"
            return self._audit_decision(record, payload, True, None, now)

    def _binding_failure(self, payload: dict[str, Any], context: Mapping[str, Any]) -> str | None:
        if not isinstance(context, Mapping) or set(context) != self.CONTEXT_FIELDS:
            return "malformed"
        simple = (
            ("board_slug", "task_mismatch"),
            ("task_id", "task_mismatch"),
            ("run_id", "run_mismatch"),
            ("profile", "profile_mismatch"),
            ("profile_home", "profile_home_mismatch"),
            ("workspace", "workspace_mismatch"),
        )
        for field, failure in simple:
            expected = payload[field]
            actual = context[field]
            if field in {"profile_home", "workspace"}:
                try:
                    actual = _canonical_path(actual)
                except ScopedTerminalPermitError:
                    return failure
            if actual != expected:
                return failure
        source = context["source"]
        if not isinstance(source, Mapping):
            return "source_mismatch"
        expected_source = payload["source"]
        if source.get("expected_size_bytes") != expected_source["expected_size_bytes"]:
            return "size_mismatch"
        if (
            source.get("content_sha256") != expected_source["content_sha256"]
            or source.get("manifest_sha256") != expected_source["manifest_sha256"]
        ):
            return "hash_mismatch"
        if dict(source) != expected_source:
            return "source_mismatch"
        if context["destination"] != payload["destination"]:
            return "destination_mismatch"
        if (
            context["operation_sequence"] != payload["operation_sequence"]
            or context["authorized_operation_index"] != payload["authorized_operation_index"]
            or context["predecessor_receipt_digest"] != payload["predecessor_receipt_digest"]
        ):
            return "operation_sequence_mismatch"
        if context["command_digest"] != payload["command_digest"]:
            return "command_mismatch"
        return None

    def _audit_decision(
        self,
        record: _PermitRecord,
        payload: dict[str, Any],
        allowed: bool,
        failure: str | None,
        now: int,
    ) -> PermitDecision:
        kind = "terminal_permit_consumed" if allowed else "terminal_permit_rejected"
        try:
            self._write_audit(kind, self._audit_for_record(record, payload, "allow" if allowed else "deny", failure, now))
        except Exception:
            record.status = "rejected"
            return PermitDecision(False, "audit_failed", _digest(payload["permit_id"]))
        return PermitDecision(allowed, failure, _digest(payload["permit_id"]))

    def _finish_replay(self, record: _PermitRecord) -> PermitDecision:
        payload = _parse_canonical(record.envelope.payload)
        try:
            self._write_audit(
                "terminal_permit_rejected",
                self._audit_for_record(record, payload, "deny", "replay", int(self._clock())),
            )
        except Exception:
            return PermitDecision(False, "audit_failed", _digest(payload["permit_id"]))
        return PermitDecision(False, "replay", _digest(payload["permit_id"]))

    def _audit_for_arm(
        self, arm: _PendingArm, now: int, failure: str | None = None
    ) -> dict[str, Any]:
        contract = _parse_canonical(arm.contract_bytes)
        return {
            "permit_id_digest": _digest(arm.arm_id),
            "nonce_digest": None,
            "issuer_key_id": self._issuer_key_id,
            "arm_contract_digest": arm.contract_digest,
            "evidence_task_id": arm.evidence_task_id,
            "evidence_artifact_digest": arm.evidence_artifact_digest,
            "task_id": arm.task_id,
            "run_id": None,
            "profile": contract["profile"],
            "profile_home_digest": _digest(contract["profile_home"]),
            "workspace_digest": _digest(contract["workspace"]),
            "source_digest": _digest(_canonical_bytes(contract["source"])),
            "destination_digest": _digest(_canonical_bytes(contract["destination"])),
            "operation_sequence_digest": _digest(_canonical_bytes(contract["operation_sequence"])),
            "operation_index": contract["authorized_operation_index"],
            "command_digest": contract["command_digest"],
            "decision": "cancel" if failure else "armed",
            "failure_class": failure,
            "issued_at": None,
            "expires_at": arm.armed_at + arm.ttl_seconds,
            "decided_at": now,
        }

    def _audit_for_record(
        self,
        record: _PermitRecord,
        payload: dict[str, Any],
        decision: str,
        failure: str | None,
        now: int,
    ) -> dict[str, Any]:
        return {
            "permit_id_digest": _digest(payload["permit_id"]),
            "nonce_digest": _digest(payload["nonce"]),
            "issuer_key_id": payload["issuer_key_id"],
            "arm_contract_digest": record.arm_contract_digest,
            "evidence_task_id": record.evidence_task_id,
            "evidence_artifact_digest": record.evidence_artifact_digest,
            "task_id": payload["task_id"],
            "run_id": payload["run_id"],
            "profile": payload["profile"],
            "profile_home_digest": _digest(payload["profile_home"]),
            "workspace_digest": _digest(payload["workspace"]),
            "source_digest": _digest(_canonical_bytes(payload["source"])),
            "destination_digest": _digest(_canonical_bytes(payload["destination"])),
            "operation_sequence_digest": payload["operation_sequence_digest"],
            "operation_index": payload["authorized_operation_index"],
            "command_digest": payload["command_digest"],
            "decision": decision,
            "failure_class": failure,
            "issued_at": payload["issued_at"],
            "expires_at": payload["expires_at"],
            "decided_at": now,
        }

    def _write_audit(self, kind: str, payload: Mapping[str, Any]) -> None:
        if set(payload) - self.AUDIT_FIELDS:
            raise ScopedTerminalPermitError("audit_failed")
        self._audit_writer(kind, dict(payload))

    def permit_status(self, permit_id: str) -> str | None:
        with self._lock:
            record = self._permits.get(permit_id)
            return None if record is None else record.status

    def permit_status_from_digest(self, permit_id_digest: str) -> str | None:
        with self._lock:
            for permit_id, record in self._permits.items():
                if hmac.compare_digest(_digest(permit_id), permit_id_digest):
                    return record.status
        return None

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            now = int(self._clock())
            for arm in list(self._pending.values()):
                try:
                    self._write_audit(
                        "terminal_permit_cancelled",
                        self._audit_for_arm(arm, now, "issuer_unavailable"),
                    )
                except Exception:
                    pass
            self._pending.clear()
            for record in self._permits.values():
                if record.status == "issued":
                    record.status = "rejected"
            self._nonces.clear()
            self._signing_key = None
            self._public_key = None
            self._public_key_bytes = None
            self._closed = True


_ACTIVE_ISSUER: Optional[ScopedTerminalPermitIssuer] = None
_ACTIVE_ISSUER_LOCK = threading.RLock()


def get_active_issuer() -> Optional[ScopedTerminalPermitIssuer]:
    with _ACTIVE_ISSUER_LOCK:
        return _ACTIVE_ISSUER


def install_active_issuer(issuer: ScopedTerminalPermitIssuer) -> bool:
    """Install ``issuer`` only when no process-local issuer is already active."""
    global _ACTIVE_ISSUER
    if not isinstance(issuer, ScopedTerminalPermitIssuer) or issuer.closed:
        return False
    with _ACTIVE_ISSUER_LOCK:
        if _ACTIVE_ISSUER is not None:
            return False
        _ACTIVE_ISSUER = issuer
        return True


def uninstall_active_issuer(issuer: ScopedTerminalPermitIssuer) -> bool:
    """Remove only the exact issuer installed by the caller.

    Identity matching prevents delayed cleanup from an older dispatcher-owner
    lifecycle from clearing a newer owner's issuer.
    """
    global _ACTIVE_ISSUER
    with _ACTIVE_ISSUER_LOCK:
        if _ACTIVE_ISSUER is not issuer:
            return False
        _ACTIVE_ISSUER = None
        return True
