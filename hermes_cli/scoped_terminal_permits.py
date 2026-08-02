"""Process-local authenticated permits for one exact Kanban terminal operation.

This module deliberately contains no file, environment, database, CLI, or socket
issuance surface. The ephemeral Ed25519 key and all pending/terminal state stay
inside the dispatcher-lock-owning gateway process.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import socket
import stat
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, NoReturn, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_DOMAIN = b"HERMES-KANBAN-TERMINAL-PERMIT\x00v1\x00"
_RESPONSE_DOMAIN = b"HERMES-KANBAN-TERMINAL-PERMIT-RESPONSE\x00v1\x00"
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
_OPERATION_PREFIXES = {
    "rclone_copy": ("rclone", "copyto"),
    "rclone_verify": ("rclone", "check"),
    "unlink_manifest_batch": ("rm", "--"),
    "rmdir_manifest_batch": ("rmdir", "--"),
}
_SHELL_META_CHARS = frozenset(";&|<>`$*?[]{}~'\\\"\x00")


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
class PreparedPermitTicket:
    """Opaque Phase-A result passed to the later broker-consume phase.

    The signed envelope and verification key intentionally remain private to
    the worker client.  Callers can use only the digest/index metadata when
    constructing an execution request; this object never authorizes or
    consumes a permit by itself.
    """

    _client: object
    _permit_id_digest: str
    _operation_index: int
    _command_digest: str

    @property
    def permit_id_digest(self) -> str:
        return self._permit_id_digest

    @property
    def operation_index(self) -> int:
        return self._operation_index

    @property
    def command_digest(self) -> str:
        return self._command_digest

    def __repr__(self) -> str:
        return (
            "PreparedPermitTicket("
            f"permit_id_digest={self._permit_id_digest!r}, "
            f"operation_index={self._operation_index})"
        )


@dataclass(frozen=True)
class PreparedTerminalContract:
    """Non-authorizing, digest-only preparation result for a typed contract."""

    contract: dict[str, Any]
    canonical_bytes: bytes
    contract_digest: str
    operation_sequence_digest: str
    source_size_bytes: int
    source_content_sha256: str | None
    manifest_sha256: str | None
    readback_json: str


@dataclass(frozen=True)
class _PreparedTicketBinding:
    """Private Phase-A metadata retained separately from the public ticket."""

    permit_id_digest: str
    operation_index: int
    command_digest: str


PERMIT_FD_ENV = "HERMES_KANBAN_TERMINAL_PERMIT_FD"


@dataclass
class SpawnPermitChannel:
    """The one-shot capability channel handed to a spawned worker.

    The parent endpoint remains owned by the issuer.  Only ``child_endpoint``
    is placed in ``pass_fds``; the descriptor number is merely an env bridge
    and carries no authorization by itself.
    """

    permit: SignedPermit
    parent_endpoint: socket.socket
    child_endpoint: socket.socket
    public_key: bytes = b""
    _child_released: bool = False

    @property
    def child_fd(self) -> int:
        return self.child_endpoint.fileno()

    @property
    def env_bridge(self) -> dict[str, str]:
        return {PERMIT_FD_ENV: str(self.child_fd)}

    def send_envelope(self) -> None:
        """Send the signed envelope without exposing it in env or storage."""
        body = _canonical_bytes(
            {
                "payload": self.permit.payload.decode("utf-8"),
                "signature": self.permit.signature.hex(),
                "public_key": self.public_key.hex(),
            }
        )
        self.parent_endpoint.sendall(len(body).to_bytes(4, "big") + body)

    def release_child_endpoint(self) -> None:
        if self._child_released:
            return
        self._child_released = True
        try:
            self.child_endpoint.close()
        except OSError:
            pass

    def close(self) -> None:
        self.release_child_endpoint()
        try:
            self.parent_endpoint.close()
        except OSError:
            pass


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


_CONSUME_REQUEST_FIELDS = frozenset(
    {"version", "permit_id", "payload", "signature", "challenge", "context"}
)
_CONSUME_RESPONSE_FIELDS = frozenset(
    {"version", "permit_id_digest", "challenge", "allowed", "failure_class", "decided_at"}
)


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
    if ".." in path.split(os.sep):
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


def _require_argv_text(value: Any) -> str:
    if isinstance(value, str) and any(ord(char) < 32 for char in value):
        raise ScopedTerminalPermitError("operation_forbidden")
    return _require_text(value)


def _validate_simple_argv(argv: list[str]) -> None:
    for arg in argv:
        if any(char in _SHELL_META_CHARS for char in arg):
            raise ScopedTerminalPermitError("operation_forbidden")
        if any(token in arg for token in ("$(", "${", "<(", ">(", "))")):
            raise ScopedTerminalPermitError("operation_forbidden")


def _canonical_operation_path(value: str) -> str:
    if not os.path.isabs(value) or ".." in value.split(os.sep):
        raise ScopedTerminalPermitError("operation_forbidden")
    canonical = os.path.realpath(value)
    if canonical != value:
        raise ScopedTerminalPermitError("operation_forbidden")
    return canonical


def _path_is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((path, root)) == root and path != root
    except ValueError:
        return False


def _validate_manifest_targets(
    operation: Mapping[str, Any], source: Mapping[str, Any], *, directories: bool
) -> None:
    argv = operation["argv"]
    if operation["manifest_ref"] is None or source["manifest_path"] is None:
        raise ScopedTerminalPermitError("operation_forbidden")
    targets = argv[2:]
    if not targets:
        raise ScopedTerminalPermitError("operation_forbidden")
    root = source["canonical_path"]
    canonical_targets = [_canonical_operation_path(target) for target in targets]
    if source["kind"] == "file":
        if any(target != root for target in canonical_targets):
            raise ScopedTerminalPermitError("operation_forbidden")
    elif any(not _path_is_within(target, root) for target in canonical_targets):
        raise ScopedTerminalPermitError("operation_forbidden")
    if len(set(canonical_targets)) != len(canonical_targets):
        raise ScopedTerminalPermitError("operation_forbidden")
    if directories:
        for earlier_index, earlier in enumerate(canonical_targets):
            for later in canonical_targets[earlier_index + 1 :]:
                if _path_is_within(later, earlier):
                    raise ScopedTerminalPermitError("operation_forbidden")


def _validate_operation_policy(
    operation: Mapping[str, Any],
    source: Mapping[str, Any],
    destination: Mapping[str, Any],
    workspace: str,
) -> None:
    kind = operation["kind"]
    prefix = _OPERATION_PREFIXES.get(kind)
    if prefix is None or operation["cwd"] != workspace:
        raise ScopedTerminalPermitError("operation_forbidden")
    argv = operation["argv"]
    _validate_simple_argv(argv)
    if operation["source_ref"] != "source" or operation["destination_ref"] != "destination":
        raise ScopedTerminalPermitError("operation_forbidden")
    if kind in {"rclone_copy", "rclone_verify"}:
        if (
            len(argv) != 4
            or tuple(argv[:2]) != prefix
            or argv[2] != source["canonical_path"]
            or argv[3] != destination["canonical_uri"]
            or operation["manifest_ref"] is not None
        ):
            raise ScopedTerminalPermitError("operation_forbidden")
        return
    if tuple(argv[:2]) != prefix:
        raise ScopedTerminalPermitError("operation_forbidden")
    _validate_manifest_targets(
        operation,
        source,
        directories=kind == "rmdir_manifest_batch",
    )


def _validate_operations(
    value: Any,
    *,
    source: Mapping[str, Any],
    destination: Mapping[str, Any],
    workspace: str,
) -> list[dict[str, Any]]:
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
        item["argv"] = [_require_argv_text(arg) for arg in item["argv"]]
        item["cwd"] = _canonical_operation_path(item["cwd"])
        if item["background"] is not False or item["pty"] is not False:
            raise ScopedTerminalPermitError("malformed")
        for field in ("source_ref", "destination_ref"):
            item[field] = _require_text(item[field])
        if item["manifest_ref"] is not None:
            item["manifest_ref"] = _require_text(item["manifest_ref"])
        item["execution_context_digest"] = _require_digest(item["execution_context_digest"])
        _validate_operation_policy(item, source, destination, workspace)
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
    copied["operation_sequence"] = _validate_operations(
        copied["operation_sequence"],
        source=copied["source"],
        destination=copied["destination"],
        workspace=copied["workspace"],
    )
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


def _read_preparation_file_digest(path: str) -> tuple[int, str]:
    """Read one canonical regular file for non-destructive preparation."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ScopedTerminalPermitError("preparation_source_unreadable") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ScopedTerminalPermitError("preparation_source_unreadable")
        try:
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        except OSError as exc:
            raise ScopedTerminalPermitError("preparation_source_changed") from exc
    finally:
        os.close(fd)
    if size != info.st_size:
        raise ScopedTerminalPermitError("preparation_source_changed")
    return size, digest.hexdigest()


def _preparation_source_readback(source: Mapping[str, Any]) -> tuple[int, str | None, str | None]:
    """Verify declared source metadata without writing or executing anything."""
    path = source["canonical_path"]
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ScopedTerminalPermitError("preparation_source_unreadable") from exc
    if source["kind"] == "file" or source["kind"] == "manifest":
        if not stat.S_ISREG(info.st_mode):
            raise ScopedTerminalPermitError("preparation_source_unreadable")
        size, digest = _read_preparation_file_digest(path)
    elif source["kind"] == "directory":
        if not stat.S_ISDIR(info.st_mode):
            raise ScopedTerminalPermitError("preparation_source_unreadable")
        size = 0
        for root, dirs, files in os.walk(path, followlinks=False):
            for name in dirs:
                if stat.S_ISLNK(os.lstat(os.path.join(root, name)).st_mode):
                    raise ScopedTerminalPermitError("preparation_source_unreadable")
            dirs[:] = sorted(dirs)
            for name in sorted(files):
                child = os.path.join(root, name)
                child_info = os.lstat(child)
                if not stat.S_ISREG(child_info.st_mode):
                    raise ScopedTerminalPermitError("preparation_source_unreadable")
                size += child_info.st_size
        digest = None
    else:  # pragma: no cover - _normalize_contract owns this check.
        raise ScopedTerminalPermitError("malformed")
    if size != source["expected_size_bytes"]:
        raise ScopedTerminalPermitError("preparation_size_mismatch")
    expected_content = source["content_sha256"]
    if expected_content is not None and digest != expected_content:
        raise ScopedTerminalPermitError("preparation_hash_mismatch")
    manifest_digest = None
    if source["manifest_path"] is not None:
        _, manifest_digest = _read_preparation_file_digest(source["manifest_path"])
        if manifest_digest != source["manifest_sha256"]:
            raise ScopedTerminalPermitError("preparation_manifest_mismatch")
    return size, digest, manifest_digest


def prepare_scoped_terminal_contract(
    contract: Mapping[str, Any],
) -> PreparedTerminalContract:
    """Validate and read back an exact contract without arming or executing it.

    This is deliberately a pure preparation boundary: it may read the declared
    source and manifest to verify size/digests, but it never grants authority,
    opens a network connection, invokes a subprocess, or mutates storage.
    """
    normalized = _normalize_contract(contract)
    source_size, content_digest, manifest_digest = _preparation_source_readback(
        normalized["source"]
    )
    canonical = _canonical_bytes(normalized)
    sequence_digest = _digest(_canonical_bytes(normalized["operation_sequence"]))
    readback = _canonical_bytes(
        {
            "contract_digest": _digest(canonical),
            "operation_sequence_digest": sequence_digest,
            "authorized_operation_index": normalized["authorized_operation_index"],
            "source_size_bytes": source_size,
            "source_content_sha256": content_digest,
            "manifest_sha256": manifest_digest,
        }
    ).decode("utf-8")
    return PreparedTerminalContract(
        contract=normalized,
        canonical_bytes=canonical,
        contract_digest=_digest(canonical),
        operation_sequence_digest=sequence_digest,
        source_size_bytes=source_size,
        source_content_sha256=content_digest,
        manifest_sha256=manifest_digest,
        readback_json=readback,
    )


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
    operations = _validate_operations(
        payload["operation_sequence"],
        source=payload["source"],
        destination=payload["destination"],
        workspace=payload["workspace"],
    )
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


def _default_audit_writer(kind: str, payload: Mapping[str, Any]) -> None:
    """Persist a digest-only permit event through the board transaction helper."""
    from hermes_cli.kanban_db import append_terminal_permit_event

    append_terminal_permit_event(kind, payload)


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
        self._audit_writer = audit_writer or _default_audit_writer
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
        self._challenges: set[str] = set()
        self._spawn_channels: dict[str, SpawnPermitChannel] = {}

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

    def cancel_pending_arm(
        self,
        *,
        board_slug: str,
        task_id: str,
        failure_class: str = "resume_failed",
    ) -> bool:
        """Spend a pending arm when the paired task resume cannot commit."""
        with self._lock:
            board = _require_text(board_slug).strip().lower()
            task = _require_text(task_id)
            arm = self._pending.pop((board, task), None)
            if arm is None:
                return False
            now = int(self._clock())
            try:
                self._write_audit(
                    "terminal_permit_cancelled",
                    self._audit_for_arm(arm, now, failure_class),
                )
            except Exception:
                raise ScopedTerminalPermitError("audit_failed") from None
            return True

    def arm_and_resume(
        self,
        *,
        board_slug: str,
        task_id: str,
        contract: Mapping[str, Any],
        ttl_seconds: int,
        evidence_task_id: str,
        evidence_artifact_digest: str,
        resume: Callable[[], bool],
    ) -> ArmReceipt:
        """Arm and resume one task, cancelling authority if resume fails."""
        with self._lock:
            receipt = self.arm_next_run(
                board_slug=board_slug,
                task_id=task_id,
                contract=contract,
                ttl_seconds=ttl_seconds,
                evidence_task_id=evidence_task_id,
                evidence_artifact_digest=evidence_artifact_digest,
            )
            try:
                resumed = resume()
            except Exception:
                resumed = False
            if not resumed:
                self.cancel_pending_arm(
                    board_slug=board_slug,
                    task_id=task_id,
                    failure_class="resume_failed",
                )
                raise ScopedTerminalPermitError("resume_failed")
            return receipt

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

    def activate_spawn_channel(
        self,
        *,
        board_slug: str,
        task_id: str,
        run_id: int,
        profile: str,
        profile_home: str,
        workspace: str,
    ) -> SpawnPermitChannel:
        """Activate one exact arm and create its POSIX capability channel."""
        envelope = self.activate_for_spawn(
            board_slug=board_slug,
            task_id=task_id,
            run_id=run_id,
            profile=profile,
            profile_home=profile_home,
            workspace=workspace,
        )
        parent_endpoint = child_endpoint = None
        try:
            parent_endpoint, child_endpoint = socket.socketpair()
            parent_endpoint.set_inheritable(False)
            child_endpoint.set_inheritable(False)
            channel = SpawnPermitChannel(
                envelope,
                parent_endpoint,
                child_endpoint,
                self._public_key_bytes or b"",
            )
            with self._lock:
                self._spawn_channels[envelope.permit_id] = channel
            threading.Thread(
                target=self._serve_spawn_channel,
                args=(channel,),
                name="hermes-scoped-permit-broker",
                daemon=True,
            ).start()
            return channel
        except Exception:
            for endpoint in (parent_endpoint, child_endpoint):
                if endpoint is not None:
                    try:
                        endpoint.close()
                    except OSError:
                        pass
            with self._lock:
                record = self._permits.get(envelope.permit_id)
                if record is not None:
                    record.status = "cancelled"
            raise ScopedTerminalPermitError("channel_failed") from None

    def _serve_spawn_channel(self, channel: SpawnPermitChannel) -> None:
        """Serve exactly one authenticated consume request on a spawn channel."""
        try:
            frame_size = int.from_bytes(_recv_exact(channel.parent_endpoint, 4), "big")
            request_bytes = _recv_exact(channel.parent_endpoint, frame_size)
            response = self._handle_consume_request(channel, request_bytes)
            channel.parent_endpoint.sendall(
                len(response).to_bytes(4, "big") + response
            )
        except (ScopedTerminalPermitError, OSError, ValueError, TypeError):
            # A lost worker or malformed transport is terminal for this channel;
            # never fall back to ordinary approval or revive the permit.
            try:
                with self._lock:
                    record = self._permits.get(channel.permit.permit_id)
                if record is not None and record.status == "issued":
                    self.consume(
                        record.envelope,
                        context={},
                        challenge=secrets.token_hex(32),
                    )
            except Exception:
                pass
            pass
        finally:
            with self._lock:
                self._spawn_channels.pop(channel.permit.permit_id, None)
            channel.close()

    def _handle_consume_request(
        self, channel: SpawnPermitChannel, request_bytes: bytes
    ) -> bytes:
        """Validate the wire envelope, consume the parent-held permit, and sign deny/allow."""
        challenge = secrets.token_hex(32)
        failure = "malformed"
        decision = PermitDecision(False, failure, _digest(channel.permit.permit_id))
        try:
            request = _parse_canonical(request_bytes)
            if set(request) != _CONSUME_REQUEST_FIELDS or request.get("version") != 1:
                raise ScopedTerminalPermitError("malformed")
            challenge = request["challenge"]
            if not isinstance(challenge, str) or not re.fullmatch(r"[0-9a-f]{64}", challenge):
                raise ScopedTerminalPermitError("malformed")
            with self._lock:
                if challenge in self._challenges:
                    raise ScopedTerminalPermitError("replay")
                self._challenges.add(challenge)
            permit_id = _require_text(request["permit_id"])
            payload = _require_text(request["payload"]).encode("utf-8")
            signature = _decode_hex(request["signature"], length=64)
            context = request["context"]
            envelope = SignedPermit(permit_id, payload, signature)
            if permit_id != channel.permit.permit_id:
                raise ScopedTerminalPermitError("malformed")
            decision = self.consume(envelope, context=context, challenge=challenge)
        except ScopedTerminalPermitError as exc:
            if challenge not in self._challenges and re.fullmatch(
                r"[0-9a-f]{64}", challenge
            ):
                self._challenges.add(challenge)
            try:
                record = self._permits.get(channel.permit.permit_id)
                if record is not None and record.status == "issued":
                    decision = self.consume(
                        record.envelope,
                        context={},
                        challenge=challenge,
                    )
            except Exception:
                decision = PermitDecision(
                    False, exc.failure_class, _digest(channel.permit.permit_id)
                )
            if decision.failure_class is None or decision.allowed:
                decision = PermitDecision(
                    False, exc.failure_class, _digest(channel.permit.permit_id)
                )
        except Exception:
            decision = PermitDecision(
                False, "malformed", _digest(channel.permit.permit_id)
            )
        response = {
            "version": 1,
            "permit_id_digest": decision.permit_id_digest
            or _digest(channel.permit.permit_id),
            "challenge": challenge,
            "allowed": bool(decision.allowed),
            "failure_class": decision.failure_class,
            "decided_at": int(self._clock()),
        }
        response_bytes = _canonical_bytes(response)
        with self._lock:
            signing_key = self._signing_key
            if signing_key is None:
                raise ScopedTerminalPermitError("issuer_unavailable")
            signature = signing_key.sign(_RESPONSE_DOMAIN + response_bytes)
        return _canonical_bytes({"response": response_bytes.decode("utf-8"), "signature": signature.hex()})

    def cancel_spawn_channel(self, channel: SpawnPermitChannel) -> None:
        """Spend an activated spawn permit and close both channel endpoints."""
        with self._lock:
            record = self._permits.get(channel.permit.permit_id)
            if record is not None and record.status == "issued":
                record.status = "cancelled"
                try:
                    payload = _parse_canonical(record.envelope.payload)
                    self._write_audit(
                        "terminal_permit_cancelled",
                        self._audit_for_record(
                            record,
                            payload,
                            "cancel",
                            "spawn_failed",
                            int(self._clock()),
                        ),
                    )
                except Exception:
                    pass
            self._spawn_channels.pop(channel.permit.permit_id, None)
            channel.close()

    def release_spawn_child(self, channel: SpawnPermitChannel) -> None:
        """Close the gateway's duplicate of the inherited child endpoint."""
        channel.release_child_endpoint()

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
            for channel in self._spawn_channels.values():
                channel.close()
            self._spawn_channels.clear()
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


# ---------------------------------------------------------------------------
# Worker-side Phase-A client
# ---------------------------------------------------------------------------

_WORKER_CHANNEL_LOCK = threading.Lock()
_WORKER_CHANNEL_CLAIMED = False
_WORKER_PERMIT_CLIENT: Optional["_WorkerPermitClient"] = None
_PREPARED_TICKET_LOCK = threading.RLock()
_PREPARED_TICKET_ORIGINS: dict[
    int, tuple[PreparedPermitTicket, "_WorkerPermitClient"]
] = {}


def _retain_prepared_ticket(
    ticket: PreparedPermitTicket, client: "_WorkerPermitClient"
) -> None:
    """Retain the Phase-A origin outside caller-mutable ticket metadata."""
    with _PREPARED_TICKET_LOCK:
        _PREPARED_TICKET_ORIGINS[id(ticket)] = (ticket, client)


def _discard_prepared_ticket(
    ticket: PreparedPermitTicket | None, client: "_WorkerPermitClient"
) -> None:
    if ticket is None:
        return
    with _PREPARED_TICKET_LOCK:
        retained = _PREPARED_TICKET_ORIGINS.get(id(ticket))
        if retained is not None and retained[0] is ticket and retained[1] is client:
            _PREPARED_TICKET_ORIGINS.pop(id(ticket), None)


def _take_prepared_ticket_origin(
    ticket: object,
) -> "_WorkerPermitClient":
    """Atomically spend and resolve the exact privately retained ticket origin."""
    with _PREPARED_TICKET_LOCK:
        retained = _PREPARED_TICKET_ORIGINS.pop(id(ticket), None)
        if (
            isinstance(ticket, PreparedPermitTicket)
            and retained is not None
            and retained[0] is ticket
        ):
            return retained[1]
        # An unrecognized ticket must not leave any privately retained Phase-A
        # capability or the authenticated claimed channel live. Fail-close
        # without consulting the incoming ticket's caller-mutable ``_client``.
        retained_entries = list(_PREPARED_TICKET_ORIGINS.values())
        if retained is not None:
            retained_entries.append(retained)
        had_prepared_origin = bool(retained_entries)
        active_origins = {
            id(origin): origin
            for _, origin in retained_entries
        }
        _PREPARED_TICKET_ORIGINS.clear()
        with _WORKER_CHANNEL_LOCK:
            claimed_origin = _WORKER_PERMIT_CLIENT
        if claimed_origin is not None:
            active_origins[id(claimed_origin)] = claimed_origin
        for origin in active_origins.values():
            origin.close()
    if not isinstance(ticket, PreparedPermitTicket) or had_prepared_origin:
        raise ScopedTerminalPermitError("malformed")
    raise ScopedTerminalPermitError("missing")


def _recv_exact(endpoint: socket.socket, size: int) -> bytes:
    if size < 0 or size > 2 * 1024 * 1024:
        raise ScopedTerminalPermitError("malformed")
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = endpoint.recv(remaining)
        except socket.timeout:
            raise ScopedTerminalPermitError("broker_unreachable") from None
        except OSError:
            raise ScopedTerminalPermitError("broker_unreachable") from None
        if not chunk:
            raise ScopedTerminalPermitError("partial_bridge")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _decode_hex(value: Any, *, length: int) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2:
        raise ScopedTerminalPermitError("malformed")
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        raise ScopedTerminalPermitError("malformed") from None
    if decoded.hex() != value:
        raise ScopedTerminalPermitError("malformed")
    return decoded


class _WorkerPermitClient:
    """Private authenticated view of the one inherited permit envelope."""

    __slots__ = (
        "_envelope",
        "_public_key",
        "_payload",
        "_endpoint",
        "_closed",
        "_prepared_ticket",
        "_prepared_ticket_binding",
    )

    def __init__(
        self,
        envelope: SignedPermit,
        public_key: bytes,
        payload: dict[str, Any],
        endpoint: socket.socket,
    ):
        self._envelope = envelope
        self._public_key = public_key
        self._payload = payload
        self._endpoint = endpoint
        self._closed = False
        self._prepared_ticket: PreparedPermitTicket | None = None
        self._prepared_ticket_binding: _PreparedTicketBinding | None = None

    @property
    def permit_id_digest(self) -> str:
        return _digest(self._envelope.permit_id)

    def prepare(
        self,
        command: str,
        env_type: str,
        execution_context: Mapping[str, Any],
    ) -> PreparedPermitTicket:
        with _PREPARED_TICKET_LOCK:
            if self._closed or self._endpoint is None:
                raise ScopedTerminalPermitError("missing")
        payload = self._payload
        if env_type != "local":
            raise ScopedTerminalPermitError("operation_forbidden")
        if not isinstance(execution_context, Mapping):
            raise ScopedTerminalPermitError("malformed")
        required = ScopedTerminalPermitIssuer.CONTEXT_FIELDS
        if not required.issubset(execution_context):
            raise ScopedTerminalPermitError("malformed")

        for field, failure in (
            ("board_slug", "task_mismatch"),
            ("task_id", "task_mismatch"),
            ("run_id", "run_mismatch"),
        ):
            if execution_context[field] != payload[field]:
                raise ScopedTerminalPermitError(failure)
        if (
            not isinstance(execution_context["profile"], str)
            or execution_context["profile"].strip().lower() != payload["profile"]
        ):
            raise ScopedTerminalPermitError("profile_mismatch")
        for field, failure in (
            ("profile_home", "profile_home_mismatch"),
            ("workspace", "workspace_mismatch"),
        ):
            try:
                actual = _canonical_path(execution_context[field])
            except ScopedTerminalPermitError:
                raise ScopedTerminalPermitError(failure) from None
            if actual != payload[field]:
                raise ScopedTerminalPermitError(failure)

        try:
            actual_source = _validate_source(execution_context["source"])
        except ScopedTerminalPermitError:
            raise ScopedTerminalPermitError("source_mismatch") from None
        expected_source = payload["source"]
        if actual_source["expected_size_bytes"] != expected_source["expected_size_bytes"]:
            raise ScopedTerminalPermitError("size_mismatch")
        if (
            actual_source["content_sha256"] != expected_source["content_sha256"]
            or actual_source["manifest_sha256"] != expected_source["manifest_sha256"]
        ):
            raise ScopedTerminalPermitError("hash_mismatch")
        if actual_source != expected_source:
            raise ScopedTerminalPermitError("source_mismatch")
        try:
            actual_destination = _validate_destination(execution_context["destination"])
        except ScopedTerminalPermitError:
            raise ScopedTerminalPermitError("destination_mismatch") from None
        if actual_destination != payload["destination"]:
            raise ScopedTerminalPermitError("destination_mismatch")

        if (
            execution_context["operation_sequence"] != payload["operation_sequence"]
            or execution_context["authorized_operation_index"]
            != payload["authorized_operation_index"]
            or execution_context["predecessor_receipt_digest"]
            != payload["predecessor_receipt_digest"]
        ):
            raise ScopedTerminalPermitError("operation_sequence_mismatch")
        if execution_context["command_digest"] != payload["command_digest"]:
            raise ScopedTerminalPermitError("command_mismatch")

        if any(
            execution_context.get(field)
            for field in (
                "background",
                "pty",
                "stdin",
                "force",
                "notify_on_complete",
                "watch_patterns",
            )
        ):
            raise ScopedTerminalPermitError("operation_forbidden")
        command_text = command if isinstance(command, str) else ""
        try:
            argv = shlex.split(command_text, posix=True)
        except (ValueError, TypeError):
            raise ScopedTerminalPermitError("operation_forbidden") from None
        if not argv or shlex.join(argv) != command_text or any(
            any(ord(char) < 32 for char in arg) for arg in argv
        ):
            raise ScopedTerminalPermitError("operation_forbidden")
        if any(any(char in _SHELL_META_CHARS for char in arg) for arg in argv):
            raise ScopedTerminalPermitError("operation_forbidden")
        operation = payload["operation_sequence"][payload["authorized_operation_index"]]
        if any(
            token in argv
            for token in ("sh", "bash", "zsh", "env", "sudo", "hermes")
        ) and argv != operation["argv"]:
            raise ScopedTerminalPermitError("operation_forbidden")
        if argv != operation["argv"]:
            raise ScopedTerminalPermitError("command_mismatch")
        if execution_context.get("cwd") is not None:
            try:
                cwd = _canonical_operation_path(execution_context["cwd"])
            except ScopedTerminalPermitError:
                raise ScopedTerminalPermitError("operation_forbidden") from None
            if cwd != operation["cwd"]:
                raise ScopedTerminalPermitError("operation_forbidden")
        now = int(time.time())
        if now < payload["not_before"]:
            raise ScopedTerminalPermitError("not_yet_valid")
        if now > payload["expires_at"]:
            raise ScopedTerminalPermitError("expired")
        binding = _PreparedTicketBinding(
            permit_id_digest=self.permit_id_digest,
            operation_index=payload["authorized_operation_index"],
            command_digest=payload["command_digest"],
        )
        ticket = PreparedPermitTicket(
            self,
            binding.permit_id_digest,
            binding.operation_index,
            binding.command_digest,
        )
        with _PREPARED_TICKET_LOCK:
            if self._closed or self._endpoint is None:
                raise ScopedTerminalPermitError("missing")
            _discard_prepared_ticket(self._prepared_ticket, self)
            self._prepared_ticket = ticket
            self._prepared_ticket_binding = binding
            _retain_prepared_ticket(ticket, self)
        return ticket

    def _reject_pre_send_input(self, failure_class: str) -> NoReturn:
        """Invalidate local Phase A state and terminalize the capability channel."""
        self.close()
        raise ScopedTerminalPermitError(failure_class)

    def consume(
        self, ticket: PreparedPermitTicket, execution_context: Mapping[str, Any]
    ) -> PermitDecision:
        with _PREPARED_TICKET_LOCK:
            if self._closed or self._endpoint is None:
                self._reject_pre_send_input("missing")
            binding = self._prepared_ticket_binding
            if (
                not isinstance(ticket, PreparedPermitTicket)
                or ticket is not self._prepared_ticket
                or ticket._client is not self
                or binding is None
                or not isinstance(ticket._permit_id_digest, str)
                or not hmac.compare_digest(
                    ticket._permit_id_digest, binding.permit_id_digest
                )
                or ticket._operation_index != binding.operation_index
                or not isinstance(ticket._command_digest, str)
                or not hmac.compare_digest(
                    ticket._command_digest, binding.command_digest
                )
            ):
                self._reject_pre_send_input("malformed")
            if (
                not isinstance(execution_context, Mapping)
                or not ScopedTerminalPermitIssuer.CONTEXT_FIELDS.issubset(
                    execution_context
                )
            ):
                self._reject_pre_send_input("malformed")
            # The ticket capability is one-shot even if later wire serialization
            # fails. A second caller cannot reuse Phase-A authority on this client.
            _discard_prepared_ticket(ticket, self)
            self._prepared_ticket = None
            self._prepared_ticket_binding = None
        challenge = secrets.token_hex(32)
        request = {
            "version": 1,
            "permit_id": self._envelope.permit_id,
            "payload": self._envelope.payload.decode("utf-8"),
            "signature": self._envelope.signature.hex(),
            "challenge": challenge,
            # The terminal execution context also carries transient dispatch
            # flags (cwd, stdin, notifications). Only the signed binding
            # fields cross the broker; the parent requires this exact shape.
            "context": {
                key: execution_context[key]
                for key in ScopedTerminalPermitIssuer.CONTEXT_FIELDS
            },
        }
        request_bytes = _canonical_bytes(request)
        endpoint = self._endpoint
        try:
            endpoint.sendall(len(request_bytes).to_bytes(4, "big") + request_bytes)
            frame_size = int.from_bytes(_recv_exact(endpoint, 4), "big")
            response_frame = _recv_exact(endpoint, frame_size)
        except (ScopedTerminalPermitError, OSError):
            raise ScopedTerminalPermitError("broker_unreachable") from None
        finally:
            self.close()
        try:
            frame = _parse_canonical(response_frame)
            if set(frame) != {"response", "signature"}:
                raise ScopedTerminalPermitError("broker_protocol_error")
            response_bytes = _require_text(frame["response"]).encode("utf-8")
            signature = _decode_hex(frame["signature"], length=64)
            response = _parse_canonical(response_bytes)
            if set(response) != _CONSUME_RESPONSE_FIELDS or response.get("version") != 1:
                raise ScopedTerminalPermitError("broker_protocol_error")
            if (
                response["permit_id_digest"] != self.permit_id_digest
                or response["challenge"] != challenge
                or not isinstance(response["allowed"], bool)
                or (
                    response["failure_class"] is not None
                    and not isinstance(response["failure_class"], str)
                )
            ):
                raise ScopedTerminalPermitError("broker_protocol_error")
            try:
                Ed25519PublicKey.from_public_bytes(self._public_key).verify(
                    signature, _RESPONSE_DOMAIN + response_bytes
                )
            except (InvalidSignature, ValueError, TypeError):
                raise ScopedTerminalPermitError("response_signature_invalid") from None
            if response["allowed"]:
                if response["failure_class"] is not None:
                    raise ScopedTerminalPermitError("broker_protocol_error")
                return PermitDecision(True, None, self.permit_id_digest)
            return PermitDecision(
                False,
                response["failure_class"] or "malformed",
                self.permit_id_digest,
            )
        except ScopedTerminalPermitError:
            raise
        except Exception:
            raise ScopedTerminalPermitError("broker_protocol_error") from None

    def close(self) -> None:
        with _PREPARED_TICKET_LOCK:
            if self._closed:
                return
            self._closed = True
            _discard_prepared_ticket(self._prepared_ticket, self)
            self._prepared_ticket = None
            self._prepared_ticket_binding = None
            endpoint = self._endpoint
            self._endpoint = None
        if endpoint is not None:
            try:
                endpoint.close()
            except OSError:
                pass


def claim_worker_permit_channel() -> _WorkerPermitClient:
    """Claim, authenticate, and consume the inherited FD bridge once.

    The environment value is only a descriptor bridge.  It is removed before
    any caller can inspect it, and the descriptor is made close-on-exec before
    the signed envelope is read.  All failures are stable, non-secret classes.
    """
    global _WORKER_CHANNEL_CLAIMED, _WORKER_PERMIT_CLIENT
    with _WORKER_CHANNEL_LOCK:
        if _WORKER_CHANNEL_CLAIMED:
            raise ScopedTerminalPermitError("missing")
        _WORKER_CHANNEL_CLAIMED = True
        fd_text = os.environ.pop(PERMIT_FD_ENV, None)
        if fd_text is None:
            raise ScopedTerminalPermitError("missing")
        endpoint: socket.socket | None = None
        try:
            fd = int(fd_text, 10)
            if fd < 0:
                raise ValueError
            os.set_inheritable(fd, False)
            endpoint = socket.socket(fileno=fd)
            endpoint.set_inheritable(False)
            endpoint.settimeout(5.0)
            frame_size = int.from_bytes(_recv_exact(endpoint, 4), "big")
            body_bytes = _recv_exact(endpoint, frame_size)
        except ScopedTerminalPermitError:
            if endpoint is not None:
                endpoint.close()
            raise
        except (OSError, TypeError, ValueError):
            if endpoint is not None:
                try:
                    endpoint.close()
                except OSError:
                    pass
            raise ScopedTerminalPermitError("partial_bridge") from None

        try:
            body = _parse_canonical(body_bytes)
            if set(body) != {"payload", "signature", "public_key"}:
                raise ScopedTerminalPermitError("malformed")
            payload_bytes = _require_text(body["payload"]).encode("utf-8")
            signature = _decode_hex(body["signature"], length=64)
            public_key = _decode_hex(body["public_key"], length=32)
            payload = _parse_canonical(payload_bytes)
            _validate_payload(payload)
            if _digest(public_key) != payload["issuer_key_id"]:
                raise ScopedTerminalPermitError("unknown_key_generation")
            try:
                Ed25519PublicKey.from_public_bytes(public_key).verify(
                    signature, _DOMAIN + payload_bytes
                )
            except (InvalidSignature, ValueError, TypeError):
                raise ScopedTerminalPermitError("signature_invalid") from None
            permit_id = _require_text(payload["permit_id"])
            envelope = SignedPermit(permit_id, payload_bytes, signature)
            now = int(time.time())
            if now < payload["not_before"]:
                raise ScopedTerminalPermitError("not_yet_valid")
            if now > payload["expires_at"]:
                raise ScopedTerminalPermitError("expired")
            client = _WorkerPermitClient(envelope, public_key, payload, endpoint)
            _WORKER_PERMIT_CLIENT = client
            return client
        except ScopedTerminalPermitError:
            if endpoint is not None:
                try:
                    endpoint.close()
                except OSError:
                    pass
            raise
        except Exception:
            if endpoint is not None:
                try:
                    endpoint.close()
                except OSError:
                    pass
            raise ScopedTerminalPermitError("malformed") from None


def get_worker_permit_client() -> Optional[_WorkerPermitClient]:
    with _WORKER_CHANNEL_LOCK:
        return _WORKER_PERMIT_CLIENT


def build_worker_permit_execution_context(
    *,
    cwd: str,
    background: bool,
    pty: bool,
    stdin: bool,
    force: bool,
    notify_on_complete: bool,
    watch_patterns: Optional[list[str]],
    client: Optional[_WorkerPermitClient] = None,
) -> dict[str, Any]:
    """Combine signed operation scope with live worker and terminal identity.

    Source, destination, sequence, and command metadata come only from the
    authenticated envelope. Process identity and transient dispatch modes are
    sampled from the actual worker call so Phase A can compare both boundaries.
    """
    selected = client or get_worker_permit_client()
    if selected is None:
        raise ScopedTerminalPermitError("missing")
    payload = selected._payload
    run_id_text = os.environ.get("HERMES_KANBAN_RUN_ID", "")
    try:
        run_id: Any = int(run_id_text)
    except (TypeError, ValueError):
        run_id = run_id_text
    return {
        "board_slug": os.environ.get("HERMES_KANBAN_BOARD", ""),
        "task_id": os.environ.get("HERMES_KANBAN_TASK", ""),
        "run_id": run_id,
        "profile": os.environ.get("HERMES_PROFILE", ""),
        "profile_home": os.environ.get("HERMES_HOME", ""),
        "workspace": os.environ.get("HERMES_KANBAN_WORKSPACE", ""),
        "source": copy.deepcopy(payload["source"]),
        "destination": copy.deepcopy(payload["destination"]),
        "operation_sequence": copy.deepcopy(payload["operation_sequence"]),
        "authorized_operation_index": payload["authorized_operation_index"],
        "predecessor_receipt_digest": payload["predecessor_receipt_digest"],
        "command_digest": payload["command_digest"],
        "cwd": cwd,
        "background": bool(background),
        "pty": bool(pty),
        "stdin": bool(stdin),
        "force": bool(force),
        "notify_on_complete": bool(notify_on_complete),
        "watch_patterns": copy.deepcopy(watch_patterns),
    }


def prepare_scoped_terminal_permit(
    command: str,
    env_type: str,
    execution_context: Mapping[str, Any],
    *,
    client: Optional[_WorkerPermitClient] = None,
) -> PreparedPermitTicket:
    """Validate exact Phase-A scope without consuming or executing anything."""
    selected = client or get_worker_permit_client()
    if selected is None:
        raise ScopedTerminalPermitError("missing")
    return selected.prepare(command, env_type, execution_context)


def consume_scoped_terminal_permit(
    ticket: object, execution_context: Mapping[str, Any]
) -> PermitDecision:
    """Consume through the authenticated origin privately retained by Phase A."""
    origin = _take_prepared_ticket_origin(ticket)
    if not isinstance(ticket, PreparedPermitTicket):
        raise ScopedTerminalPermitError("malformed")
    return origin.consume(ticket, execution_context)
