"""Shared, lane-neutral authorization for model-created Kanban tasks."""

from __future__ import annotations

from typing import Optional

from hermes_constants import get_default_hermes_root
from hermes_cli.profiles import normalize_profile_name, read_profile_routing_meta


_DECISION_FIELDS = (
    "allowed",
    "code",
    "actor_profile",
    "actor_role",
    "target_profile",
    "target_role",
)


def authority_enforcement_enabled() -> bool:
    """Return the global task-create authority flag from the Hermes root.

    Named profile overlays do not control this cross-fleet boundary.  A missing
    file or key is OFF; a present value must be a real YAML boolean.
    """
    path = get_default_hermes_root() / "config.yaml"
    if not path.is_file():
        return False
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except Exception as exc:
        raise ValueError(f"invalid global config.yaml: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("invalid global config.yaml: expected mapping")
    kanban = data.get("kanban")
    if kanban is None:
        return False
    if not isinstance(kanban, dict):
        raise ValueError("kanban config must be a mapping")
    authority = kanban.get("authority_enforcement")
    if authority is None:
        return False
    if not isinstance(authority, dict):
        raise ValueError("kanban.authority_enforcement must be a mapping")
    if "enabled" not in authority:
        return False
    enabled = authority["enabled"]
    if not isinstance(enabled, bool):
        raise ValueError("kanban.authority_enforcement.enabled must be boolean")
    return enabled


def _decision(
    allowed: bool,
    code: str,
    actor_profile: str,
    actor_role: Optional[str],
    target_profile: str,
    target_role: Optional[str],
) -> dict:
    result = {
        "allowed": allowed,
        "code": code,
        "actor_profile": actor_profile,
        "actor_role": actor_role,
        "target_profile": target_profile,
        "target_role": target_role,
    }
    assert tuple(result) == _DECISION_FIELDS
    return result


def _read(profile: str) -> tuple[Optional[dict], Optional[str]]:
    try:
        return read_profile_routing_meta(profile), None
    except FileNotFoundError:
        return None, "unknown"
    except (TypeError, ValueError, OSError):
        return None, "invalid"


def authorize_task_create(
    actor_profile: str,
    target_profile: str,
    enabled: Optional[bool] = None,
) -> dict:
    """Return the frozen six-field decision for a prospective task create."""
    actor = normalize_profile_name(actor_profile)
    target = normalize_profile_name(target_profile)
    if enabled is None:
        enabled = authority_enforcement_enabled()
    if not isinstance(enabled, bool):
        raise ValueError("authority enabled override must be boolean")
    if not enabled:
        return _decision(True, "disabled", actor, None, target, None)

    actor_meta, actor_error = _read(actor)
    if actor_error == "unknown":
        return _decision(False, "unknown_actor", actor, None, target, None)
    if actor_error == "invalid":
        return _decision(False, "invalid_actor_metadata", actor, None, target, None)
    assert actor_meta is not None
    actor_role = actor_meta["routing_role"]
    if actor_role == "junior":
        return _decision(False, "actor_role_denied", actor, actor_role, target, None)
    if actor_role == "authority" and actor != "consigliere":
        return _decision(
            False,
            "authority_actor_not_delegated",
            actor,
            actor_role,
            target,
            None,
        )

    target_meta, target_error = _read(target)
    if target_error == "unknown":
        return _decision(False, "unknown_target", actor, actor_role, target, None)
    if target_error == "invalid":
        return _decision(
            False, "invalid_target_metadata", actor, actor_role, target, None
        )
    assert target_meta is not None
    target_role = target_meta["routing_role"]

    if actor_role == "router":
        if (
            actor == "default"
            and target == "consigliere"
            and target_role == "authority"
        ):
            return _decision(
                True, "router_to_consigliere", actor, actor_role, target, target_role
            )
        if target_role == "lead":
            return _decision(
                True, "router_to_lead", actor, actor_role, target, target_role
            )
        return _decision(
            False, "router_target_not_lead", actor, actor_role, target, target_role
        )

    if actor_role == "lead":
        if target == "consigliere" and target_role == "authority":
            return _decision(
                True, "lead_to_consigliere", actor, actor_role, target, target_role
            )
        if target in actor_meta["routing_children"]:
            return _decision(
                True, "lead_to_child", actor, actor_role, target, target_role
            )
        if target_role == "lead":
            return _decision(
                True, "lead_to_peer", actor, actor_role, target, target_role
            )
        return _decision(
            False, "lead_target_not_owned", actor, actor_role, target, target_role
        )

    if actor_role == "authority":
        if target_role == "router":
            return _decision(
                True, "authority_to_router", actor, actor_role, target, target_role
            )
        if target_role == "lead":
            return _decision(
                True, "authority_to_lead", actor, actor_role, target, target_role
            )
        return _decision(
            False,
            "authority_target_not_router_or_lead",
            actor,
            actor_role,
            target,
            target_role,
        )

    return _decision(False, "invalid_actor_metadata", actor, actor_role, target, target_role)