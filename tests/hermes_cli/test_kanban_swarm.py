
from pathlib import Path

import pytest
import yaml

from hermes_cli import kanban_db as kb
from hermes_cli.kanban_swarm import (
    SwarmWorkerSpec,
    create_swarm,
    latest_blackboard,
    post_blackboard_update,
)


MUTATION_TABLES = (
    "tasks", "task_links", "task_events", "task_comments",
    "kanban_notify_subs", "task_runs", "task_attachments",
)


@pytest.fixture
def authority_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    (home / "config.yaml").write_text(
        "kanban:\n  authority_enforcement:\n    enabled: true\n", encoding="utf-8"
    )
    roles = {
        "developer-capo": ("lead", ["drafter", "reviewer", "writer"]),
        "soldier": ("junior", []),
        "drafter": ("junior", []),
        "reviewer": ("junior", []),
        "writer": ("junior", []),
    }
    for name, (role, children) in roles.items():
        profile = home / "profiles" / name
        profile.mkdir(parents=True)
        (profile / "profile.yaml").write_text(
            yaml.safe_dump({"routing_role": role, "routing_children": children}),
            encoding="utf-8",
        )
    return home


def _counts(conn):
    return {
        table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in MUTATION_TABLES
    }


def test_denied_swarm_is_atomic_across_all_mutation_tables(authority_home):
    conn = kb.connect(authority_home / "kanban.db")
    try:
        before = _counts(conn)
        with pytest.raises(ValueError, match="actor_role_denied"):
            create_swarm(
                conn,
                goal="Forbidden worker swarm",
                workers=[SwarmWorkerSpec(profile="developer-capo", title="Foreign", body="x")],
                verifier_assignee="reviewer",
                synthesizer_assignee="writer",
                created_by="default",
                authority_actor="soldier",
            )
        assert _counts(conn) == before
    finally:
        conn.close()


def test_permitted_lead_swarm_propagates_authority_to_every_create(authority_home):
    conn = kb.connect(authority_home / "kanban.db")
    try:
        created = create_swarm(
            conn,
            goal="Owned child swarm",
            workers=[SwarmWorkerSpec(profile="drafter", title="Build", body="x")],
            verifier_assignee="reviewer",
            synthesizer_assignee="writer",
            created_by="developer-capo",
            authority_actor="developer-capo",
        )
        assert kb.get_task(conn, created.root_id).assignee == "drafter"
        assert len(created.worker_ids) == 1
    finally:
        conn.close()


def test_swarm_idempotent_replay_precedes_authority_but_new_key_is_denied(authority_home):
    conn = kb.connect(authority_home / "kanban.db")
    kwargs = {
        "goal": "Replayable swarm",
        "workers": [SwarmWorkerSpec(profile="drafter", title="Build", body="x")],
        "verifier_assignee": "reviewer",
        "synthesizer_assignee": "writer",
        "created_by": "developer-capo",
    }
    try:
        original = create_swarm(
            conn, **kwargs, idempotency_key="existing", authority_actor="developer-capo"
        )
        before = _counts(conn)
        replay = create_swarm(
            conn, **kwargs, idempotency_key="existing", authority_actor="soldier"
        )
        assert replay == original
        assert _counts(conn) == before

        with pytest.raises(ValueError, match="actor_role_denied"):
            create_swarm(
                conn, **kwargs, idempotency_key="new", authority_actor="soldier"
            )
        assert _counts(conn) == before
    finally:
        conn.close()


def test_create_swarm_builds_parallel_workers_verifier_and_synthesizer(tmp_path):
    conn = kb.connect(tmp_path / "kanban.db")
    try:
        created = create_swarm(
            conn,
            goal="Map the target market and produce a decision memo.",
            workers=[
                SwarmWorkerSpec(profile="researcher-a", title="Market scan", body="Find competitors"),
                SwarmWorkerSpec(profile="researcher-b", title="Customer scan", body="Find customer pains"),
            ],
            verifier_assignee="reviewer",
            synthesizer_assignee="writer",
            tenant="intel",
            created_by="orchestrator",
        )

        root = kb.get_task(conn, created.root_id)
        workers = [kb.get_task(conn, tid) for tid in created.worker_ids]
        verifier = kb.get_task(conn, created.verifier_id)
        synthesizer = kb.get_task(conn, created.synthesizer_id)

        assert root.status == "done"
        assert root.assignee == "orchestrator"
        assert [task.status for task in workers] == ["ready", "ready"]
        assert [task.assignee for task in workers] == ["researcher-a", "researcher-b"]
        assert verifier.status == "todo"
        assert synthesizer.status == "todo"
        assert set(kb.parent_ids(conn, created.verifier_id)) == set(created.worker_ids)
        assert kb.parent_ids(conn, created.synthesizer_id) == [created.verifier_id]
        assert all(created.root_id in (task.body or "") for task in workers)
    finally:
        conn.close()


def test_swarm_blackboard_merges_structured_updates(tmp_path):
    conn = kb.connect(tmp_path / "kanban.db")
    try:
        created = create_swarm(
            conn,
            goal="Collect evidence.",
            workers=[SwarmWorkerSpec(profile="researcher", title="Evidence", body="Find proof")],
            verifier_assignee="reviewer",
            synthesizer_assignee="writer",
        )

        post_blackboard_update(
            conn,
            created.root_id,
            author="researcher",
            key="sources",
            value=["https://example.com/a"],
        )
        post_blackboard_update(
            conn,
            created.root_id,
            author="reviewer",
            key="risks",
            value={"missing_primary_source": True},
        )

        board = latest_blackboard(conn, created.root_id)
        assert board["sources"] == ["https://example.com/a"]
        assert board["risks"] == {"missing_primary_source": True}
        assert board["_authors"]["sources"] == "researcher"
    finally:
        conn.close()


def test_swarm_verifier_and_synthesis_are_dependency_gated(tmp_path):
    conn = kb.connect(tmp_path / "kanban.db")
    try:
        created = create_swarm(
            conn,
            goal="Research two branches then verify and synthesize.",
            workers=[
                SwarmWorkerSpec(profile="a", title="Branch A", body="A"),
                SwarmWorkerSpec(profile="b", title="Branch B", body="B"),
            ],
            verifier_assignee="reviewer",
            synthesizer_assignee="writer",
        )

        kb.complete_task(
            conn,
            created.worker_ids[0],
            summary="A done",
            metadata={"confidence": 0.8},
        )
        kb.recompute_ready(conn)
        assert kb.get_task(conn, created.verifier_id).status == "todo"
        assert kb.get_task(conn, created.synthesizer_id).status == "todo"

        kb.complete_task(conn, created.worker_ids[1], summary="B done")
        kb.recompute_ready(conn)
        assert kb.get_task(conn, created.verifier_id).status == "ready"
        assert kb.get_task(conn, created.synthesizer_id).status == "todo"

        kb.complete_task(
            conn,
            created.verifier_id,
            summary="Verified both branches",
            metadata={"gate": "pass"},
        )
        kb.recompute_ready(conn)
        assert kb.get_task(conn, created.synthesizer_id).status == "ready"
    finally:
        conn.close()
