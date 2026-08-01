from agent.prompt_builder import build_kanban_guidance


def test_router_guidance_routes_named_junior_intent_to_owner_lead():
    guidance = build_kanban_guidance("default", "router")
    assert "valid owning lead or exact `consigliere`" in guidance
    assert "Don names a junior" in guidance
    assert "carry that intent on the owning-lead card" in guidance
    assert "appropriate specialist profile" not in guidance


def test_lead_guidance_limits_creation_to_owned_child_peer_lead_or_consigliere():
    guidance = build_kanban_guidance("enforcer", "lead")
    assert "declared `routing_children` child, peer lead, or exact `consigliere`" in guidance
    assert "foreign junior" in guidance
    assert "one per specialist" not in guidance


def test_exact_consigliere_guidance_has_only_router_and_lead_targets():
    guidance = build_kanban_guidance("consigliere", "authority")
    assert "exact `default` or a valid lead" in guidance
    assert "authority_to_router" in guidance
    assert "authority_to_lead" in guidance
    assert "right specialist profile" not in guidance
    assert "one per specialist" not in guidance


def test_other_authority_guidance_denies_task_creation():
    for actor in ("kharon", "underboss"):
        guidance = build_kanban_guidance(actor, "authority")
        assert "authority_actor_not_delegated" in guidance
        assert "must not create Kanban tasks" in guidance
        assert "exact `default` or a valid lead" not in guidance


def test_junior_guidance_denies_cross_profile_creation():
    guidance = build_kanban_guidance("soldier", "junior")
    assert "no cross-profile task-create authority" in guidance
    assert "kanban_create(title=" not in guidance


def test_human_admin_guidance_is_not_worker_guidance():
    assert build_kanban_guidance(None, None) == ""
