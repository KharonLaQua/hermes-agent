---
description: Verify a change with the repo's real checks, then ship a small PR with proof. Use when the user or Bot is ready to declare done, open a PR, or hand work back.
---

# Verify and ship

## Steps

1. Read `AGENTS.md`, `package.json` / `Makefile` / `justfile`, and any `openclaw` scripts. Use the commands that already exist. Do not invent a runner.
2. Multi-step tickets start with `/manager`. Pairing on one seam may stay in `/builder`.
3. If the blast radius is unclear, `/mapper` first. Stay inside its file list.
4. Implementation belongs to `builder`. Manager dispatches it; it does not implement itself.
5. Spawn `verifier`. Require PASS plus command output (and a screenshot if UI/device-facing). Manager owns this handoff when it is running.
6. If the diff touches auth, tokens, config, Discord/gateway, IPC, HID, or network, spawn `security-auditor`. Critical findings block the PR.
7. If checks are red, spawn `debugger`. One causal fix. Re-verify.
8. Open a small PR. Title states the outcome. Body includes what changed, commands run, auditor status if invoked.
9. Do not merge unless the human or Bot explicitly asked.
