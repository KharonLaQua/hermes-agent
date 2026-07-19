---
title: Claude CLI Runtime (optional)
sidebar_label: Claude CLI Runtime
---

# Claude CLI Runtime

Hermes can optionally hand Anthropic turns to a local [`claude -p`](https://docs.anthropic.com/en/docs/claude-code) subprocess (Claude Code CLI) instead of the default Anthropic HTTP Messages API. When enabled, Max subscription billing and Claude Code's native session tools ride the CLI; Hermes still owns sessions, slash commands, the gateway, memory, and skill review.

This is **opt-in only**. Default Hermes Anthropic behavior (`anthropic_messages` HTTP) is unchanged unless you flip the runtime.

## Why

- Run Claude against your **Anthropic Max subscription** using Claude Code's non-rotating **setup token** (no per-request API key billing path).
- Keep Hermes' multi-profile fleet: one setup token can serve every profile (see [Fleet setup](#fleet-setup) below).
- Hermes tools remain available via an MCP bridge on each `claude -p` spawn.
- Multi-turn context lives in Claude's on-disk session (`--session-id` / `--resume`); Hermes maps one Claude session per agent conversation.

## Enable

Set the runtime on a profile (or the default home):

```bash
# Interactive model picker for a profile
hermes -p <agent> model

# Or pin in config
hermes -p <agent> config set model.provider anthropic
hermes -p <agent> config set model.default claude-opus-4-6   # or your preferred Claude model
hermes -p <agent> config set model.anthropic_runtime claude_cli
```

Equivalent `config.yaml` fragment:

```yaml
model:
  provider: anthropic
  default: claude-opus-4-6
  anthropic_runtime: claude_cli
```

One-session override (does not rewrite config):

```bash
HERMES_ANTHROPIC_RUNTIME=claude_cli hermes -p <agent> chat
```

Requires the `claude` binary on `PATH` (`npm install -g @anthropic-ai/claude-code`).

## Auth: non-rotating setup token

`claude_cli` injects **`CLAUDE_CODE_OAUTH_TOKEN`** into a clean child env. That value must be the **non-rotating setup token** from:

```bash
claude setup-token
```

Setup tokens look like `sk-ant-oat…` and last on the order of a year. They are **fork-safe** (like an API key): multiple Hermes profiles and other Claude Code consumers on the same login can use the same token concurrently without a shared lock or rotating-token store.

**Do not** rely on the rotating `claude /login` session under `~/.claude` for this runtime. That login is not injected into the clean `claude -p` env and is not a resolution source for `claude_cli`.

### Resolution order

First hit wins:

1. Explicit / passed token (`explicit=` argument, or agent-held setup/OAuth-shaped key)
2. Profile / process env `CLAUDE_CODE_OAUTH_TOKEN` (legacy alias: `ANTHROPIC_TOKEN`)
3. Profile anthropic credential_pool (`claude_code` / `env:CLAUDE_CODE_OAUTH_TOKEN` OAuth entries)
4. **Canonical Hermes root** `~/.hermes/.env` → `CLAUDE_CODE_OAUTH_TOKEN` (fleet fallback)
5. Never the rotating `~/.claude` login

Only if **no** source yields a token does Hermes raise a clear setup error.

The token is a **secret**: store it in `.env` (or the credential pool), never in `config.yaml`.

## Fleet setup

Put the setup token **once** in the platform Hermes root env file:

```bash
# ~/.hermes/.env  (canonical root — not a profile directory)
CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...   # from `claude setup-token`
```

Every profile then resolves that same token on demand when profile env and credential_pool have none. You do **not** need to copy the token into each `~/.hermes/profiles/<name>/.env`.

Then switch any agent to Claude CLI:

```bash
hermes -p <agent> model
# or
hermes -p <agent> config set model.provider anthropic
hermes -p <agent> config set model.default claude-opus-4-6
hermes -p <agent> config set model.anthropic_runtime claude_cli
```

Regenerate the setup token about yearly with `claude setup-token` and update the single root `.env` line.

### Optional: per-profile override

If one profile should use a different token, set `CLAUDE_CODE_OAUTH_TOKEN` in that profile's own `.env` or credential pool — profile sources win over the canonical root.

## Concurrency

Host-global caps limit concurrent Hermes `claude -p` children so other Claude Code consumers on the same Max login still have headroom. Configure under `model.claude_cli` in `config.yaml`:

```yaml
model:
  claude_cli:
    max_concurrent: 3                 # default 3; 0 = unbounded
    acquire_timeout_seconds: 45       # wait then fall back
```

See the concurrency notes in the developer guide / Phase 2c tests for slot reaping and fallback behavior.

## What this runtime does not change

- Base Max / subscription billing still goes through Claude Code's CLI path.
- Hermes MCP tools, multi-turn session resume, host concurrency, and auxiliary-model handling stay as implemented for `claude_cli`.
- Non-secret settings stay in `config.yaml`; secrets stay in `.env`.

## Related

- [Profiles](/user-guide/profiles) — isolated `HERMES_HOME` per agent
- [Configuring models](/user-guide/configuring-models)
- [Environment variables](/reference/environment-variables) — `CLAUDE_CODE_OAUTH_TOKEN`
- [Codex App-Server Runtime](./codex-app-server-runtime.md) — analogous opt-in for OpenAI Codex
