# Workshop

Grok Bot decides whether this is a Cursor job and what proof to bring back.
`manager` is the foreman: sequence, seams, who writes and who checks.
`builder` is the carpenter: the only agent that writes product code. Do not mix.

Pipeline: manager → mapper (if needed) → builder → debugger (if red) → verifier (always) → security-auditor (if the change can leave the machine) → small PR with proof.

- Improve KITT as voice/driving radio only. Do not rebuild it.
- Hermes (`~/.hermes`) is the local brain default.
- Device hands = **Bossy** (separate Origin repo). Do not put HID in KITT.
- Other live products exist: trading-indicators, nurse, Courier (Hermes companion), hermes-agent — map the right repo; do not assume everything is KITT.
- Never commit secrets or live tokens.
- Do not invent a new architecture when a module already exists.
- No PASS from verifier, no done.

## Product map (do not collapse into KITT)

| Product | Role | Home |
|---|---|---|
| Hermes ◆default | Local brain / router | `~/.hermes` on Mini |
| KITT | Hands-free voice radio (esp. driving) | GitHub `KharonLaQua/KITT` / Origin `1percenter/KITT` |
| Bossy | Device hands (Sightless-class); separate from KITT | Origin `1percenter/bossy` |
| Courier | Unofficial mobile companion for Hermes serve :9119 | `~/dev/courier` |
| trading-indicators | TradingView / Pine indicators | Origin `1percenter/trading-indicators` |
| nurse | Separate app | Origin `1percenter/nurse` |
| hermes / hermes-agent | Hermes harness sources | Origin `1percenter/hermes`, `hermes-agent` |

Never OpenClaw as the brain. Never invent a repo. Map first with `mapper`.

