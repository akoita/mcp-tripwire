# Runbook — pr-watchdog (local CI replacement)

> When GitHub Actions billing is exhausted (or any time you'd rather not pay
> Actions minutes for a private solo repo), `pr-watchdog` runs the same five
> gates as [`ci.yml`](../../.github/workflows/ci.yml) +
> [`security.yml`](../../.github/workflows/security.yml) locally and posts a
> verdict comment on every PR head SHA. With a Claude Code CLI on PATH it also
> runs `/code-review` on the diff and posts the model's findings inline.

## The 30-second loop

```bash
# One-time: install dev deps (uv + ruff + pytest) so make check works.
make install

# Start the daemon in the background. Polls every WATCHDOG_INTERVAL seconds
# (default 900 / 15 min). Logs to .claude/watchdog/watchdog.log.
make watchdog-start

# Watch what it's doing.
make watchdog-status
tail -f .claude/watchdog/watchdog.log

# Stop it when CI billing resumes.
make watchdog-stop
```

## What it actually does, per PR

For every open, non-draft, non-bot PR whose `headRefOid` changed since the
last seen ledger entry:

1. `git worktree add` the PR head into `.claude/watchdog/worktrees/pr-N/`.
2. Run [`scripts/ci-local.sh`](../../scripts/ci-local.sh) inside it. Captures
   the full log to `.claude/watchdog/runs/pr-N-<sha>.log`.
3. **If green** — invoke `claude -p "/code-review"` against the worktree's
   `HEAD~1..HEAD` diff. Save the output to `pr-N-<sha>.review.md`.
4. Post a comment on the PR (`gh pr comment N`) — green ✅ with the tail of
   the ci-local log + the `/code-review` verdict, or red ❌ with the failure
   detail. Token cost only paid when ci-local is green.
5. Record the SHA in `.claude/watchdog/seen-N.sha` so the next tick skips it.

A `kill -TERM` from `make watchdog-stop` cleans up gracefully — the loop is
not interrupted mid-PR.

## Why a daemon, not `/loop`

`/loop` runs inside a chat session: closing the terminal kills it. The daemon
shape (`nohup` + PID file) survives logout and pairs with `systemd --user` if
you want auto-start (recipe at the bottom). The same script runs in both
shapes — `make watchdog-start` for the simple case, `systemctl --user start
pr-watchdog` for the durable one.

## Configuration

All knobs are env vars; the daemon reads them once at start.

| Env | Default | What it does |
|---|---|---|
| `WATCHDOG_INTERVAL` | `900` | Seconds between ticks. Lower = more responsive, more API calls. |
| `WATCHDOG_REPO` | auto from `gh` | `owner/repo`. Override for cross-repo daemons. |
| `WATCHDOG_AUTOAPPROVE` | `0` | When `1`, also `gh pr review --approve` on green. Off by default — leaves the human gate intact. |
| `WATCHDOG_SKIP_BOTS` | `1` | When `1`, skip PRs authored by `*[bot]` / `app/*`. Dependabot PRs would fail the worktree checkout anyway. |
| `WATCHDOG_CLAUDE_BIN` | `claude` | Path to the Claude Code CLI. Set to a wrapper if you want a smaller model. |

## Subcommands (bypass make for fine control)

```bash
bash scripts/pr-watchdog.sh start         # nohup + PID file
bash scripts/pr-watchdog.sh stop          # SIGTERM + remove PID file
bash scripts/pr-watchdog.sh status        # running/not + seen ledger + log tail
bash scripts/pr-watchdog.sh tick          # one poll, then exit (foreground)
bash scripts/pr-watchdog.sh run           # the loop, foreground (use for systemd)
bash scripts/pr-watchdog.sh review 42     # re-review one PR now, ignoring the ledger
```

## Cost shape

| Event | Cost |
|---|---|
| Idle tick (no new SHA) | one `gh pr list` call |
| New SHA, ci-local **fails** | `make check` + ruff + scan; **no model call** |
| New SHA, ci-local **passes** | the above + one `claude -p /code-review` over the diff |

For a private solo repo with a few PRs per week, the model cost is bounded by
PR push frequency, not by tick count. The 15-min default interval is mostly
cosmetic — you can run it at 5 min without changing token spend.

## systemd user service (optional, auto-start)

Drop this at `~/.config/systemd/user/pr-watchdog.service`:

```ini
[Unit]
Description=pr-watchdog (local CI replacement for mcp-tripwire)
After=network.target

[Service]
Type=simple
WorkingDirectory=%h/dev/kaggle/5-day-ai-agents-intensive-vibe-coding-course-with-google/mcp-tripwire
ExecStart=/usr/bin/env bash scripts/pr-watchdog.sh run
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
```

Then:

```bash
systemctl --user daemon-reload
systemctl --user enable --now pr-watchdog
systemctl --user status pr-watchdog
journalctl --user -u pr-watchdog -f
```

## State directory layout

```
.claude/watchdog/
├── pid                      # daemon PID file (only present when running)
├── watchdog.log             # append-only log of every tick + post
├── seen-<N>.sha             # last reviewed head SHA per PR
├── runs/
│   ├── pr-<N>-<short>.log         # ci-local output for one tick
│   └── pr-<N>-<short>.review.md   # /code-review output for one tick
└── worktrees/
    └── pr-<N>/              # transient per-tick worktree (auto-removed)
```

All gitignored — see [.gitignore](../../.gitignore).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `make watchdog-start` says "already running" but `status` shows nothing | Stale PID file from a kill -9. | `rm .claude/watchdog/pid` then retry. |
| Worktree add fails with "already checked out" | A previous tick crashed mid-review. | `git worktree prune` then `make watchdog-tick`. |
| `/code-review` block in the comment says "claude CLI not on PATH" | Claude Code isn't installed where the daemon runs. | Install it, or set `WATCHDOG_CLAUDE_BIN=/abs/path/to/claude`. |
| Daemon posts the same SHA twice | Two daemons running. | `pgrep -af pr-watchdog`; kill all, restart one. |
| Comments fail with 403 | `gh` is signed in as a user without comment perms on the repo. | `gh auth status`; re-login with the right account. |

## Turning it off

Once GitHub Actions billing resumes:

```bash
make watchdog-stop
# systemctl --user disable --now pr-watchdog   # if using systemd
rm -rf .claude/watchdog/                       # optional — clears the ledger
```

Workflows in `.github/workflows/` are unchanged — they'll start passing again
automatically on the next push.
