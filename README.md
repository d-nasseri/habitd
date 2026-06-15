# habitd

> **About this project:** I'm in my second year of retraining as a so-called
> "Fachinformatiker für Systemintegration" in Germany (IT specialist for systems
> integration), planning to specialize in cybersecurity afterwards.
> habitd is my first larger project — and at the same time a way for me  to practice
> Linux internals (auditd, /proc, process hierarchies), SIEM integration (Wazuh),
> and threat modeling. It's not production-ready and not intended for use on
> critical systems. Feedback, criticism, and PRs welcome — I'm still learning.

Behavioral Linux daemon. Learns a system's process habits from `auditd`
(`execve`) and flags deviations.

> **Status: functional prototype, actively evolving.**
> Full pipeline tested on a Debian 12 dev VM (Qubes test bench), 2026-06-09:
> auditd → logparse → detection → Wazuh Agent → Manager → OpenSearch → Dashboard → ntfy → mobile push.
> See [Known limitations](#known-limitations-v02) for what's rough around the edges.

## Concept

The idea: on a server with a stable, predictable set of processes, any new
`parent → child` relationship is worth a second look. That's the angle this
project explores — Living-off-the-Land (LotL) techniques, where attackers
abuse legitimate binaries (`bash`, `python`, `curl`, ...) instead of dropping
obvious malware.

Two detection layers:

- **Layer 1 — static rules:** high-confidence known-bad patterns (shell from
  `nginx`, interpreter from `sshd`, execution from `/tmp`, in-place execve on a
  long-running process). Active from event one, no learning needed.
- **Layer 2 — learned baseline:** is the `(parent_exe, exe, uid)` tuple known
  for *this* system? Unknown ⇒ anomaly. Continuous learning with admin review.

Baseline key is path-based, not process-name-based — names are trivially
spoofable (`cp /bin/bash /tmp/systemd`).

### Process identity

Beyond PID, habitd tracks `(pid, start_time)` from `/proc/<pid>/stat` to
distinguish PID recycling (benign, silent cache update) from in-place execve
(the same long-running process replacing its own image — possible process
hijacking). `/proc` is read **at event time**, not from a stale cache, to
eliminate the TTL-eviction bypass.

## Layout

```
config/config.yaml        main config (paths, learning window, alerting)
config/habitd.rules       auditd rule — execve only (V0.1 scope)
systemd/habitd.service    hardened systemd unit with StateDirectory
wazuh/
  habitd_rules.xml        custom Wazuh rules (install on manager)
  agent_localfile.xml     Wazuh agent localfile snippet (install on agent)
src/habitd/
  events.py               ExecEvent dataclass — the one normalized event shape
  config.py               YAML loader with defaults and dotted-path access
  db.py                   SQLite: baseline + alerts + review status (WAL mode)
  detection.py            Layer 1 static rules + Layer 2 baseline + Reason codes
  alert.py                severity by reason code + Wazuh JSON + async ntfy push + dedup
  daemon.py               asyncio loop + ProcessCache + signal handling
  __main__.py             CLI — see "CLI" section below
  sources/
    base.py               EventSource abstraction + factory
    logparse.py           tail audit.log (verified against Debian 12 / auditd 3.0.9)
    audisp.py             DEFERRED — will be superseded by eBPF migration
tests/
  test_detection.py       detection logic, ProcessCache, severity, Wazuh field naming
```

## Install (dev)

```bash
pip install -e ".[dev]" --break-system-packages
pytest -q
```

## Deploy

### 1. auditd rule (agent/target system)

```bash
sudo cp config/habitd.rules /etc/audit/rules.d/habitd.rules
sudo augenrules --load
sudo auditctl -l   # verify: -a always,exit -F arch=b64 -S execve -F key=habitd_exec
```

### 2. habitd daemon (agent/target system)

```bash
sudo install -d /etc/habitd
sudo cp config/config.yaml /etc/habitd/config.yaml
pip install . --break-system-packages

sudo cp systemd/habitd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now habitd
```

The systemd unit creates `/var/lib/habitd` and `/var/log/habitd` automatically
via `StateDirectory=` and `LogsDirectory=` (correct permissions, tamper-resistant
mtime for install-timestamp).

If Wazuh agent runs on the same host, grant it read access:

```bash
sudo setfacl -m u:wazuh:rx /var/log/habitd
sudo setfacl -m u:wazuh:r /var/log/habitd/alerts.json
```

### 3. Wazuh agent config (agent/target system)

Add to `/var/ossec/etc/ossec.conf` before `</ossec_config>`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/habitd/alerts.json</location>
  <label key="source">habitd</label>
</localfile>
```

```bash
sudo systemctl restart wazuh-agent
```

### 4. Wazuh manager rules

```bash
sudo cp wazuh/habitd_rules.xml /var/ossec/etc/rules/habitd_rules.xml
sudo systemctl restart wazuh-manager
```

Verify in Wazuh Dashboard: Threat Hunting → Events → `rule.groups: habitd`

### 5. ntfy push notifications (optional)

habitd sends push notifications via ntfy for `medium`, `high`, and `critical`
alerts. Configure in `config.yaml`:

```yaml
alerting:
  ntfy_url: "https://ntfy.sh"      # or self-hosted instance
  ntfy_topic: "habitd-<RANDOM>"    # see security note below
  ntfy_token: ""                   # optional Bearer token for private instances
```

**Security note on ntfy topics:** when using the public `ntfy.sh`, the topic
name is the only access control. Anyone who guesses or learns the topic name
can read all your alerts. Use a long random string, not a guessable name:

```bash
python3 -c 'import secrets; print(f"habitd-{secrets.token_hex(8)}-alerts")'
```

Install the ntfy app on Android and subscribe to the same topic.

## CLI

```bash
habitd run                                         # start daemon (normally via systemd)
habitd status                                      # tuple/alert counts + learning/alerts state
habitd baseline                                    # dump learned tuples + status
habitd review                                      # interactive pending review (y/n/m/a/q)
habitd whitelist <parent_exe> <exe> <uid|user>     # mark tuple as confirmed-legitimate
habitd mark-malicious <parent_exe> <exe> <uid|user>  # mark tuple as known IOC
habitd uid <username>                              # resolve a username to its UID
habitd log [-n N]                                  # tail alert log, pretty-printed (default: 20)
habitd flush                                       # WAL checkpoint — flush DB writes to disk
habitd learning on|off                             # toggle learning phase at runtime
habitd alerts on|off                               # toggle SIEM output at runtime
habitd ntfy on|off                                 # toggle push notifications at runtime
habitd --help                                      # full command reference
```

The `whitelist` and `mark-malicious` commands accept either a numeric UID or
a username (e.g. `www-data`, resolved via `getpwnam`).

The interactive `habitd review` flow is the recommended way to whitelist
pending tuples — it shows you the exact strings to confirm, so you don't have
to type paths or look up UIDs.

Override config path:

```bash
habitd --config /path/to/config.yaml <subcommand>
```

## Runtime toggles

```bash
habitd learning off    # freeze baseline — no new tuples accepted
habitd learning on     # resume learning
habitd alerts off      # silence SIEM output — detection still runs internally
habitd alerts on       # resume SIEM output
habitd ntfy off        # silence push notifications — SIEM output unaffected
habitd ntfy on         # resume push notifications
```

State is persisted in the SQLite `meta` table — survives daemon restarts.
A hint is shown in `habitd log` and `habitd review` when a toggle is off.

## Wazuh alert schema

One JSON object per line, appended to `alerting.json_log`:

```json
{
  "timestamp": "2026-06-09T15:45:23",
  "habitd_level": "high",
  "process_name": "bash",
  "pid": 3256,
  "parent_name": "sudo",
  "parent_pid": 3255,
  "uid": 33,
  "executable_path": "/usr/bin/bash",
  "parent_executable_path": "/usr/bin/sudo",
  "detection_layer": "layer1_static",
  "secondary_detection_layer": "",
  "reasons": ["static_rule.service_user_shell: shell spawned as service user (www-data/uid=33)"],
  "reason_codes": ["static_rule.service_user_shell"],
  "audit_id": "audit(1781012723.466:2888)",
  "tool": "habitd"
}
```

**Why `habitd_level` and `process_name` instead of `level` and `process`?**
Wazuh's OpenSearch index template maps `data.process` as an object with
sub-fields. A string value causes `mapper_parsing_exception` — events silently
dropped. `data.level` shadows `rule.level`. Renaming avoids both conflicts.

**Why `reason_codes` as a separate field?** Dashboards and SIEM filters need
to match on stable identifiers, not free-text reason messages. `reasons` is
human-readable; `reason_codes` is the structured filter target.

## Wazuh rules

| Rule ID | Level | Matches                   | Description                             |
|---------|-------|---------------------------|-----------------------------------------|
| 100500  | 3     | tool=habitd               | Base rule, any habitd event             |
| 100501  | 12    | habitd_level=high         | Layer 1 static hit or suspicious path  |
| 100502  | 15    | habitd_level=critical     | P4: blocked + killed malicious tuple   |
| 100503  | 3     | habitd_level=informational| Learning phase baseline acquisition     |
| 100504  | 7     | habitd_level=medium       | New behavior on settled system          |

## Things I broke and fixed along the way

These came up during development and live testing — keeping them here as a
record of what I learned, not as a "completed QA pass":

1. **Layer label mislabeling:** Non-anomalous Layer 1 verdict carried
   `layer="layer1_static"` even when it didn't fire. Fixed: empty layer when
   Layer 1 doesn't trigger.

2. **SIGTERM ignored on idle systems:** Signal handler set an `asyncio.Event`
   flag but the loop was parked in `asyncio.sleep()` and never checked it.
   Fixed: signal cancels the running task via `task.cancel()`.

3. **Repeated alerts for known tuples:** `pending` status was not treated as
   "seen". Fixed: `seen` now includes both `confirmed` and `pending`.

4. **Wazuh field mapping conflict:** `data.process` is an object in Wazuh's
   index template. Fixed: renamed to `process_name`, `parent_name`,
   `habitd_level`.

5. **Alert log in /home:** Wazuh logcollector couldn't traverse `/home/<user>`
   (mode 0700). Fixed: alert log moved to `/var/log/habitd/`.

6. **`tail` binary shadowed by local script:** `/home/<user>/bin/tail` was a
   Tailscale toggle script that shadowed `/usr/bin/tail`. Fixed: hardcoded
   `/usr/bin/tail` in `_cmd_log`.

## Known limitations (V0.2)

- **No argument analysis:** Args captured but deliberately unused — planned for P4.
- **No `connect()`/`ptrace()` monitoring:** Planned post-eBPF migration (P5/P6).
- **In-place execve whitelisting:** Service-manager re-execs (systemd on
  upgrade, runit/s6 wrappers) currently alert. Whitelist via config under
  `detection.inplace_execve_whitelist`.
- **Startup detection gap:** Parent-based static rules (e.g. shell-from-nginx)
  are blind until ProcessCache is seeded via `/proc`. UID-based rules
  (`service_user_shell`) still catch during this window.
- **Replay ignores runtime toggles:** `_replay_unemitted_alerts()` does not
  check `alerts_enabled` / `ntfy_enabled` — on restart after a crash, all
  pending alerts are emitted and pushed regardless of toggle state.
- **Sync I/O in async loop:** `/proc` reads and SQLite writes in `_handle()`
  block the event loop. Acceptable for normal server loads; bottleneck under
  fork bombs or mass-execve bursts (queue backpressure logging mitigates).
- **`boot_time=0` failure mode:** If `/proc/stat` is unreadable, the age
  heuristic for in-place execve fires on every process (mass false positives).
  Guard planned for next patch.

## Roadmap

Phase numbering (P3-P6) is just how I've been tracking this for myself —
think of it less as a sprint plan and more as "stuff I've done" /
"stuff I want to learn next".

### Done so far (V0.2)
- ProcessCache with `(pid, start_time)` identity
- TOCTOU mitigation for `/proc` reads
- In-place execve detection (cache path + age heuristic)
- Reason-code-based severity (decoupled from message text)
- Alert deduplication (60s suppression window, ntfy only)
- siem_emitted-replay on daemon restart (crash recovery)
- Async ntfy push (ThreadPoolExecutor, non-blocking)
- Install marker file (tamper-resistant `installed_at`)
- Backpressure logging on event queue saturation
- systemd hardening (StateDirectory, SystemCallFilter)
- CLI: `habitd uid`, `habitd ntfy on|off`, username acceptance

### Next up
- Capability-drop in systemd unit (currently runs as root — see limitations)
- journald + Forward Secure Sealing for tamper-evident alerts
- Argument logging + normalization
- Malicious tuple response engine — `habitd malicious block/allow <id>`, SIGKILL on hit
- Separate Wazuh rule (100502, level 15) for blocked+killed events

### Further out
- `execveat` syscall coverage (closes an evasion gap)
- `ptrace` monitoring — needs BaseEvent polymorphism
- `connect()` monitoring — needs a high-volume filter design first
- Package manager detection (apt/pip/npm → automatic learning phase)

### Eventually / would be cool
- eBPF integration — replaces auditd as event source
- Self-hosted ntfy + Headscale (no third-party push dependency)
- GUI

## License

GPL-3.0-or-later.
