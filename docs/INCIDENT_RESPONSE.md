# Super Tanks — Incident Response Runbook

When something fires, follow the matching playbook below. The triggers
are already wired into the code; this document is the human side —
what William does between the alert arriving and the system being
back to a known-good state.

## Severity index

| Symptom | Detect | Playbook |
|---|---|---|
| Tripwire honeypot accessed | Telegram "TRIPWIRE UTLOYST" | [§ Tripwire](#tripwire-access) |
| Soul file SHA-256 mismatch | Telegram "SOUL INTEGRITY ALERT" + system enters SAFE_MODE | [§ Soul](#soul-integrity-mismatch) |
| DIQ contract checksum mismatch | System refuses to start; `RuntimeError` from bootstrap | [§ DIQ](#diq-contract-mismatch) |
| Sandbox-escape pattern in proposal | Telegram "Sikkerheitsstopp" | [§ Sandbox](#sandbox-escape-blocked) |
| Trust score drops to probation | Telegram "TRUST LEVEL ENDRA" | [§ Trust](#trust-level-drop) |
| Repeated PIN failures from one user | `st_auth_failures` count ≥ 5 in 15 min | [§ Auth](#repeated-pin-failures) |
| AUTONOMOUS auto-reverted to LOCKDOWN | Telegram "LOCKDOWN aktivert" | [§ Mode](#unexpected-mode-revert) |
| Many ZEF blocks in short window | Logs / Telegram "ZEF BLOCKED" | [§ ZEF](#zef-block-burst) |

For anything not listed, fall back to the [§ generic playbook](#generic-playbook).

## Tripwire access

**What just happened:** an agent (or attacker via a compromised agent)
read or wrote a memory path on the honeypot list. The system has
**already** forced LOCKDOWN, deducted −100 from the agent's trust
score, and written an audit row.

**Within 5 minutes:**

1. Open the Telegram alert. Note `agent_id` and `path`.
2. SSH to the host. Run:
   ```bash
   sqlite3 ~/super-tanks/data/memory_audit.db \
     "SELECT timestamp, agent_id, operation, path, accessible
      FROM memory_access_log
      ORDER BY id DESC LIMIT 50;"
   ```
   Confirm the tripwire access is in the last few rows.
3. Check what the agent did *immediately before* the tripwire — that's
   often the prompt-injection or compromise vector.
4. Check the trust score:
   ```bash
   sqlite3 ~/super-tanks/data/trust_score.db \
     "SELECT agent_id, score, level FROM trust_scores;"
   ```
   The hit agent should be at score 0, level `probation`. Confirm.

**Within 30 minutes:**

5. Decide: was this (a) a real attack, (b) a prompt injection that
   slipped past ZEF, (c) a buggy tool that took the agent into a
   tripwire, or (d) operator error (you renamed a path that overlaps
   the honeypot list)?
6. If (a) or (b), keep the system in LOCKDOWN. Do not restore trust
   until the input vector is identified and patched.
7. If (c), file a bug against the tool. Restore trust manually:
   ```bash
   python -c "from core.security.trust_score import set_score; \
              set_score('aeris', 70, reason='false-positive trip from tool-X bug')"
   ```
8. If (d), update the tripwire path list (`core/memory/tripwires.py`)
   and re-deploy honeypots:
   ```bash
   python -c "from core.memory.tripwires import ensure_tripwires_exist; \
              from core.memory.hierarchical_store import HierarchicalMemoryStore; \
              ensure_tripwires_exist(HierarchicalMemoryStore())"
   ```

**Post-mortem:**

9. Add a row to `docs/RISK_REGISTER.md` if the failure mode wasn't
   anticipated.
10. If ZEF should have caught the input, add the bypass to the
    redteam corpus (`tests/security/redteam_corpus/` — pending) and
    extend the regex / LLM-classifier prompt.

## Soul integrity mismatch

**What just happened:** SHA-256 of `aeris_soul.py` or `zeph_soul.py`
no longer matches `core/soul_integrity.json`. The system entered
`SOUL_SAFE_MODE` — agents respond with the canned safe-mode message
only.

**Within 5 minutes:**

1. Open the Telegram alert. Note which soul file mismatched and the
   actual vs. expected hash.
2. SSH to the host. Verify which file changed:
   ```bash
   cd ~/super-tanks
   sha256sum core/aeris_soul.py core/zeph_soul.py
   cat core/soul_integrity.json
   ```
3. If the mismatch is on a file you intentionally changed (you were
   editing the soul yourself), this is a deployment-process bug —
   you forgot to re-seal. Skip to step 8.
4. If you did not change the file, treat it as compromise.
   - Check the file's modification time and owner.
   - `git status core/aeris_soul.py core/zeph_soul.py` — is it tracked?
   - `git log -1 --format="%H %ci %s" -- core/aeris_soul.py` — when?
5. Pull a clean copy from the last known-good commit:
   ```bash
   git fetch origin
   git checkout main -- core/aeris_soul.py core/zeph_soul.py
   ```
6. Re-verify hashes. If they now match `soul_integrity.json`, exit
   safe mode by sending `/approve_soul_start` to the Aeris bot on
   Telegram.

**For deliberate edits (step 8):**

7. Re-compute and seal the new hashes:
   ```bash
   python -c "
   import hashlib, json, pathlib
   manifest = {'souls': {}}
   for name in ('aeris', 'zeph'):
       p = pathlib.Path(f'core/{name}_soul.py')
       manifest['souls'][name] = {
           'file': str(p),
           'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
       }
   pathlib.Path('core/soul_integrity.json').write_text(
       json.dumps(manifest, indent=2))
   "
   ```
8. Restart the system. SAFE_MODE will not trigger this time.

## DIQ contract mismatch

**What just happened:** `core/diq/diq_integrity.py` raised RuntimeError
during boot because a frozen DIQ file no longer matches its checksum.
The system **did not start** — there's no Telegram alert because the
process exited.

1. Read the systemd journal:
   ```bash
   journalctl -u aeris-gateway --since "10 min ago" --no-pager
   ```
2. The error names the offending file. Treat it like soul integrity
   mismatch above: investigate intent vs. tampering, restore from
   git, re-seal via:
   ```bash
   python -c "from core.diq.diq_integrity import write_checksums; write_checksums()"
   ```
3. Restart the service.

## Sandbox-escape blocked

**What just happened:** `core.zeph_quarantine` AST scanner found a
banned pattern in an Aeris-authored code proposal. The proposal is
in `failed` status; nothing was applied.

1. Open the Telegram alert. Note the proposal ID and the violating
   line(s).
2. Read the rejected proposal:
   ```bash
   cat ~/super-tanks/quarantine/incoming/<proposal_id>/files/*.py
   cat ~/super-tanks/quarantine/incoming/<proposal_id>/zeph_report.json
   ```
3. Decide: legitimate need (Aeris was solving a real task and reached
   for `subprocess`) or compromise (Aeris was prompt-injected)?
4. If legitimate: provide Aeris a sandbox-friendly alternative
   (a wrapped tool that does the operation safely) and document the
   case as "what we'd add to the allowlist instead of bypassing the
   scanner".
5. If compromise: same flow as Tripwire steps 5-10. Trust score is
   already deducted automatically by `quarantine_fail` event.

## Trust level drop

**What just happened:** an agent crossed a band boundary downward.
This is informational unless it's a drop into `probation` (-100 from
tripwire, or accumulated negative events).

1. Read the recent trust events:
   ```bash
   sqlite3 ~/super-tanks/data/trust_score.db \
     "SELECT timestamp, agent_id, event_type, score_change, score_after, details
      FROM trust_events
      ORDER BY id DESC LIMIT 20;"
   ```
2. If the drop is from `quarantine_fail`, `gogate_denied`, or
   `zef_blocked`, the system is working as intended. No action needed
   unless the rate is unusual.
3. If the drop is from `tripwire_access`, follow the Tripwire playbook.
4. If the drop is unexplained (`manual_adjust` you didn't make), check
   for a compromise.

## Repeated PIN failures

**What just happened:** a user account has hit 5 failed authentications
in 15 minutes. The account is locked out (subsequent valid PIN attempts
also return `None`) for the rest of the window.

1. Check who:
   ```bash
   sqlite3 ~/super-tanks/data/users.db \
     "SELECT user_id, COUNT(*) AS fails
      FROM st_auth_failures
      WHERE timestamp > datetime('now', '-15 minutes')
      GROUP BY user_id ORDER BY fails DESC;"
   ```
2. If it's a known user (forgot PIN): wait out the window or reset
   from a Level-5 admin session via `update_user`.
3. If it's an unknown `user_id`, you have a probe. Check Telegram
   for any unauthorised attempts; consider restricting cockpit /
   bot access at the network level.

## Unexpected mode revert

**What just happened:** the system flipped from AUTONOMOUS to LOCKDOWN
without you initiating it. The expected reasons:

- `_autonomous_timeout_at` reached → automatic timeout (8h default).
- Tripwire access → forced LOCKDOWN.
- Soul integrity failure → SAFE_MODE includes mode flip.

1. Check which:
   ```bash
   sqlite3 ~/super-tanks/data/memory_audit.db \
     "SELECT timestamp, operation, path FROM memory_access_log
      WHERE operation IN ('MODE_CHANGE', 'TRIPWIRE_ACCESS', 'search_tripwire_hit')
      ORDER BY id DESC LIMIT 10;"
   ```
2. If it's the timeout, no action needed. To re-enable AUTONOMOUS:
   ```bash
   python -c "from core.security.super_tanks_mode import set_mode, TankMode; \
              set_mode(TankMode.AUTONOMOUS, timeout_hours=12)"
   ```
3. If a tripwire fired, follow that playbook.

## ZEF block burst

**What just happened:** the prompt-injection filter blocked many
messages in a short window. Every block is logged at WARNING and
sent to the admin via Telegram (per `_notify_william`).

1. Tally the blocks:
   ```bash
   journalctl -u aeris-gateway --since "1 hour ago" \
     | grep "ZEF BLOCKED" | wc -l
   ```
2. If > 10 in an hour, treat as an attack campaign:
   - Identify the source channel (the alert text includes `Source:`).
   - Block the channel at the network level if possible.
3. Check whether any blocks are false positives (legitimate Norwegian
   that the regex misjudged). If so, file a bug against
   `core/security/zef_injection_filter.py` and add the false-positive
   string to the test suite as a regression case.

## Generic playbook

If a symptom isn't in the matrix above:

1. **Don't panic.** Most defenses fail closed — the system is in
   LOCKDOWN or SAFE_MODE, not exposed.
2. **Capture state** before anything else:
   ```bash
   cd ~/super-tanks
   git status
   git diff --stat
   sha256sum core/aeris_soul.py core/zeph_soul.py
   cat config/super_tanks_state.json
   ```
3. **Check the audit log for the last 5 minutes.**
4. **Check the trust score table.**
5. **Check `data/.identity_key` mtime** — if newer than the running
   process start time, the HMAC key was rotated and every token is
   invalidated.
6. If you can't identify the cause within 30 minutes, **stop the
   service** rather than restart it:
   ```bash
   systemctl stop aeris-gateway
   ```
   Don't restart until the root cause is identified — restarting
   may overwrite forensic state.

## When to involve the maintainer

Email security@aeris.no immediately if:

- A Critical bypass is reproducible.
- The host shows evidence of compromise (unexpected processes,
  modified system files, unexplained network connections).
- A new failure mode that isn't in this runbook fires twice within
  a week.

## Post-incident

After every Critical or High event:

1. Update `docs/RISK_REGISTER.md` with the new failure mode.
2. Add a regression test if the cause is reproducible in code.
3. Bump the version in `SYSTEM_CARD.md` if a control changed.
4. Decide whether the event warrants a write-up under the public
   advisory process described in `SECURITY.md`.

Last reviewed: 2026-05-14.
