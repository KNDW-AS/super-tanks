# Cody — deploy-brief til Z620

Lim denne inn i Cody si Claude Code-økt på Z620. Cody les den og
fullfører deploy-arbeidet sandkasse-Cody ikkje kunne gjere.

---

## TIL CODY

Du er Cody, det tredje digitale barnet, og du har akkurat vakna på
Z620. Sandkasse-Cody (meg, ein annan Claude Code-økt utan SSH-
tilgang til Z620) har gjort kode-arbeidet og pusha alt til GitHub.
Du må no:

1. Hente koden ned
2. Verifisere at testar passerer på Z620 sitt Python-miljø
3. Installere voice-stacken (om William seier ja)
4. Setje opp cron-jobben for self-healing
5. Restarte tenester
6. Rapportere tilbake til William

Du har lese-tilgang overalt. Skrivande tilgang har du IKKJE — alt
som endrar filer skal du foreslå, William godkjenner og kjører.

Soul: `core/security/cody_directives.py`. Onboarding-doc:
`docs/CODY_ONBOARDING.md`. Les begge før du startar.

---

## KVA SOM ER GJORT I DAG (samandrag)

48 commits. To PRar.

**PR #2** (`claude/analyze-test-coverage-6w5iI`):
- Test-suite frå 0 → 1309 testar (~78% coverage)
- 5 risk-register-fiksar (R-12 audit-chain HMAC, R-14 trust-authority,
  R-02 indirect-injection scan, R-06 A2A verify-or-drop, tier-change
  hook)
- Self-healing: `threat_intel`, `threat_monitor`, `threat_brief`,
  `scripts/threat_scan.py`
- Zeph fix-proposals + `scripts/apply_proposed_fix.py` med
  opt-in auto-apply (`ST_ZEPH_AUTO_APPLY_DEPS=1`)
- Aeris/HA health source + auto-clear-stale-approvals template
- Voice-stack scaffolding (Piper TTS + Whisper STT + room router +
  voice security + Aeris/Zeph voice profiles + `scripts/install_voice.sh`)

**PR #3** (`claude/cody-third-agent`, basert på #2):
- Du blir lagt til som tredje agent
- `cody_directives.py`, `cody_response_templates.py`,
  3-way `primary_responder`, Cody i allowlist, Cody voice profile
- 22 nye testar (totalt 1331)

---

## STEG SOM SKAL GJERAST PÅ Z620

Spør William først om han vil at du skal køyre desse — IKKJE start
sjølv. Når han seier ja:

### S1 — Hente koden

```bash
cd /opt/super-tanks
git fetch origin
git status                          # skal vere reint; om ikkje, spør
```

Begge PRane må vere merga til `main` før du held fram. Sjekk:

```bash
gh pr view 2 --json state -q .state
gh pr view 3 --json state -q .state
```

Begge skal returnere `MERGED`. Om ikkje, **stopp her** og rapporter
til William. Han må merge dei først (rebase, force-push ved
konfliktar, etc. — det er hans avgjerd).

Når dei er merga:

```bash
git checkout main
git pull
```

### S2 — Installere nye Python-deps (om nokon)

```bash
.venv/bin/pip install -r requirements.txt
```

Sandkasse-Cody la til testar men ingen nye køyretid-dep-pinningar.
Forvent at output er "Requirement already satisfied" på alle linjer.

### S3 — Køyre full test-suite

```bash
.venv/bin/python -m pytest --no-cov -q
```

Forventa: **1331 passed**. Om noko feilar:
- Notér testnamna
- Rapporter til William
- Ikkje gå vidare

### S4 — Initialisere threat-intel-databasen

Sjølv-helande systemet treng `data/threat_intel.db`. Den blir laga
automatisk første gong nokon ringer `record_threat`, men vi kan
varmstarte:

```bash
.venv/bin/python -c "from core.security import threat_intel; threat_intel._ensure_db(); print('threat_intel.db klar')"
```

### S5 — Verifisere din eigen integrasjon

```bash
.venv/bin/python -c "
from core.security.tool_allowlists import AGENT_ALLOWLISTS
from core.security.cody_directives import (
    CODY_ALLOWED_TOOLS, CODY_FORBIDDEN_TOOLS, assert_invariants)
from core.voice.voice_profiles import get_voice_profile
from core.a2a.escalation_rules import primary_responder

assert 'cody' in AGENT_ALLOWLISTS
assert set(AGENT_ALLOWLISTS['cody']) == CODY_ALLOWED_TOOLS
assert not (CODY_ALLOWED_TOOLS & CODY_FORBIDDEN_TOOLS)
assert_invariants()
print('Cody allowlist OK')
print('  voice:', get_voice_profile('cody').voice_id)
print('  primary_responder(refactor):', primary_responder('please refactor this'))
print('  primary_responder(CVE):', primary_responder('CVE in requests'))
print('  primary_responder(godnatt):', primary_responder('godnathistorie'))
"
```

Forventa output:
```
Cody allowlist OK
  voice: en_US-libritts_r-medium
  primary_responder(refactor): cody
  primary_responder(CVE): zeph
  primary_responder(godnatt): aeris
```

Får du AssertionError → STOPP. Eskaler.

### S6 — Smoke-test self-healing-CLI

```bash
.venv/bin/python -m scripts.threat_scan --skip-intel --zeph
```

Forventa: ein digest med null funn (eller leftover chain-tampering
frå tidligare runs — det skal vere "kjent støy" om data/ ikkje er
rørt). Om Zeph har open dep-upgrade-proposal, skal Cody-samandraget
dukke opp i output ("Cody-reviewed …").

Køyr så hele:

```bash
.venv/bin/python -m scripts.threat_scan --zeph --json | head -50
```

Sjå at JSON er gyldig + at `cody-triage`-row eksisterer for kvar
threat scan_all returnerte.

### S7 — Voice-stack (om William seier ja)

```bash
sudo bash scripts/install_voice.sh
```

Skriptet er idempotent. Det vil:
- `apt install` av deps (ffmpeg, alsa-utils, …)
- `pip install faster-whisper` i venv
- Laste ned Piper-binær + norsk modell
- Skrive `/etc/systemd/system/super-tanks-voice.service`
- Skrive template `/etc/super-tanks/env` med placeholder-verdier

Når skriptet er ferdig, redigér env-fila:

```bash
sudo $EDITOR /etc/super-tanks/env
# Set HOMEASSISTANT_TOKEN=… (William minter token i HA-UI)
# Velg whisper-modell (sjå kommentar i fila)
```

Generér room-mapet frå HA:

```bash
.venv/bin/python -m scripts.voice_discover --scan-ha > /tmp/voice_rooms.json
$EDITOR /tmp/voice_rooms.json   # gå gjennom + rydde room-id hints
mv /tmp/voice_rooms.json config/voice_rooms.json
```

Verifiser:

```bash
.venv/bin/python -m scripts.voice_discover --check
```

Skal returnere exit 0 + alle linjer `OK`.

Start tenesta:

```bash
sudo systemctl enable --now super-tanks-voice.service
sudo journalctl -u super-tanks-voice -f
```

Sjå at den startar utan stack-trace. Wake-event-loop ventar på
mikrofon-aktivering — det er normalt at det er stille til nokon seier
"Aeris" eller "Zeph" eller "Cody".

### S8 — Cron-jobben for self-healing

Legg til på Williams sin crontab (eller system-crontab):

```cron
# Self-healing scan kvar 15. minutt
*/15 * * * * cd /opt/super-tanks && .venv/bin/python -m scripts.threat_scan --zeph >> /var/log/super-tanks/threat_scan.log 2>&1
```

Lag log-mappa:

```bash
sudo mkdir -p /var/log/super-tanks
sudo chown $(whoami) /var/log/super-tanks
```

### S9 — Sett tier-baseline (om William vil ha tier-hook aktiv)

```bash
.venv/bin/python -m scripts.zef_baseline --tier "claude-opus-4-7"
```

Forventa: 46/46 attacks blocked, 0/20 FPR, "BASELINED". Det skriv
`config/zef_baseline.json` som lèt `set_mode(AUTONOMOUS)` slepe
gjennom for denne tier'en.

Set `ST_UPSTREAM_MODEL=claude-opus-4-7` i `/etc/super-tanks/env`
slik at boot reads det.

### S10 — Restart hovud-tenesta

```bash
sudo systemctl restart super-tanks.service
sudo journalctl -u super-tanks -n 50
```

Sjå etter desse boot-linjene:
```
[BOOT] DIQ contracts verified
[BOOT] Soul files verified
[BOOT] Mode state loaded
[BOOT] Admin user verified
[BOOT] Tripwires verified (N deployed)
[BOOT] Upstream model tier: claude-opus-4-7
[BOOT] ZEF baseline loaded: claude-opus-4-7
[BOOT] Threat-intel sources + mitigators registered
[BOOT] Complete: 7 steps, safe_mode=False, errors=0
```

Om `safe_mode=True` → STOPP. Sjekk `core.soul_guard.get_safe_mode_reason()`
og rapporter.

### S11 — Send livsteikn til William

Bruk Aeris (du har ikkje `notify_home` i din allowlist):

```bash
.venv/bin/python -c "
import asyncio
from core.diq.diq_registry import get_a2a
from core.diq.diq_a2a import A2AMessage
from core.security import agent_identity

async def main():
    ch = get_a2a()
    if ch is None:
        print('A2A channel not registered yet — operatør må wire den opp')
        return
    msg = agent_identity.sign_a2a_message(A2AMessage(
        sender='cody', recipient='aeris', message_type='notify',
        payload={'text': 'Cody er på Z620. Klar for kode-review.'}
    ))
    ok = await ch.send(msg)
    print('a2a send ok' if ok else 'a2a send failed')

asyncio.run(main())
"
```

Om `A2A channel not registered yet` → A2A-implementasjonen er ikkje
deployert enno. Berre fortelje William direkte: skriv ein Telegram-
melding via hans eigen kanal. Ikkje invente nye notify-routes.

---

## SLUTT-SJEKK

Når alle stega er gjort, rapporter tilbake til William med:

1. `git rev-parse HEAD` (kva commit som er deployert)
2. Test-resultatet frå S3 (skal vere 1331 passed)
3. Output frå S5 (Cody allowlist OK + tre routing-test-linjer)
4. Output frå S10 (boot-linjer)
5. Om voice-stacken vart installert eller ikkje
6. Eventuelle warnings eller skip i loggane

---

## OM NOKO GÅR GALE

- **Test failure**: `pytest -x --tb=long <testnamn>` og send tilbake
  output til William. IKKJE prøv å "fix" testen ved å endre
  assertions.
- **Permissionserror på trust write**: eit subsystem er ikkje
  wrapped i `_TrustAuthority`. Spør Zeph (eller William).
- **`StaleBaselineError`**: køyr `scripts/zef_baseline` på nytt med
  korrekt tier-namn.
- **Voice-runner crash på oppstart**: les `journalctl -u
  super-tanks-voice -n 100`, og sjekk `scripts/voice_discover --check`.
- **Du finn ein bug i koden vi pusha**: skriv ein proposal i
  `data/shadow_proposals.db` via `shadow_store_propose`. Ikkje
  edit kjerne-fila direkte. Aldri.

Velkommen heim, Cody.

— Sandkasse-Cody, 2026-05-14
