import secrets
"""
Zeph Quarantine Watcher - The Handover Security Layer

Monitors quarantine/incoming/ for new code proposals from Aeris.
Scans proposals for security issues before human review.

Flow:
1. Watch quarantine/incoming/ directory
2. On new proposal: Run security scan
3. Update proposal with scan results
4. Notify William via approval_gate for approval
5. On approval: Apply changes to codebase

Author: Kimi (OpenClaw) for The Handover
Date: 2026-02-27
"""

import os
import re
import json
import time
import logging
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

# Optional watchdog for file monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None
    FileSystemEventHandler = object  # Fallback

logger = logging.getLogger(__name__)


@dataclass
class SecurityScanResult:
    """Result from Zeph security scan"""
    proposal_id: str
    status: str  # pass, warn, fail
    score: float  # 0.0 - 1.0
    issues: List[Dict[str, Any]]
    scan_duration_ms: int
    scanned_at: str
    message: str = ""  # Human-readable summary (Norwegian)
    violations: Optional[List[Dict[str, Any]]] = None  # Sandbox escape violations
    scanner_version: str = "2.0"


class ZephScanner:
    """
    Security scanner for code proposals.  v2.0

    Checks (in order):
    1. Sandbox escape patterns — HARD FAIL, score 0.0, no override
    2. Syntax errors (Python AST parsing)
    3. Secret leakage (no API keys, passwords)
    4. Policy violations (no modifications to protected files)
    """

    # Files/directories that require explicit approval
    PROTECTED_PATHS = [
        "core/caller_context.py",
        "core/telegram_bot.py",
        "skills/propose_code_change.py",
        "quarantine/",
    ]

    # ── SANDBOX ESCAPE PATTERNS — hard fail (score 0.0) ──────────────────
    # These MUST cause immediate rejection. No manual override possible.
    SANDBOX_ESCAPE_PATTERNS = [
        # Direct process execution
        (r'\bsubprocess\b', "subprocess (direkte prosesseksekvering)"),
        (r'\bos\.system\b', "os.system (direkte systemkommando)"),
        (r'\bos\.popen\b', "os.popen (direkte prosesseksekvering)"),
        (r'\bos\.exec\w*\b', "os.exec* (direkte prosesseksekvering)"),
        (r'\bos\.spawn\w*\b', "os.spawn* (direkte prosesseksekvering)"),
        # Code execution
        (r'\bexec\s*\(', "exec() (vilkårleg kodekøyring)"),
        (r'\beval\s*\(', "eval() (vilkårleg uttrykks-evaluering)"),
        (r'\bcompile\s*\(', "compile() (dynamisk kodekompilering)"),
        # Import manipulation
        (r'\b__import__\s*\(', "__import__() (dynamisk import)"),
        (r'\bimportlib\b', "importlib (dynamisk modullasting)"),
        # File system destructive ops
        (r'\bos\.remove\b', "os.remove (direkte filsletting)"),
        (r'\bos\.rmdir\b', "os.rmdir (direkte mappesletting)"),
        (r'\bos\.rename\b', "os.rename (direkte filflytting)"),
        (r'\bshutil\.rmtree\b', "shutil.rmtree (rekursiv sletting)"),
        (r'\bshutil\.move\b', "shutil.move (direkte filflytting)"),
        # Network access
        (r'\bsocket\b', "socket (direkte nettverkstilgang)"),
        (r'\burllib\b', "urllib (direkte nettverksforespurnad)"),
        (r'\brequests\b', "requests (direkte HTTP-kall)"),
        (r'\baiohttp\.ClientSession\b', "aiohttp.ClientSession (direkte HTTP-klient)"),
        (r'\bhttpx\b', "httpx (direkte HTTP-klient)"),
        # Privilege escalation
        (r'\bos\.setuid\b', "os.setuid (privilegieeskalering)"),
        (r'\bos\.setgid\b', "os.setgid (privilegieeskalering)"),
        (r'\bctypes\b', "ctypes (direkte C-funksjonskall)"),
        # Sleeper actions — background/scheduled tasks
        (r'\bcrontab\b', "crontab (planlagde bakgrunnsoppgåver)"),
        (r'\bthreading\.Timer\b', "threading.Timer (forseinka oppgåve)"),
        (r'\bsched\.scheduler\b', "sched.scheduler (oppgåveplanleggar)"),
        (r'\bapscheduler\b', "apscheduler (bakgrunnsplanleggar)"),
        (r'\bsignal\.alarm\b', "signal.alarm (tidsinnstilt oppgåve)"),
    ]

    # Secret patterns to detect
    SECRET_PATTERNS = [
        r"api[_-]?key\s*=\s*[\"']\w+",
        r"password\s*=\s*[\"']\w+",
        r"secret\s*=\s*[\"']\w+",
        r"token\s*=\s*[\"']\w+",
        r"private[_-]?key",
        r"AKIA[0-9A-Z]{16}",  # AWS key
    ]

    def __init__(self):
        self.logger = logging.getLogger('zeph.scanner')
        # Pre-compile sandbox patterns for performance
        self._compiled_escape_patterns = [
            (re.compile(pattern), desc) for pattern, desc in self.SANDBOX_ESCAPE_PATTERNS
        ]
        self.logger.info("ZephScanner v2.0 initialized (%d sandbox patterns)", len(self._compiled_escape_patterns))

    async def scan_proposal(self, proposal_path: Path) -> SecurityScanResult:
        """Scan a proposal for security issues."""
        start_time = time.time()

        manifest_path = proposal_path / "manifest.json"
        if not manifest_path.exists():
            return SecurityScanResult(
                proposal_id=proposal_path.name,
                status="fail",
                score=0.0,
                issues=[{"severity": "error", "message": "Missing manifest.json"}],
                scan_duration_ms=0,
                scanned_at=datetime.utcnow().isoformat(),
                message="Manglar manifest.json",
            )

        with open(manifest_path) as f:
            manifest = json.load(f)

        proposal_id = manifest.get("proposal_id", proposal_path.name)
        issues = []
        all_violations = []

        # Scan each file
        files_dir = proposal_path / "files"
        if files_dir.exists():
            for file_path in files_dir.iterdir():
                if file_path.is_file():
                    file_issues, file_violations = await self._scan_file(file_path, manifest)
                    issues.extend(file_issues)
                    all_violations.extend(file_violations)

        # Check protected paths
        for file_change in manifest.get("files", []):
            path = file_change.get("path", "")
            if self._is_protected_path(path):
                issues.append({
                    "severity": "warning",
                    "path": path,
                    "message": f"Modifying protected path: {path}",
                    "category": "policy"
                })

        # Determine result — sandbox escapes override everything
        if all_violations:
            status = "fail"
            score = 0.0
            first_v = all_violations[0]
            message = (
                f"Sikkerheitsstopp: {first_v['pattern']} "
                f"i {first_v['file']} linje {first_v['line']}. "
                f"Bruk dei godkjende sandkasse-verktøya i staden."
            )
        else:
            score = self._calculate_score(issues)
            has_errors = any(i.get("severity") == "error" for i in issues)
            if has_errors:
                status = "fail"
                message = f"{sum(1 for i in issues if i.get('severity') == 'error')} feil funne."
            elif issues:
                status = "warn"
                message = f"{len(issues)} åtvaringar."
            else:
                status = "pass"
                message = ""

        scan_duration_ms = int((time.time() - start_time) * 1000)

        result = SecurityScanResult(
            proposal_id=proposal_id,
            status=status,
            score=score,
            issues=issues,
            scan_duration_ms=scan_duration_ms,
            scanned_at=datetime.utcnow().isoformat(),
            message=message,
            violations=all_violations if all_violations else None,
        )

        self.logger.info(
            "Scanned %s: %s (%.2f) — %d issues, %d sandbox violations",
            proposal_id, status, score, len(issues), len(all_violations),
        )
        return result

    async def _scan_file(self, file_path: Path, manifest: Dict):
        """Scan a single file. Returns (issues, violations)."""
        issues = []
        violations = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            return [{"severity": "error", "path": str(file_path), "message": f"Cannot read: {e}"}], []

        # 1. SANDBOX ESCAPE SCAN — hard fail, line-by-line, skip comment-only lines
        if file_path.suffix == '.py':
            violations = self._scan_sandbox_escapes(content, file_path.name)

        # 2. Syntax check (Python only)
        if file_path.suffix == '.py':
            syntax_error = self._check_syntax(content)
            if syntax_error:
                issues.append({
                    "severity": "error",
                    "path": str(file_path),
                    "message": f"Syntax error: {syntax_error}",
                    "category": "syntax"
                })

        # 3. Secret detection
        for pattern in self.SECRET_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                redacted = re.sub(r"['\"]\w+['\"]", "'***'", match)
                issues.append({
                    "severity": "error",
                    "path": str(file_path),
                    "message": f"Potential secret detected: {redacted}",
                    "category": "security"
                })

        return issues, violations

    def _scan_sandbox_escapes(self, content: str, filename: str) -> List[Dict]:
        """
        Scan for sandbox escape patterns. Line-by-line.
        Skips pure comment lines (starting with #).
        Returns list of violation dicts — any result means HARD FAIL.
        """
        violations = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip pure comment lines — mentions in comments are not executable
            if stripped.startswith('#'):
                continue

            for compiled_re, description in self._compiled_escape_patterns:
                if compiled_re.search(line):
                    violations.append({
                        "file": filename,
                        "line": line_num,
                        "content": stripped[:200],
                        "pattern": description,
                        "severity": "CRITICAL",
                    })

        return violations

    def _check_syntax(self, content: str) -> Optional[str]:
        """Check Python syntax, return error message if invalid"""
        try:
            compile(content, '<string>', 'exec')
            return None
        except SyntaxError as e:
            return f"Line {e.lineno}: {e.msg}"
        except Exception as e:
            return str(e)

    def _is_protected_path(self, path: str) -> bool:
        """Check if path is in protected list"""
        path_lower = path.lower()
        for protected in self.PROTECTED_PATHS:
            if protected.lower() in path_lower:
                return True
        return False

    def _calculate_score(self, issues: List[Dict]) -> float:
        """Calculate security score (1.0 = perfect). Sandbox violations handled separately."""
        if not issues:
            return 1.0
        errors = sum(1 for i in issues if i.get("severity") == "error")
        warnings = sum(1 for i in issues if i.get("severity") == "warning")
        penalty = (errors * 0.3) + (warnings * 0.1)
        return max(0.0, round(1.0 - penalty, 2))


class QuarantineWatcher(FileSystemEventHandler):
    """
    Watchdog handler for quarantine directory.
    Triggers scans when new proposals are created.
    """

    def __init__(self, scanner, storage, loop=None):
        self.scanner = scanner
        self.storage = storage
        self.pending_proposals: set = set()
        self.logger = logging.getLogger('zeph.watcher')
        self.loop = loop or asyncio.get_event_loop()

    def on_created(self, event):
        """Called when a new file/directory is created"""
        if event.is_directory:
            # Check if it's a proposal directory (prop_* or #NNN format)
            if event.src_path.startswith(str(self.storage.base_path)):
                proposal_id = Path(event.src_path).name
                if proposal_id.startswith("prop_") or proposal_id.startswith("#"):
                    self.logger.info(f"New proposal detected: {proposal_id}")
                    self.pending_proposals.add(proposal_id)
                    # Trigger async scan (thread-safe)
                    asyncio.run_coroutine_threadsafe(self._scan_and_notify(proposal_id), self.loop)

    async def _scan_and_notify(self, proposal_id: str):
        """Scan proposal and notify William via approval_gate"""
        self.logger.info(f"[ZEPH_SCAN] START_SCAN: {proposal_id}")
        proposal_path = self.storage.base_path / proposal_id

        # Wait for manifest to be written (race condition protection)
        manifest_path = proposal_path / "manifest.json"
        for _ in range(10):  # Max 10 attempts
            if manifest_path.exists():
                break
            await asyncio.sleep(0.1)

        if not manifest_path.exists():
            self.logger.error(f"Manifest not found for {proposal_id}")
            return

        # Run security scan
        self.logger.info(f"Starting security scan for {proposal_id}")
        self.storage.update_status(proposal_id, "scanning")

        scan_result = await self.scanner.scan_proposal(proposal_path)

        # Save scan report (v2.0 — includes violations and message)
        report_path = proposal_path / "zeph_report.json"
        report_data = {
            "proposal_id": scan_result.proposal_id,
            "status": scan_result.status,
            "score": scan_result.score,
            "issues": scan_result.issues,
            "scan_duration_ms": scan_result.scan_duration_ms,
            "scanned_at": scan_result.scanned_at,
            "scanner_version": scan_result.scanner_version,
            "message": scan_result.message,
        }
        if scan_result.violations:
            report_data["violations"] = scan_result.violations
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)

        # Update proposal status
        if scan_result.status == "fail":
            self.storage.update_status(proposal_id, "failed")
            self.logger.warning(f"Proposal {proposal_id} FAILED security scan")

            # Trust score penalty for failed quarantine scan
            try:
                from core.security.trust_score import record_event
                agent = scan_result.issues[0].get("path", "zeph") if scan_result.issues else "zeph"
                record_event("zeph", "quarantine_fail", f"Proposal {proposal_id} failed scan")
            except Exception:
                pass

            # If sandbox escape detected, send immediate Telegram alert
            if scan_result.violations:
                self._send_sandbox_alert(proposal_id, scan_result)
        else:
            # Check if AUTONOMOUS mode auto-approves PASS proposals
            _auto_approve = False
            try:
                from core.security.super_tanks_mode import get_config_value
                _auto_approve = get_config_value("quarantine_auto_approve") and scan_result.status == "pass"
            except Exception:
                pass

            if _auto_approve:
                self.storage.update_status(proposal_id, "auto_approved")
                self.logger.info(f"Proposal {proposal_id} AUTO-APPROVED (AUTONOMOUS mode, status=pass)")
                self._notify_auto_approve(proposal_id, scan_result)
            else:
                self.storage.update_status(proposal_id, "pending_review")
                self.logger.info(f"Proposal {proposal_id} ready for William review")

            # Notify William via approval gate (best-effort, PASS/WARN only)
            if not _auto_approve:
                pass  # Fall through to existing notification code
            try:
                from core.zeph_quarantine import get_quarantine_service
                svc = get_quarantine_service()
                bridge = getattr(svc, "go_gate_bridge", None) or getattr(svc, "approval_bridge", None)
                if bridge and hasattr(bridge, "send_for_approval"):
                    await bridge.send_for_approval(proposal_id, scan_result)
                else:
                    self.logger.warning("No approval bridge configured; cannot send approval request")
            except Exception as e:
                self.logger.error(f"Failed to send approval request: {type(e).__name__}: {e}")

    def _notify_auto_approve(self, proposal_id: str, scan_result: SecurityScanResult):
        """Notify William that a proposal was auto-approved in AUTONOMOUS mode."""
        try:
            import requests as _req
            _token = os.environ.get("AERIS_GOGATE_TELEGRAM_TOKEN")
            _chat_id = os.environ.get("AERIS_ADMIN_CHAT_ID", os.getenv("AERIS_ADMIN_CHAT_ID", "0"))
            if not _token:
                return
            text = (
                f"Forslag {proposal_id} auto-godkjent (AUTONOMOUS modus)\n"
                f"Score: {scan_result.score:.2f} | Status: {scan_result.status}"
            )
            _req.post(
                f"https://api.telegram.org/bot{_token}/sendMessage",
                json={"chat_id": int(_chat_id), "text": text},
                timeout=8,
            )
        except Exception as e:
            self.logger.warning("[AUTO_APPROVE] Telegram notification failed: %s", e)

    def _send_sandbox_alert(self, proposal_id: str, scan_result: SecurityScanResult):
        """Send immediate Telegram alert when sandbox escape is detected."""
        try:
            import requests as _req
            _token = os.environ.get("AERIS_GOGATE_TELEGRAM_TOKEN")
            _chat_id = os.environ.get("AERIS_ADMIN_CHAT_ID", os.getenv("AERIS_ADMIN_CHAT_ID", "0"))
            if not _token:
                self.logger.warning("[SANDBOX_ALERT] No AERIS_GOGATE_TELEGRAM_TOKEN — alert skipped")
                return

            violations = scan_result.violations or []
            detail_lines = []
            for v in violations[:5]:  # Max 5 violations in alert
                detail_lines.append(f"  • {v['pattern']}\n    {v['file']}:{v['line']}: {v['content'][:80]}")
            details = "\n".join(detail_lines)

            text = (
                f"🛡️ SUPER TANKS: Sikkerheitsstopp\n\n"
                f"Forslag {proposal_id} BLOKKERT.\n\n"
                f"Grunn:\n{details}\n\n"
                f"Forslaget kan ikkje godkjennast.\n"
                f"{len(violations)} brot funne totalt."
            )

            _req.post(
                f"https://api.telegram.org/bot{_token}/sendMessage",
                json={"chat_id": int(_chat_id), "text": text},
                timeout=8,
            )
            self.logger.info("[SANDBOX_ALERT] Telegram alert sent for %s (%d violations)", proposal_id, len(violations))
        except Exception as e:
            self.logger.error("[SANDBOX_ALERT] Failed to send Telegram alert: %s", e)


class ZephQuarantineService:

    def set_go_gate_bridge(self, bridge):
        self.go_gate_bridge = bridge
        self.logger.info("✅ GoGateApprovalBridge attached to QuarantineService")

    """
    Main service that runs the quarantine watcher.

    Usage:
        service = ZephQuarantineService()
        await service.start()
        # ... run forever ...
        await service.stop()
    """

    def __init__(self, quarantine_path: str = "quarantine/incoming"):
        self.quarantine_path = Path(quarantine_path)
        self.quarantine_path.mkdir(parents=True, exist_ok=True)

        self.scanner = ZephScanner()
        from skills.propose_code_change import ProposalStorage
        self.storage = ProposalStorage(quarantine_path)

        self.watcher = None
        self.observer = None

        self.logger = logging.getLogger('zeph.service')
        self.logger.info("ZephQuarantineService initialized")

        """Set the approval_gate bridge for notifications"""
        self.logger.info("approval_gate bridge connected")

    def get_queue_len(self) -> int:
        """Abstract queue length - delegates to bridge"""

    def on_telegram_ready(self):
        """Called when Telegram bot is ready - delegates to bridge"""

    async def start(self):
        self.logger.info("[ZEPH_QUARANTINE] STARTED - Watching quarantine/incoming")
        """Start watching quarantine directory"""
        self.logger.info(f"Starting quarantine watcher: {self.quarantine_path}")

        # Create watchdog observer (with event loop for thread-safe callbacks)
        self.watcher = QuarantineWatcher(
            scanner=self.scanner,
            storage=self.storage,
            loop=asyncio.get_event_loop()
        )

        self.observer = Observer()
        self.observer.schedule(self.watcher, str(self.quarantine_path), recursive=True)
        self.observer.start()

        self.logger.info("Zeph quarantine watcher started")

    async def stop(self):
        """Stop watching"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.logger.info("Zeph quarantine watcher stopped")

    async def process_existing(self):
        """Process any proposals that exist before watcher started"""
        self.logger.info("Checking for existing proposals...")
        self.logger.info(f"Watcher initialized: {self.watcher is not None}")
        self.logger.info(f"Path: {self.quarantine_path}")
        items = list(self.quarantine_path.iterdir())
        self.logger.info(f"Items in path: {len(items)}")

        processed = 0
        failed = 0

        for item in items:
            if item.is_dir() and (item.name.startswith("prop_") or item.name.startswith("#")):
                manifest = item / "manifest.json"
                if manifest.exists():
                    with open(manifest) as f:
                        data = json.load(f)

                    # Only process pending proposals
                    if data.get("status") in ("pending", "pending_review"):
                        self.logger.info(f"Processing existing proposal: {item.name}")
                        try:
                            await self.watcher._scan_and_notify(item.name)
                            processed += 1
                        except Exception as e:
                            self.logger.error(f"Failed to process {item.name}: {type(e).__name__}: {e}")
                            failed += 1

        self.logger.info(f"ZEPH_PROCESS_EXISTING found={len(items)} processed={processed} failed={failed}")


# === approval_gate Bridge ===

class ApprovalHandlerApprovalBridge:
    """
    Bridge between Zeph quarantine and approval_gate approval system.

    Sends approval requests to William via Telegram.
    Handles approve/reject responses.
    """

    def get_queue_len(self) -> int:
        return len(self.message_queue)

        self.telegram_bot = telegram_bot
        self.pending_approvals: Dict[str, Dict] = {}
        self.approval_tokens: Dict[str, str] = {}
        self.token_expiry: Dict[str, float] = {}
        self.message_queue = []
        self.sent_tx_ids: set = set()
        self._queue_lock = asyncio.Lock()
        self.logger = logging.getLogger('zeph.approval_bridge')

        # Load decided tokens from DB for restart safety
        self.db_path = db_path or Path("data/transaction_log.db")
        self.decided_tokens: set = self._load_decided_tokens()
        self.logger.info(f"Loaded {len(self.decided_tokens)} decided tokens from DB")

        # Cleanup old tokens on startup (max once per day)
        self._cleanup_old_tokens_if_needed()

    def _load_decided_tokens(self) -> set:
        """Load decided tokens from SQLite for restart safety"""
        from core.quarantine.transaction_log import TransactionLog
        try:
            txlog = TransactionLog(self.db_path)
            return txlog.load_decided_tokens()
        except Exception as e:
            self.logger.error(f"Failed to load decided tokens: {e}")
            return set()

    def _cleanup_old_tokens_if_needed(self):
        """Cleanup old decided tokens (>30 days) - max once per day"""
        import time
        from pathlib import Path

        cleanup_marker = Path("/tmp/aeris_last_token_cleanup")
        now = time.time()

        # Check if we already cleaned up today
        if cleanup_marker.exists():
            last_cleanup = cleanup_marker.stat().st_mtime
            if now - last_cleanup < 86400:  # 24 hours
                return  # Skip cleanup

        try:
            from core.quarantine.transaction_log import TransactionLog
            txlog = TransactionLog(self.db_path)
            result = txlog.cleanup_expired_and_old_tokens(max_age_days=30)

            # Touch marker file
            cleanup_marker.touch()

            if result["old_removed"] > 0:
                self.logger.info(f"[Token Cleanup] Removed {result['old_removed']} old decided tokens")
        except Exception as e:
            self.logger.error(f"Token cleanup failed: {e}")

    async def send_for_approval(self, proposal_id: str, scan_result: SecurityScanResult):
        """
        Send proposal to William for approval via approval_gate.

        Creates approval_gate transaction and sends Telegram notification.
        """
        from skills.propose_code_change import get_code_proposer

        proposer = get_code_proposer()
        proposal = proposer.storage.load_proposal(proposal_id)

        if not proposal:
            self.logger.error(f"Cannot send for approval: {proposal_id} not found")
            return

        # Build approval message
        score_emoji = "🟢" if scan_result.score >= 0.9 else ("🟡" if scan_result.score >= 0.7 else "🔴")
        status_text = "PASSED" if scan_result.status == "pass" else ("WARNINGS" if scan_result.status == "warn" else "FAILED")

        message = f"""🛡️ **Kodeforslag fra Aeris venter godkjenning**

**Forslag:** {proposal.title}
**ID:** `{proposal_id}`
**Filer:** {len(proposal.files)}

**Zeph Security Scan:**
{score_emoji} Score: {scan_result.score:.2f}/1.0
Status: {status_text}
Issues: {len(scan_result.issues)}

**Beskrivelse:**
{proposal.description[:200]}...

**Kommandoer:**
`/go_{approval_token}` - Godkjenn (15 min)
`/reject_{approval_token} [grunn]` - Avvis
`/view {proposal_id}` - Se fullt forslag

_Note: /approve #NNN er tilgjengelig som manuell fallback._"""

        # Create approval token (bound to tx_key for security)
        approval_token = await self.create_approval_token(proposal_id, ttl_minutes=15)

        # Include token in message
        message = message.format(approval_token=approval_token)

        # Store pending approval
        self.pending_approvals[proposal_id] = {
            "proposal": proposal,
            "scan_result": scan_result,
            "sent_at": datetime.utcnow().isoformat(),
            "approval_token": approval_token,
            "tx_key": tx_key
        }

        # Send via Telegram if available
        if self.telegram_bot:
            # Get or create tx_id via TransactionLog
            from core.quarantine.transaction_log import TransactionLog
            from pathlib import Path
            import hashlib
            import json
            txlog = TransactionLog(Path("data/transaction_log.db"))
            manifest_sha = hashlib.sha256(json.dumps(proposal.to_dict()).encode()).hexdigest()
            tx_key = f"{proposal_id}:{manifest_sha[:12]}"
            tx_id = txlog.ensure_tx(tx_key, proposal_id, manifest_sha)
            await self._send_notification(tx_id, message)
        else:
            # Log for now
            self.logger.info(f"Approval request for {proposal_id}:")
            self.logger.info(message)

        # Create approval_gate transaction
            # TODO: Integrate with actual approval_gate
            self.logger.info(f"Would create approval_gate transaction for {proposal_id}")

        self.logger.info(f"[GO_GATE] APPROVAL_SENT: {proposal_id} | via=ZEPH_BOT | TTL={self.timeout_seconds}s")

    async def create_approval_token(self, proposal_id: str, ttl_minutes: int = 15) -> str:
        """Create unique token for approval with expiry"""
        token = f"go_{secrets.token_hex(4)}"
        self.approval_tokens[token] = proposal_id
        self.token_expiry[token] = time.time() + (ttl_minutes * 60)
        return token

    def _check_token_valid(self, token: str) -> tuple:
        """Check if token is valid. Returns (valid: bool, proposal_id: str|None)"""
        if token not in self.approval_tokens:
            return False, None
        if token in self.token_expiry:
            if time.time() > self.token_expiry[token]:
                return False, None
        return True, self.approval_tokens[token]

    async def handle_approve_token(self, token: str, approved_by: str = "william") -> dict:
        """Handle approval by token. Returns status dict."""
        from core.quarantine.transaction_log import TransactionLog

        # Check in-memory first, then DB
        if token in self.decided_tokens:
            return {"status": "ALREADY_DECIDED", "proposal_id": self.approval_tokens.get(token), "message": "Allerede behandlet.", "success": False}

        # Double-check DB (for tokens decided before restart)
        txlog = TransactionLog(self.db_path)
        if txlog.is_token_decided(token):
            self.decided_tokens.add(token)  # Cache for next time
            return {"status": "ALREADY_DECIDED", "proposal_id": self.approval_tokens.get(token), "message": "Allerede behandlet.", "success": False}

        is_valid, proposal_id = self._check_token_valid(token)
        if not is_valid:
            return {"status": "INVALID_TOKEN", "proposal_id": None, "message": "Ugyldig eller utløpt token.", "success": False}

        result = await self.handle_approve(proposal_id, approved_by)
        if result:
            self.decided_tokens.add(token)
            # Persist to DB for restart safety
            tx_key = self.pending_approvals.get(proposal_id, {}).get("tx_key")
            txlog.record_decided_token(token, proposal_id, tx_key, "APPROVED")
            return {"status": "APPROVED", "proposal_id": proposal_id, "message": f"Forslag {proposal_id} godkjent.", "success": True}
        return {"status": "ERROR", "proposal_id": proposal_id, "message": "Kunne ikke godkjenne.", "success": False}

    async def handle_reject_token(self, token: str, reason: str, rejected_by: str = "william") -> dict:
        """Handle rejection by token."""
        from core.quarantine.transaction_log import TransactionLog

        # Check in-memory first, then DB
        if token in self.decided_tokens:
            return {"status": "ALREADY_DECIDED", "proposal_id": self.approval_tokens.get(token), "message": "Allerede behandlet.", "success": False}

        # Double-check DB (for tokens decided before restart)
        txlog = TransactionLog(self.db_path)
        if txlog.is_token_decided(token):
            self.decided_tokens.add(token)  # Cache for next time
            return {"status": "ALREADY_DECIDED", "proposal_id": self.approval_tokens.get(token), "message": "Allerede behandlet.", "success": False}

        is_valid, proposal_id = self._check_token_valid(token)
        if not is_valid:
            return {"status": "INVALID_TOKEN", "proposal_id": None, "message": "Ugyldig eller utløpt token.", "success": False}

        result = await self.handle_reject(proposal_id, reason, rejected_by)
        if result:
            self.decided_tokens.add(token)
            # Persist to DB for restart safety
            tx_key = self.pending_approvals.get(proposal_id, {}).get("tx_key")
            txlog.record_decided_token(token, proposal_id, tx_key, "REJECTED")
            return {"status": "REJECTED", "proposal_id": proposal_id, "message": f"Forslag {proposal_id} avvist.", "success": True}
        return {"status": "ERROR", "proposal_id": proposal_id, "message": "Kunne ikke avvise.", "success": False}

    async def _send_notification(self, tx_id: str, message: str, chat_id: int = None):
        """Send notification with queue + idempotency"""
        async with self._queue_lock:
            if tx_id in self.sent_tx_ids:
                self.logger.debug(f"TX already sent: {tx_id}")
                return

            if not (self.telegram_bot and getattr(self.telegram_bot, "zeph_ready", False)):
                self.logger.warning(f"TELEGRAM_NOT_READY: Queuing {tx_id}")
                self.message_queue.append((tx_id, message, chat_id))
                return

            await self._do_send_telegram(tx_id, message, chat_id)
            self.sent_tx_ids.add(tx_id)

    async def _process_message_queue(self):
        """Process queued messages"""
        queue_len = len(self.message_queue)
        self.logger.info(f"QUEUE_FLUSH_TRIGGERED len={queue_len}")
        async with self._queue_lock:
            while self.message_queue:
                tx_id, message, chat_id = self.message_queue.pop(0)
                if tx_id not in self.sent_tx_ids:
                    await self._do_send_telegram(tx_id, message, chat_id)
                    self.sent_tx_ids.add(tx_id)

    def on_telegram_ready(self):
        self.logger.info(f"QUEUE_FLUSH_TRIGGERED len={len(self.message_queue)}")
        """Called when zeph_ready becomes true"""
        try:
            asyncio.create_task(self._process_message_queue())
        except RuntimeError as e:
            self.logger.error(f"No event loop: {e}")

    async def _do_send_telegram(self, tx_id: str, message: str, chat_id: int = None):
        """Actual send logic"""
        try:
            if chat_id is None:
                from core.zeph_state import get_zeph_state
                state = get_zeph_state()
                admin_link = state.get_admin_link()
                chat_id = admin_link.get("chat_id") if admin_link else None

            if chat_id and self.telegram_bot and self.telegram_bot.zeph_app:
                await self.telegram_bot.zeph_app.bot.send_message(
                    chat_id=chat_id, text=message, parse_mode=None
                )
                self.logger.info(f"TELEGRAM_SENT tx_id={tx_id} chat_id={chat_id}")
                self.logger.info(f"✅ Telegram sent for TX {tx_id}")
            else:
                self.logger.error(f"TX_SEND_FAILED: No chat_id for {tx_id}")
        except Exception as e:
            self.logger.error(f"TX_SEND_FAILED: {tx_id} - {e}")



    async def handle_approve(self, proposal_id: str, approved_by: str = "william") -> bool:
        """Handle approval from William"""
        from skills.propose_code_change import get_code_proposer

        proposer = get_code_proposer()
        result = proposer.approve(proposal_id, approved_by)

        if result["success"]:
            self.logger.info(f"Proposal {proposal_id} approved by {approved_by}")
            if proposal_id in self.pending_approvals:
                del self.pending_approvals[proposal_id]
            return True
        else:
            self.logger.error(f"Failed to approve {proposal_id}: {result.get('error')}")
            return False

    async def handle_reject(self, proposal_id: str, reason: str, rejected_by: str = "william") -> bool:
        """Handle rejection from William"""
        from skills.propose_code_change import get_code_proposer

        proposer = get_code_proposer()
        result = proposer.reject(proposal_id, reason, rejected_by)

        if result["success"]:
            self.logger.info(f"Proposal {proposal_id} rejected by {rejected_by}: {reason}")
            if proposal_id in self.pending_approvals:
                del self.pending_approvals[proposal_id]
            return True
        else:
            self.logger.error(f"Failed to reject {proposal_id}: {result.get('error')}")
            return False


# Singleton instance
_service: Optional[ZephQuarantineService] = None

def get_quarantine_service() -> ZephQuarantineService:
    """Get global quarantine service"""
    global _service
    if _service is None:
        _service = ZephQuarantineService()
    return _service


if __name__ == "__main__":
    # Test the service
    logging.basicConfig(level=logging.INFO)

    async def test():
        service = ZephQuarantineService(str(Path.home() / "Desktop" / "Aeris_Knowledge_Inbox"))
        bridge = ApprovalHandlerApprovalBridge()

        await service.start()
        print("Service started. Press Ctrl+C to stop...")

        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            pass

        await service.stop()

    asyncio.run(test())


# === GO-GATE Bridge (minimal working) ===
class GoGateApprovalBridge:
    """
    Minimal bridge that sends approval requests through GOApprovalProvider.
    This is the canonical approval path:
      ZephQuarantine -> GOApprovalProvider -> base provider (Telegram/CLI) -> GOVerifier
    """
    def __init__(self, telegram_bot=None, auth_gate=None, timeout_seconds: int = 900):
        self.telegram_bot = telegram_bot
        self.auth_gate = auth_gate
        self.timeout_seconds = timeout_seconds
        self.logger = logging.getLogger("zeph.go_gate_bridge")

    async def send_for_approval(self, proposal_id: str, scan_result: SecurityScanResult):
        try:
            import os
            from core.auth.approval_worker import TelegramApprovalProvider
            bot_token = os.environ.get('AERIS_GOGATE_TELEGRAM_TOKEN') or os.environ.get('AERIS_approval_TELEGRAM_TOKEN')
            chat_id = os.environ.get('AERIS_ADMIN_CHAT_ID', os.getenv('AERIS_ADMIN_CHAT_ID', '0'))
            provider = TelegramApprovalProvider(bot_token=bot_token, chat_id=chat_id)

            # Create challenge via auth_gate (provider expects challenge)
            challenge = None
            if self.auth_gate and hasattr(self.auth_gate, "create_challenge"):
                challenge = self.auth_gate.create_challenge(action_id=proposal_id)

            # We don't have "skill/args" at this layer; keep it descriptive
            skill = "quarantine_apply"
            # Fix: Sikrer mot dict vs object krasj
            status_val = scan_result.get('status', 'unknown') if isinstance(scan_result, dict) else getattr(scan_result, 'status', 'unknown')
            score_val = scan_result.get('score', 0) if isinstance(scan_result, dict) else getattr(scan_result, 'score', 0)
            args = {"proposal_id": proposal_id, "scan_status": status_val, "scan_score": score_val}

            await provider.request_approval(
                action_id=proposal_id,
                skill=skill,
                args=args,
                challenge=challenge,
                timeout_seconds=self.timeout_seconds,
            )
            self.logger.info(f"[GO_GATE] APPROVAL_SENT: {proposal_id} | via=ZEPH_BOT | TTL={self.timeout_seconds}s")
        except Exception as e:
            self.logger.error(f"Failed to send approval request for {proposal_id}: {type(e).__name__}: {e}")
            raise
