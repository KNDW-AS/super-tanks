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
from datetime import datetime, timezone
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
                scanned_at=datetime.now(timezone.utc).isoformat(),
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
            scanned_at=datetime.now(timezone.utc).isoformat(),
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
        """Scan for sandbox escape patterns via AST analysis.

        AST analysis catches obfuscation that the previous regex
        approach silently passed:
          - `from os import system as s` then `s("rm -rf /")`
          - `getattr(__builtins__, "ex" + "ec")(...)`
          - `__class__.__bases__[0].__subclasses__()`
          - `importlib.import_module("os").system(...)`
        Files that fail to parse return a single "syntax_error"
        violation rather than passing silently.
        """
        from core.zeph_quarantine_ast import scan_python_source
        return scan_python_source(content, filename)

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
                from core.security.trust_score import record_event, _TrustAuthority
                agent = scan_result.issues[0].get("path", "zeph") if scan_result.issues else "zeph"
                with _TrustAuthority():
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

    def get_queue_len(self) -> int:
        """Abstract queue length - delegates to the attached bridge, or 0
        if no bridge has been attached yet."""
        bridge = getattr(self, "go_gate_bridge", None) or \
                 getattr(self, "approval_bridge", None)
        if bridge and hasattr(bridge, "get_queue_len"):
            return bridge.get_queue_len()
        return 0

    def on_telegram_ready(self):
        """Called when Telegram bot is ready - forwards to the attached bridge."""
        bridge = getattr(self, "go_gate_bridge", None) or \
                 getattr(self, "approval_bridge", None)
        if bridge and hasattr(bridge, "on_telegram_ready"):
            bridge.on_telegram_ready()

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



# Singleton instance
_service: Optional[ZephQuarantineService] = None

def get_quarantine_service() -> ZephQuarantineService:
    """Get global quarantine service"""
    global _service
    if _service is None:
        _service = ZephQuarantineService()
    return _service



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
