"""
core/security/audit_sanitizer.py
==================================
Masks sensitive data (API keys, passwords, tokens, fødselsnummer, card numbers)
before they enter the audit log.
"""

import re
import logging

logger = logging.getLogger("super_tanks.sanitizer")

SANITIZE_PATTERNS = [
    (r'(?i)(api[_-]?key|token|secret|password|passwd|pwd)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{8,})["\']?', r'\1=***REDACTED***'),
    (r'(?i)Bearer\s+[A-Za-z0-9_\-\.]+', 'Bearer ***REDACTED***'),
    (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE KEY-----.*?-----END\s+(?:RSA\s+)?PRIVATE KEY-----', '***SSH_KEY_REDACTED***'),
    (r'\b\d{6}\s?\d{5}\b', '***FNUMMER_REDACTED***'),
    (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '***CARD_REDACTED***'),
    (r'\b[0-9a-fA-F]{40,}\b', '***HEX_REDACTED***'),
    (r'(?i)(OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|TELEGRAM_BOT_TOKEN|HOMEASSISTANT_TOKEN|MOONSHOT_API_KEY)\s*=\s*\S+', r'\1=***REDACTED***'),
    (r'(?i)eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '***JWT_REDACTED***'),
]

_COMPILED = [(re.compile(p, re.DOTALL), r) for p, r in SANITIZE_PATTERNS]


def sanitize(text: str) -> str:
    if not text:
        return text
    result = text
    for pattern, replacement in _COMPILED:
        result = pattern.sub(replacement, result)
    return result


def sanitize_dict(data: dict) -> dict:
    sanitized = {}
    for key, value in data.items():
        if isinstance(value, str):
            sanitized[key] = sanitize(value)
        elif isinstance(value, dict):
            sanitized[key] = sanitize_dict(value)
        elif isinstance(value, list):
            sanitized[key] = [sanitize(v) if isinstance(v, str) else sanitize_dict(v) if isinstance(v, dict) else v for v in value]
        else:
            sanitized[key] = value
    return sanitized
