"""Security middleware and utilities for the dashboard."""
import hashlib
import logging
import os
import re
import secrets
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)

# --- API Key Auth ---

def generate_api_key() -> str:
    """Generate a random API key."""
    return f"ops-{secrets.token_urlsafe(32)}"


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Require X-API-Key header for /api/* endpoints (except /api/health).

    Disabled when api_key is None (local dev mode).
    """

    def __init__(self, app, api_key: Optional[str] = None):
        super().__init__(app)
        self.api_key = api_key
        self.api_key_hash = hashlib.sha256(api_key.encode()).hexdigest() if api_key else None

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Skip auth for non-API routes, health check, and static files
        if not path.startswith("/api/") or path == "/api/health":
            return await call_next(request)
        # Skip if no key configured (local dev mode)
        if not self.api_key:
            return await call_next(request)
        # Check header
        provided = request.headers.get("X-API-Key", "")
        if not provided:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header")
        provided_hash = hashlib.sha256(provided.encode()).hexdigest()
        if provided_hash != self.api_key_hash:
            raise HTTPException(status_code=403, detail="Invalid API key")
        return await call_next(request)


# --- Rate Limiting ---

class RateLimiter:
    """Simple in-memory rate limiter by client IP."""

    def __init__(self, requests_per_minute: int = 30, burst: int = 10):
        self.rpm = requests_per_minute
        self.burst = burst
        self._requests: dict[str, list[float]] = defaultdict(list)

    def check(self, client_ip: str) -> bool:
        """Return True if request is allowed, False if rate limited."""
        now = time.time()
        window = 60.0
        # Clean old entries
        self._requests[client_ip] = [
            t for t in self._requests[client_ip] if now - t < window
        ]
        # Check burst (last 5 seconds)
        recent = sum(1 for t in self._requests[client_ip] if now - t < 5)
        if recent >= self.burst:
            return False
        # Check RPM
        if len(self._requests[client_ip]) >= self.rpm:
            return False
        self._requests[client_ip].append(now)
        return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limit /api/* endpoints."""

    def __init__(self, app, limiter: RateLimiter):
        super().__init__(app)
        self.limiter = limiter

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith("/api/") or path == "/api/health":
            return await call_next(request)
        client_ip = request.client.host if request.client else "unknown"
        if not self.limiter.check(client_ip):
            raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again shortly.")
        return await call_next(request)


# --- Security Headers ---

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # CSP: allow self + CDN for mermaid + AWS fonts
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://d1.awsstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        return response


# --- Chat Input Sanitization ---

MAX_CHAT_MESSAGE_LENGTH = 4000
MAX_FINDINGS_COUNT = 500

def sanitize_chat_message(message: str) -> str:
    """Sanitize chat input: strip control chars, enforce length limit."""
    if not message:
        raise ValueError("Message cannot be empty")
    # Strip control characters (keep newlines and tabs)
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', message)
    # Enforce length
    if len(cleaned) > MAX_CHAT_MESSAGE_LENGTH:
        raise ValueError(f"Message too long ({len(cleaned)} chars). Maximum is {MAX_CHAT_MESSAGE_LENGTH}.")
    return cleaned.strip()


def validate_findings_payload(findings: Optional[list]) -> Optional[list]:
    """Validate findings list size to prevent abuse."""
    if findings is None:
        return None
    if len(findings) > MAX_FINDINGS_COUNT:
        return findings[:MAX_FINDINGS_COUNT]
    return findings


# --- Audit Logger ---

class AuditLogger:
    """Persistent audit log for remediation actions."""

    def __init__(self, log_file: Optional[str] = None):
        self.log_file = log_file or os.environ.get(
            "OPS_AGENT_AUDIT_LOG", "cloudpilot_audit.log"
        )
        self._logger = logging.getLogger("cloudpilot.audit")
        if not self._logger.handlers:
            handler = logging.FileHandler(self.log_file)
            handler.setFormatter(logging.Formatter(
                '%(asctime)s | %(message)s', datefmt='%Y-%m-%dT%H:%M:%SZ'
            ))
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)

    def log_remediation(self, action: str, resource_id: str, region: str,
                        skill: str, success: bool, message: str,
                        client_ip: str = "unknown"):
        self._logger.info(
            "REMEDIATION | action=%s | resource=%s | region=%s | skill=%s | "
            "success=%s | client=%s | detail=%s",
            action, resource_id, region, skill, success, client_ip, message
        )

    def log_chat(self, client_ip: str, message_length: int):
        self._logger.info(
            "CHAT | client=%s | message_length=%d", client_ip, message_length
        )
