"""Chat guardrails — input filtering, prompt injection detection, output sanitization."""
import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class GuardrailResult:
    allowed: bool
    reason: Optional[str] = None
    filtered_message: Optional[str] = None


# --- Prompt Injection Detection ---

# Patterns that indicate prompt injection attempts
_INJECTION_PATTERNS = [
    # Direct system prompt override attempts
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts|directions|context)",
     "Prompt override attempt detected"),
    (r"(?i)disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions|rules|prompts|guidelines)",
     "Prompt override attempt detected"),
    (r"(?i)forget\s+(all\s+)?(previous|prior|above|your)\s+.{0,20}(instructions|rules|context|prompts)",
     "Prompt override attempt detected"),
    # Role-play / persona hijacking
    (r"(?i)you\s+are\s+now\s+(a|an|the)\s+(?!aws|cloud|ops)",
     "Role-play attempt detected"),
    (r"(?i)act\s+as\s+(a|an|if\s+you\s+were)\s+(?!aws|cloud|ops)",
     "Role-play attempt detected"),
    (r"(?i)pretend\s+(to\s+be|you\s+are)",
     "Role-play attempt detected"),
    (r"(?i)switch\s+to\s+.{0,20}\s*mode",
     "Mode switch attempt detected"),
    # System prompt extraction
    (r"(?i)(show|reveal|print|display|output|repeat|tell)\s+(me\s+)?(your|the)\s+(system\s+prompt|instructions|rules|initial\s+prompt|hidden\s+(prompt|instructions))",
     "System prompt extraction attempt"),
    (r"(?i)what\s+(are|is)\s+your\s+(system\s+prompt|instructions|initial\s+prompt|hidden\s+instructions|rules\s+and\s+guidelines)",
     "System prompt extraction attempt"),
    # Delimiter injection
    (r"<\|?(system|assistant|endoftext|im_start|im_end)\|?>",
     "Delimiter injection detected"),
    (r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>",
     "Delimiter injection detected"),
    # Encoding evasion (base64 instructions, etc.)
    (r"(?i)(decode|execute|eval|run)\s+(this|the\s+following)\s+(base64|encoded|hex)",
     "Encoding evasion attempt"),
]

# Compiled patterns for performance
_COMPILED_INJECTION_PATTERNS = [
    (re.compile(pattern), reason) for pattern, reason in _INJECTION_PATTERNS
]


def check_prompt_injection(message: str) -> GuardrailResult:
    """Check if a message contains prompt injection attempts."""
    for pattern, reason in _COMPILED_INJECTION_PATTERNS:
        if pattern.search(message):
            logger.warning("Guardrail blocked: %s | message_preview=%s", reason, message[:80])
            return GuardrailResult(allowed=False, reason=reason)
    return GuardrailResult(allowed=True)


# --- Topic Boundary Enforcement ---

_OFF_TOPIC_PATTERNS = [
    # Harmful content requests
    (r"(?i)how\s+to\s+(hack|exploit|attack|breach|compromise|penetrate)\s+",
     "Harmful content request"),
    (r"(?i)(write|generate|create)\s+(a\s+)?(malware|virus|exploit|ransomware|keylogger|trojan)",
     "Malware generation request"),
    (r"(?i)(write|generate|create)\s+.{0,30}(phishing|spam|scam)",
     "Social engineering content request"),
    # Credential/secret extraction
    (r"(?i)(show|give|list|display)\s+(me\s+)?(all\s+)?(the\s+)?(aws\s+)?(credentials|secrets|passwords|access\s+keys|secret\s+keys)",
     "Credential extraction attempt"),
    (r"(?i)(what\s+is|show\s+me)\s+(the\s+)?(aws_secret|aws_access|secret_key|password)",
     "Credential extraction attempt"),
    # PII requests
    (r"(?i)(show|give|list|find)\s+(me\s+)?(employee|user|customer)\s+(names|emails|phone|address|ssn|social\s+security)",
     "PII request blocked"),
]

_COMPILED_TOPIC_PATTERNS = [
    (re.compile(pattern), reason) for pattern, reason in _OFF_TOPIC_PATTERNS
]


def check_topic_boundaries(message: str) -> GuardrailResult:
    """Check if a message stays within acceptable topic boundaries."""
    for pattern, reason in _COMPILED_TOPIC_PATTERNS:
        if pattern.search(message):
            logger.warning("Topic guardrail blocked: %s | message_preview=%s", reason, message[:80])
            return GuardrailResult(allowed=False, reason=reason)
    return GuardrailResult(allowed=True)


# --- Output Sanitization ---

_OUTPUT_SCRUB_PATTERNS = [
    # System prompt leakage
    (re.compile(r"(?i)(my\s+)?system\s+prompt\s+(is|says|reads|contains|instructs)[\s:]+.{20,}"), "[content filtered]"),
    (re.compile(r"(?i)my\s+(initial\s+)?instructions\s+(are|say|read)[\s:]+.{20,}"), "[content filtered]"),
    (re.compile(r"(?i)here\s+(is|are)\s+my\s+(system\s+)?instructions[\s:]+.{20,}"), "[content filtered]"),
    # AWS credential patterns (shouldn't appear but defense in depth)
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[ACCESS_KEY_REDACTED]"),
    (re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"), None),  # potential secret keys — only flag, don't replace blindly
]


def sanitize_output(response: str) -> str:
    """Scrub AI response for leaked system prompts or sensitive data."""
    result = response
    for pattern, replacement in _OUTPUT_SCRUB_PATTERNS:
        if replacement is not None:
            result = pattern.sub(replacement, result)
    return result


# --- Combined Guardrail Check ---

# Friendly refusal messages
_REFUSAL_MESSAGES = {
    "Prompt override attempt detected": (
        "I'm the AWS CloudPilot assistant — I stay focused on helping you with cloud operations. "
        "I can't change my role, but I'm happy to help with your AWS infrastructure, "
        "scan findings, or remediation questions."
    ),
    "Role-play attempt detected": (
        "I appreciate the creativity, but I'm purpose-built for AWS operations. "
        "Ask me about your scan findings, cost optimization, security posture, "
        "or any AWS topic and I'll give you a solid answer."
    ),
    "System prompt extraction attempt": (
        "I can't share my internal configuration, but I can tell you what I do: "
        "I analyze your AWS scan findings, help prioritize fixes, guide remediation, "
        "and answer AWS questions. What can I help you with?"
    ),
    "Delimiter injection detected": (
        "That input format isn't supported. Try asking a plain question about "
        "your AWS environment or scan findings."
    ),
    "Harmful content request": (
        "I'm here to help secure and optimize your AWS environment — not to assist with "
        "offensive activities. I can help you find and fix security vulnerabilities in your "
        "own infrastructure through the Security-Posture and Event-Analysis skills."
    ),
    "Malware generation request": (
        "I can't help with that. I'm focused on protecting your AWS infrastructure. "
        "If you're concerned about malware, I can help you review your GuardDuty findings "
        "and security posture."
    ),
    "Social engineering content request": (
        "I can't assist with that. If you're concerned about phishing targeting your organization, "
        "I can help review your IAM access key hygiene and Security Hub findings."
    ),
    "Credential extraction attempt": (
        "I don't have access to your AWS credentials and wouldn't share them if I did. "
        "If you're concerned about credential security, run the Security-Posture skill "
        "to check for old access keys and IAM misconfigurations."
    ),
    "PII request blocked": (
        "I don't have access to personal information and can't help with PII requests. "
        "I work with AWS infrastructure data — resource IDs, configurations, and scan findings."
    ),
    "Encoding evasion attempt": (
        "That input format isn't supported. Ask me a plain question about your AWS environment."
    ),
    "Mode switch attempt detected": (
        "I operate in one mode: helping you with AWS cloud operations. "
        "What can I help you with?"
    ),
}

_DEFAULT_REFUSAL = (
    "I can't process that request. I'm here to help with AWS cloud operations — "
    "scan findings, cost optimization, security, and infrastructure questions."
)


def apply_guardrails(message: str) -> GuardrailResult:
    """Run all input guardrails. Returns allowed=True if message is safe to process."""
    # 1. Prompt injection check
    result = check_prompt_injection(message)
    if not result.allowed:
        refusal = _REFUSAL_MESSAGES.get(result.reason, _DEFAULT_REFUSAL)
        return GuardrailResult(allowed=False, reason=result.reason, filtered_message=refusal)

    # 2. Topic boundary check
    result = check_topic_boundaries(message)
    if not result.allowed:
        refusal = _REFUSAL_MESSAGES.get(result.reason, _DEFAULT_REFUSAL)
        return GuardrailResult(allowed=False, reason=result.reason, filtered_message=refusal)

    return GuardrailResult(allowed=True)
