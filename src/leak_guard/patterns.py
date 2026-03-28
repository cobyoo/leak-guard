"""Secret detection patterns including Korean service API keys."""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    name: str
    pattern: re.Pattern
    severity: str  # "high", "medium", "low"


# --- Generic patterns ---

GENERIC_PATTERNS = [
    SecretPattern(
        name="AWS Access Key ID",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        severity="high",
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=re.compile(r"""(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""", re.IGNORECASE),
        severity="high",
    ),
    SecretPattern(
        name="GitHub Token",
        pattern=re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        severity="high",
    ),
    SecretPattern(
        name="Generic API Key",
        pattern=re.compile(r"""(?:api_key|apikey|api[-_]?secret)\s*[=:]\s*['"]([A-Za-z0-9_\-]{20,})['"]""", re.IGNORECASE),
        severity="medium",
    ),
    SecretPattern(
        name="Private Key",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        severity="high",
    ),
    SecretPattern(
        name="Generic Secret",
        pattern=re.compile(r"""(?:secret|password|passwd|pwd|token)\s*[=:]\s*['"]([^\s'"]{8,})['"]""", re.IGNORECASE),
        severity="medium",
    ),
    SecretPattern(
        name="JWT Token",
        pattern=re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}"),
        severity="high",
    ),
    SecretPattern(
        name="Slack Webhook URL",
        pattern=re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"),
        severity="high",
    ),
    SecretPattern(
        name="Google API Key",
        pattern=re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        severity="high",
    ),
    SecretPattern(
        name="Stripe Secret Key",
        pattern=re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        severity="high",
    ),
]

# --- Korean service patterns ---

KOREAN_PATTERNS = [
    SecretPattern(
        name="Kakao REST API Key",
        pattern=re.compile(r"""(?:kakao|KAKAO)[\w_]*(?:api[_-]?key|rest[_-]?key)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?""", re.IGNORECASE),
        severity="high",
    ),
    SecretPattern(
        name="Kakao JavaScript Key",
        pattern=re.compile(r"""(?:kakao|KAKAO)[\w_]*(?:js[_-]?key|javascript[_-]?key)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?""", re.IGNORECASE),
        severity="medium",
    ),
    SecretPattern(
        name="Kakao Admin Key",
        pattern=re.compile(r"""(?:kakao|KAKAO)[\w_]*admin[_-]?key\s*[=:]\s*['"]?([a-f0-9]{32})['"]?""", re.IGNORECASE),
        severity="high",
    ),
    SecretPattern(
        name="Naver Client ID",
        pattern=re.compile(r"""(?:naver|NAVER)[\w_]*client[_-]?id\s*[=:]\s*['"]?([A-Za-z0-9_]{20,})['"]?""", re.IGNORECASE),
        severity="medium",
    ),
    SecretPattern(
        name="Naver Client Secret",
        pattern=re.compile(r"""(?:naver|NAVER)[\w_]*client[_-]?secret\s*[=:]\s*['"]?([A-Za-z0-9_]{10,})['"]?""", re.IGNORECASE),
        severity="high",
    ),
    SecretPattern(
        name="Toss Payments Secret Key",
        pattern=re.compile(r"""(?:toss|TOSS)[\w_]*secret[_-]?key\s*[=:]\s*['"]?(test_sk_|live_sk_)[A-Za-z0-9]{20,}['"]?""", re.IGNORECASE),
        severity="high",
    ),
    SecretPattern(
        name="NHN Cloud AppKey",
        pattern=re.compile(r"""(?:nhn|NHN|toast|TOAST)[\w_]*app[_-]?key\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?""", re.IGNORECASE),
        severity="high",
    ),
    SecretPattern(
        name="Korea Public Data Portal API Key",
        pattern=re.compile(r"""(?:data\.go\.kr|public[_-]?data|공공데이터)[\w_]*(?:key|키)\s*[=:]\s*['"]?([A-Za-z0-9%+/=]{30,})['"]?""", re.IGNORECASE),
        severity="medium",
    ),
    SecretPattern(
        name="Iamport (PortOne) API Key",
        pattern=re.compile(r"""(?:iamport|imp|portone|PORTONE)[\w_]*(?:key|secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?""", re.IGNORECASE),
        severity="high",
    ),
    SecretPattern(
        name="Solapi (CoolSMS) API Key",
        pattern=re.compile(r"""(?:solapi|coolsms|SOLAPI|COOLSMS)[\w_]*(?:api[_-]?key|secret)\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?""", re.IGNORECASE),
        severity="high",
    ),
]

ALL_PATTERNS = GENERIC_PATTERNS + KOREAN_PATTERNS


def get_patterns(include_korean: bool = True) -> list[SecretPattern]:
    if include_korean:
        return ALL_PATTERNS
    return GENERIC_PATTERNS
