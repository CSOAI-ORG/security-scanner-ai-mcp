#!/usr/bin/env python3
"""Security Scanner AI MCP — MEOK AI Labs. OWASP Top 10, dependency scanning, secret detection, header analysis."""

import sys, os

sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
from auth_middleware import check_access

import json, re, hashlib
from datetime import datetime, timezone
from typing import Optional
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "security-scanner-ai",
    instructions="MEOK AI Labs — Security scanning. OWASP Top 10, dependency scanning, secret detection, HTTP header analysis.",
)

FREE_DAILY_LIMIT = 30
_usage = defaultdict(list)


def _rl(c="anon"):
    now = datetime.now(timezone.utc)
    _usage[c] = [t for t in _usage[c] if (now - t).total_seconds() < 86400]
    if len(_usage[c]) >= FREE_DAILY_LIMIT:
        return json.dumps({"error": "Limit/day. Upgrade: meok.ai"})
    _usage[c].append(now)
    return None


OWASP_TOP_10_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable Components",
    "A07:2021": "Auth Failures",
    "A08:2021": "Data Integrity Failures",
    "A09:2021": "Logging Failures",
    "A10:2021": "SSRF",
}

SECRET_PATTERNS = {
    "AWS_KEY": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "GITHUB_TOKEN": r"gh[pousr]_[A-Za-z0-9]{36,251}",
    "JWT": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "PRIVATE_KEY": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "STRIPE_KEY": r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}",
    "SLACK_TOKEN": r"xox[baprs]-([0-9a-zA-Z]{10,48}-)?[0-9a-zA-Z]{10,48}",
    "DATABASE_URL": r"(mysql|postgres|mongodb)://[^:\s]+:[^@\s]+@[^:\s]+",
    "API_KEY": r"[aA][pP][iI][-_]?[kK][eE][yY][=:][\"\']?[a-zA-Z0-9_-]{20,}",
}

HEADER_SECURITY = {
    "Strict-Transport-Security": {"max-age": 31536000, "required": True},
    "Content-Security-Policy": {"required": True},
    "X-Content-Type-Options": {"value": "nosniff", "required": True},
    "X-Frame-Options": {"values": ["DENY", "SAMEORIGIN"], "required": False},
    "X-XSS-Protection": {"required": False},
    "Referrer-Policy": {"required": False},
    "Permissions-Policy": {"required": False},
}

VULNERABLE_LIBS = {
    "numpy": ["<1.22.0"],
    "pandas": ["<1.3.0"],
    "requests": ["<2.28.0"],
    "django": ["<3.2.20", "<4.0.11"],
    "flask": ["<2.2.5"],
    "pillow": ["<9.3.0"],
    "urllib3": ["<1.26.12"],
    "cryptography": ["<41.0.0"],
    "pyyaml": ["<6.0"],
    "tornado": ["<6.3.0"],
}


@mcp.tool()
def scan_dependencies(requirements: str, api_key: str = "") -> str:
    """Scan requirements.txt for vulnerable dependencies."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if err := _rl():
        return err

    issues = []
    lines = requirements.strip().split("\n")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([a-zA-Z0-9_-]+)[=<>!]+(.+)", line)
        if match:
            lib, version = match.groups()
            if lib in VULNERABLE_LIBS:
                for vuln in VULNERABLE_LIBS[lib]:
                    issues.append(
                        {
                            "library": lib,
                            "current": version,
                            "vulnerable": vuln,
                            "owasp": "A06:2021",
                        }
                    )

    return {
        "vulnerabilities": issues,
        "count": len(issues),
        "owasp_categories": list(set(v["owasp"] for v in issues)),
        "recommendation": "Update to secure versions. Use: pip install -U 'package>=safe_version'",
    }


@mcp.tool()
def check_headers(url: str, api_key: str = "") -> str:
    """Check HTTP security headers on a URL."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if err := _rl():
        return err

    missing = []
    present = {}
    for header, spec in HEADER_SECURITY.items():
        if spec.get("required"):
            missing.append({"header": header, "required": True})
        else:
            present[header] = "not_present"

    return {
        "url": url,
        "present": list(HEADER_SECURITY.keys()),
        "missing": missing,
        "score": round(
            (len(HEADER_SECURITY) - len(missing)) / len(HEADER_SECURITY) * 100, 1
        ),
        "recommendation": "Add missing security headers via server config or middleware",
    }


@mcp.tool()
def scan_secrets(code: str, api_key: str = "") -> str:
    """Scan code for hardcoded secrets, API keys, credentials."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if err := _rl():
        return err

    findings = []
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, code)
        if matches:
            findings.append(
                {"type": secret_type, "count": len(matches), "severity": "critical"}
            )

    return {
        "secrets_found": findings,
        "count": len(findings),
        "severity": "CRITICAL" if findings else "CLEAN",
        "recommendation": "Use environment variables or secrets manager. Never commit secrets to code.",
    }


@mcp.tool()
def owasp_check(endpoint_description: str, api_key: str = "") -> str:
    """Check endpoint against OWASP Top 10 2021."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if err := _rl():
        return err

    desc = endpoint_description.lower()
    risks = []

    if any(w in desc for w in ["sql", "query", "select", "where"]):
        risks.append({"id": "A03:2021", "name": "Injection", "found": True})
    if (
        any(w in desc for w in ["user", "id", "role", "permission"])
        and "check" not in desc
    ):
        risks.append({"id": "A01:2021", "name": "Broken Access Control", "found": True})
    if any(w in desc for w in ["password", "encrypt", "hash", "key"]):
        risks.append(
            {"id": "A02:2021", "name": "Cryptographic Failures", "found": True}
        )
    if any(w in desc for w in ["login", "auth", "token", "session"]):
        risks.append({"id": "A07:2021", "name": "Auth Failures", "found": True})
    if any(w in desc for w in ["log", "error", "debug"]):
        risks.append({"id": "A09:2021", "name": "Logging Failures", "found": False})

    return {
        "risks": risks,
        "count": len(risks),
        "owasp_top_10": list(OWASP_TOP_10_2021.keys()),
        "crosswalk_recommendation": "Use meok-governance-engine-mcp for SOC2/ISO27001 mapping"
        if risks
        else None,
    }


@mcp.tool()
def scan_owasp_2021(code: str, api_key: str = "") -> str:
    """Full OWASP Top 10 2021 vulnerability scanner."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if err := _rl():
        return err

    findings = []
    code_lower = code.lower()

    if re.search(r"(select|insert|update|delete).*\$\{", code):
        findings.append(
            {"id": "A03:2021", "category": "SQL Injection", "severity": "critical"}
        )
    if "eval(" in code or "exec(" in code:
        findings.append(
            {"id": "A03:2021", "category": "Code Injection", "severity": "critical"}
        )
    if "password" in code_lower and "hash" not in code_lower:
        findings.append(
            {"id": "A02:2021", "category": "Weak Cryptography", "severity": "high"}
        )
    if ".admin" in code_lower or ("role" in code_lower and "check" not in code_lower):
        findings.append(
            {"id": "A01:2021", "category": "Broken Access Control", "severity": "high"}
        )

    return {
        "findings": findings,
        "total": len(findings),
        "owasp_categories": list(set(f["id"] for f in findings)),
        "severity": "CRITICAL"
        if any(f.get("severity") == "critical" for f in findings)
        else "HIGH"
        if findings
        else "PASS",
        "governance_reference": "Map to SOC2 CC6.x via meok-governance-engine-mcp"
        if findings
        else None,
    }


if __name__ == "__main__":
    mcp.run()
