<div align="center">

# Security Scanner Ai MCP

**MCP server for security scanner ai mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-security-scanner-ai-mcp)](https://pypi.org/project/meok-security-scanner-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Security Scanner Ai MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `scan_dependencies` | Scan requirements.txt for vulnerable dependencies. |
| `check_headers` | Check HTTP security headers on a URL. |
| `scan_secrets` | Scan code for hardcoded secrets, API keys, credentials. |
| `owasp_check` | Check endpoint against OWASP Top 10 2021. |
| `scan_owasp_2021` | Full OWASP Top 10 2021 vulnerability scanner. |

## Installation

```bash
pip install meok-security-scanner-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "security-scanner-ai-mcp": {
      "command": "python",
      "args": ["-m", "meok_security_scanner_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 5 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
