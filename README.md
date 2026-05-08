<div align="center">

# Jwt Ai MCP

**MCP server for jwt ai mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-jwt-ai-mcp)](https://pypi.org/project/meok-jwt-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Jwt Ai MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `decode_jwt` | Decode a JWT token and show header, payload, signature. |
| `validate_jwt` | Validate JWT signature and expiration. |
| `generate_jwt` | Generate a signed JWT token. |
| `inspect_claims` | Inspect JWT claims — issuer, audience, expiration, custom claims. |
| `verify_expiration` | Check if JWT token is expired or still valid. |

## Installation

```bash
pip install meok-jwt-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "jwt-ai-mcp": {
      "command": "python",
      "args": ["-m", "meok_jwt_ai_mcp.server"]
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
