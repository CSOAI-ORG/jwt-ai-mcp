# Jwt Ai

> By [MEOK AI Labs](https://meok.ai) — MEOK AI Labs — JWT token operations — decode, validate, generate, inspect.

JWT token operations — decode, validate, generate, inspect. — MEOK AI Labs.

## Installation

```bash
pip install jwt-ai-mcp
```

## Usage

```bash
# Run standalone
python server.py

# Or via MCP
mcp install jwt-ai-mcp
```

## Tools

### `decode_jwt`
Decode a JWT token and show header, payload, signature.

**Parameters:**
- `token` (str)

### `validate_jwt`
Validate JWT signature and expiration.

**Parameters:**
- `token` (str)
- `secret` (str)
- `algorithm` (str)

### `generate_jwt`
Generate a signed JWT token.

**Parameters:**
- `payload` (str)
- `secret` (str)
- `algorithm` (str)
- `expires_in` (int)

### `inspect_claims`
Inspect JWT claims — issuer, audience, expiration, custom claims.

**Parameters:**
- `token` (str)

### `verify_expiration`
Check if JWT token is expired or still valid.

**Parameters:**
- `token` (str)


## Authentication

Free tier: 15 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## Links

- **Website**: [meok.ai](https://meok.ai)
- **GitHub**: [CSOAI-ORG/jwt-ai-mcp](https://github.com/CSOAI-ORG/jwt-ai-mcp)
- **PyPI**: [pypi.org/project/jwt-ai-mcp](https://pypi.org/project/jwt-ai-mcp/)

## License

MIT — MEOK AI Labs
