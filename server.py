#!/usr/bin/env python3
"""JWT token operations — decode, validate, generate, inspect. — MEOK AI Labs."""

import sys, os

sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
from auth_middleware import check_access

import json, os, re, hashlib, math, base64, hmac, time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

FREE_DAILY_LIMIT = 30
_usage = defaultdict(list)


def _rl(c="anon"):
    now = datetime.now(timezone.utc)
    _usage[c] = [t for t in _usage[c] if (now - t).total_seconds() < 86400]
    if len(_usage[c]) >= FREE_DAILY_LIMIT:
        return json.dumps(
            {"error": "Limit {0}/day. Upgrade: meok.ai".format(FREE_DAILY_LIMIT)}
        )
    _usage[c].append(now)
    return None


mcp = FastMCP(
    "jwt-ai",
    instructions="MEOK AI Labs — JWT token operations — decode, validate, generate, inspect.",
)


def base64url_decode(data: str) -> bytes:
    data = data.replace("-", "+").replace("_", "/")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data)


def base64url_encode(data: bytes) -> str:
    return base64.b64encode(data).rstrip(b"=").decode("-_")


def decode_token_part(token: str) -> Dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Invalid token format"}

        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))

        return {"header": header, "payload": payload}
    except Exception as e:
        return {"error": str(e)}


def validate_signature(token: str, secret: str, algorithm: str = "HS256") -> Dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"valid": False, "error": "Invalid token format"}

        signing_input = parts[0] + "." + parts[1]

        if algorithm == "HS256":
            expected = base64url_encode(
                hmac.new(
                    secret.encode(), signing_input.encode(), hashlib.sha256
                ).digest()
            )
            signature_valid = expected == parts[2]
        elif algorithm == "HS384":
            expected = base64url_encode(
                hmac.new(
                    secret.encode(), signing_input.encode(), hashlib.sha384
                ).digest()
            )
            signature_valid = expected == parts[2]
        elif algorithm == "HS512":
            expected = base64url_encode(
                hmac.new(
                    secret.encode(), signing_input.encode(), hashlib.sha512
                ).digest()
            )
            signature_valid = expected == parts[2]
        else:
            return {"valid": False, "error": "Unsupported algorithm"}

        return {"valid": signature_valid, "algorithm": algorithm}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def generate_token(
    payload: Dict, secret: str, algorithm: str = "HS256", expires_in: int = 3600
) -> Dict:
    try:
        header = {"alg": algorithm, "typ": "JWT"}
        header_encoded = base64url_encode(json.dumps(header).encode())

        now = int(time.time())
        payload["iat"] = now
        payload["exp"] = now + expires_in

        payload_encoded = base64url_encode(json.dumps(payload).encode())

        signing_input = header_encoded + "." + payload_encoded

        if algorithm == "HS256":
            signature = base64url_encode(
                hmac.new(
                    secret.encode(), signing_input.encode(), hashlib.sha256
                ).digest()
            )
        elif algorithm == "HS384":
            signature = base64url_encode(
                hmac.new(
                    secret.encode(), signing_input.encode(), hashlib.sha384
                ).digest()
            )
        elif algorithm == "HS512":
            signature = base64url_encode(
                hmac.new(
                    secret.encode(), signing_input.encode(), hashlib.sha512
                ).digest()
            )
        else:
            return {"error": "Unsupported algorithm"}

        token = header_encoded + "." + payload_encoded + "." + signature

        return {"token": token, "expires_in": expires_in, "algorithm": algorithm}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def decode_jwt(token: str, api_key: str = "") -> str:
    """Decode a JWT token and show header, payload, signature."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if err := _rl():
        return err
    result = decode_token_part(token)
    result["decoded_at"] = datetime.now(timezone.utc).isoformat()
    return result


@mcp.tool()
def validate_jwt(
    token: str, secret: str = "", algorithm: str = "HS256", api_key: str = ""
) -> str:
    """Validate JWT signature and expiration."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if err := _rl():
        return err

    decoded = decode_token_part(token)
    if "error" in decoded:
        return decoded

    result = validate_signature(token, secret, algorithm)

    payload = decoded.get("payload", {})
    exp = payload.get("exp", 0)
    now = int(time.time())

    if exp and exp < now:
        result["expired"] = True
        result["valid"] = False
    else:
        result["expired"] = False

    return result


@mcp.tool()
def generate_jwt(
    payload: str,
    secret: str,
    algorithm: str = "HS256",
    expires_in: int = 3600,
    api_key: str = "",
) -> str:
    """Generate a signed JWT token."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if err := _rl():
        return err

    try:
        payload_dict = json.loads(payload) if isinstance(payload, str) else payload
    except Exception as e:
        return {"error": "Invalid payload JSON"}

    result = generate_token(payload_dict, secret, algorithm, expires_in)
    return result


@mcp.tool()
def inspect_claims(token: str, api_key: str = "") -> str:
    """Inspect JWT claims — issuer, audience, expiration, custom claims."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if err := _rl():
        return err

    decoded = decode_token_part(token)
    if "error" in decoded:
        return decoded

    payload = decoded.get("payload", {})

    claims = {
        "issuer": payload.get("iss"),
        "subject": payload.get("sub"),
        "audience": payload.get("aud"),
        "issued_at": payload.get("iat"),
        "expiration": payload.get("exp"),
        "not_before": payload.get("nbf"),
        "jwt_id": payload.get("jti"),
        "custom_claims": {
            k: v
            for k, v in payload.items()
            if k not in ["iss", "sub", "aud", "iat", "exp", "nbf", "jti"]
        },
    }

    return claims


@mcp.tool()
def verify_expiration(token: str, api_key: str = "") -> str:
    """Check if JWT token is expired or still valid."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if err := _rl():
        return err

    decoded = decode_token_part(token)
    if "error" in decoded:
        return decoded

    payload = decoded.get("payload", {})
    exp = payload.get("exp")
    nbf = payload.get("nbf")
    now = int(time.time())

    if not exp:
        return {"has_expiration": False, "message": "No expiration claim"}

    is_expired = exp < now
    is_premature = nbf and nbf > now

    return {
        "is_expired": is_expired,
        "is_premature": is_premature,
        "expires_at": datetime.fromtimestamp(exp, timezone.utc).isoformat()
        if exp
        else None,
        "not_before": datetime.fromtimestamp(nbf, timezone.utc).isoformat()
        if nbf
        else None,
        "seconds_until_expiry": exp - now if exp and not is_expired else 0,
    }


if __name__ == "__main__":
    mcp.run()
