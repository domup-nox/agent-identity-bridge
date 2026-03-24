"""
AIB CLI — Command line interface for Agent Identity Bridge.

Usage:
    aib create   --org mycompany --agent booking --protocols mcp,a2a
    aib verify   --token eyJ...
    aib revoke   --id urn:aib:agent:mycompany:booking
    aib list
    aib translate --from a2a --to mcp --file agent-card.json
    aib translate --from mcp --to did --file server-card.json --domain example.com --slug booking
    aib inspect  --id urn:aib:agent:mycompany:booking
    aib serve    --port 8420
    aib keygen   --rotate

All commands work offline (no server needed) except 'serve'.
Data is stored in ~/.aib/ by default.
"""

import argparse
import json
import sys
import os
import time
from pathlib import Path

# Default storage directory
AIB_HOME = Path(os.environ.get("AIB_HOME", Path.home() / ".aib"))
PASSPORTS_DIR = AIB_HOME / "passports"
KEYS_DIR = AIB_HOME / "keys"


def get_passport_service():
    from .passport import PassportService
    secret = os.environ.get("AIB_SECRET_KEY", "aib-cli-dev-key")
    return PassportService(secret_key=secret, storage_path=str(PASSPORTS_DIR))


def get_crypto():
    from .crypto import KeyManager, PassportSigner
    km = KeyManager(keys_dir=str(KEYS_DIR))
    return km, PassportSigner(km)


def get_translator():
    from .translator import CredentialTranslator
    return CredentialTranslator()


# ── Colors ────────────────────────────────────────────────────────

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def success(msg):
    print(f"{GREEN}✓{RESET} {msg}")


def error(msg):
    print(f"{RED}✗{RESET} {msg}", file=sys.stderr)


def info(msg):
    print(f"{CYAN}→{RESET} {msg}")


def header(msg):
    print(f"\n{BOLD}{msg}{RESET}")


# ── Commands ──────────────────────────────────────────────────────

def cmd_create(args):
    """Create a new Agent Passport."""
    from .passport import McpBinding, A2aBinding, AnpBinding

    svc = get_passport_service()
    protocols = [p.strip() for p in args.protocols.split(",")]

    bindings = {}
    for proto in protocols:
        if proto == "mcp":
            bindings["mcp"] = McpBinding(
                auth_method=args.auth or "oauth2",
                server_card_url=args.mcp_url or f"https://{args.org}.com/.well-known/mcp.json",
            )
        elif proto == "a2a":
            bindings["a2a"] = A2aBinding(
                auth_method=args.auth or "bearer",
                agent_card_url=args.a2a_url or f"https://{args.org}.com/.well-known/agent.json",
            )
        elif proto == "anp":
            bindings["anp"] = AnpBinding(
                auth_method="did-auth",
                did=args.did or f"did:web:{args.org}.com:agents:{args.agent}",
            )
        else:
            error(f"Unknown protocol: {proto}. Supported: mcp, a2a, anp")
            sys.exit(1)

    capabilities = [c.strip() for c in args.capabilities.split(",")] if args.capabilities else [args.agent]

    passport, token = svc.create_passport(
        org_slug=args.org,
        agent_slug=args.agent,
        display_name=args.name or f"{args.org}/{args.agent}",
        capabilities=capabilities,
        bindings=bindings,
        ttl_days=args.ttl,
        metadata={"created_by": "aib-cli"},
    )

    header("Agent Passport created")
    success(f"ID: {passport.passport_id}")
    info(f"Name: {passport.display_name}")
    info(f"Protocols: {', '.join(passport.protocol_bindings.keys())}")
    info(f"Capabilities: {', '.join(passport.capabilities)}")
    info(f"Expires: {passport.expires_at}")
    info(f"Stored: {PASSPORTS_DIR}/{args.agent}.json")

    if args.show_token:
        print(f"\n{DIM}Token:{RESET}")
        print(token)

    if args.output:
        Path(args.output).write_text(json.dumps(passport.to_dict(), indent=2, ensure_ascii=False))
        info(f"Passport JSON written to {args.output}")


def cmd_verify(args):
    """Verify a passport token."""
    svc = get_passport_service()

    # Read token from arg, file, or stdin
    if args.token:
        token = args.token
    elif args.file:
        token = Path(args.file).read_text().strip()
    else:
        token = sys.stdin.read().strip()

    if not token:
        error("No token provided. Use --token, --file, or pipe via stdin.")
        sys.exit(1)

    valid, passport, reason = svc.verify_passport(token)

    if valid:
        header("Passport verification")
        success(f"Status: VALID")
        info(f"ID: {passport.passport_id}")
        info(f"Issuer: {passport.issuer}")
        info(f"Protocols: {list(passport.protocol_bindings.keys())}")
        info(f"Expires: {passport.expires_at}")
    else:
        header("Passport verification")
        error(f"Status: INVALID — {reason}")
        sys.exit(1)


def cmd_revoke(args):
    """Revoke a passport."""
    svc = get_passport_service()

    revoked = svc.revoke_passport(args.id)
    if revoked:
        success(f"Passport revoked: {args.id}")
    else:
        error(f"Passport already revoked or not found: {args.id}")
        sys.exit(1)


def cmd_list(args):
    """List all passports."""
    svc = get_passport_service()
    items = svc.list_passports()

    if not items:
        info("No passports found.")
        info(f"Create one: aib create --org myorg --agent myagent --protocols mcp,a2a")
        return

    header(f"Agent Passports ({len(items)})")
    print(f"{'STATUS':<10} {'ID':<45} {'PROTOCOLS':<20} {'EXPIRES':<12}")
    print("─" * 90)

    for p in items:
        status = f"{RED}REVOKED{RESET}" if p["revoked"] else f"{GREEN}ACTIVE {RESET}"
        protocols = ", ".join(p["protocols"])
        expires = p["expires_at"][:10] if p["expires_at"] else "—"
        print(f"{status}  {p['passport_id']:<45} {protocols:<20} {expires}")


def cmd_inspect(args):
    """Show full details of a passport."""
    svc = get_passport_service()

    slug = args.id.split(":")[-1]
    path = PASSPORTS_DIR / f"{slug}.json"

    if not path.exists():
        error(f"Passport not found: {args.id}")
        error(f"Looked in: {path}")
        sys.exit(1)

    data = json.loads(path.read_text())

    header(f"Passport: {data['passport']['passport_id']}")
    print(json.dumps(data["passport"], indent=2, ensure_ascii=False))

    # Also verify
    token = data["token"]
    valid, _, reason = svc.verify_passport(token)
    print()
    if valid:
        success(f"Signature: VALID")
    else:
        error(f"Signature: INVALID — {reason}")


def cmd_translate(args):
    """Translate between protocol identity formats."""
    translator = get_translator()

    # Read source
    if args.file:
        source = json.loads(Path(args.file).read_text())
    else:
        source = json.loads(sys.stdin.read())

    # Map short names to full format names
    format_map = {
        "a2a": "a2a_agent_card",
        "mcp": "mcp_server_card",
        "did": "did_document",
        "a2a_agent_card": "a2a_agent_card",
        "mcp_server_card": "mcp_server_card",
        "did_document": "did_document",
    }

    from_fmt = format_map.get(args.source_format)
    to_fmt = format_map.get(args.target_format)

    if not from_fmt:
        error(f"Unknown source format: {args.source_format}. Use: a2a, mcp, did")
        sys.exit(1)
    if not to_fmt:
        error(f"Unknown target format: {args.target_format}. Use: a2a, mcp, did")
        sys.exit(1)

    try:
        result = translator.translate(
            source=source,
            from_format=from_fmt,
            to_format=to_fmt,
            domain=args.domain,
            agent_slug=args.slug,
        )
    except ValueError as e:
        error(str(e))
        sys.exit(1)

    header(f"Translation: {args.source_format} → {args.target_format}")

    if "tools" in result:
        success(f"{len(result.get('tools', []))} tools mapped")
    if "skills" in result:
        success(f"{len(result.get('skills', []))} skills mapped")
    if "id" in result and result["id"].startswith("did:"):
        success(f"DID: {result['id']}")

    # Output
    output_json = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(output_json)
        info(f"Written to {args.output}")
    else:
        print(output_json)


def cmd_serve(args):
    """Start the AIB Gateway server."""
    info(f"Starting AIB Gateway on port {args.port}...")
    info(f"Docs: http://localhost:{args.port}/docs")
    info(f"Storage: {PASSPORTS_DIR}")
    print()

    os.environ.setdefault("AIB_STORAGE_PATH", str(PASSPORTS_DIR))

    import uvicorn
    uvicorn.run("aib.main:app", host=args.host, port=args.port, reload=args.reload)


def cmd_keygen(args):
    """Generate or rotate RS256 signing keys."""
    from .crypto import KeyManager

    km = KeyManager(keys_dir=str(KEYS_DIR))

    if args.rotate:
        old_kid = km.active_key.kid
        new_key = km.rotate()
        header("Key rotated")
        info(f"Old key: {old_kid} (still valid for verification)")
        success(f"New key: {new_key.kid} (active for signing)")
    else:
        key = km.active_key
        header("Current signing key")
        info(f"Key ID: {key.kid}")
        info(f"Created: {key.created_at}")
        info(f"Algorithm: RS256 (RSA 2048-bit)")
        info(f"Stored: {KEYS_DIR}/")

    if args.jwks:
        jwks = km.jwks()
        print(json.dumps(jwks, indent=2))


# ── Main ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="aib",
        description="Agent Identity Bridge — Portable identity for AI agents",
        epilog="Documentation: https://github.com/domup-nox/agent-identity-bridge",
    )
    parser.add_argument("--version", action="version", version="aib 0.2.0")
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── create ──
    p_create = sub.add_parser("create", help="Create a new Agent Passport")
    p_create.add_argument("--org", required=True, help="Organization slug (e.g. mycompany)")
    p_create.add_argument("--agent", required=True, help="Agent slug (e.g. booking)")
    p_create.add_argument("--protocols", required=True, help="Comma-separated protocols (mcp,a2a,anp)")
    p_create.add_argument("--name", help="Display name (default: org/agent)")
    p_create.add_argument("--capabilities", help="Comma-separated capabilities")
    p_create.add_argument("--auth", help="Auth method (oauth2, bearer, api_key)")
    p_create.add_argument("--mcp-url", help="MCP server card URL")
    p_create.add_argument("--a2a-url", help="A2A agent card URL")
    p_create.add_argument("--did", help="ANP DID identifier")
    p_create.add_argument("--ttl", type=int, default=365, help="Passport TTL in days (default: 365)")
    p_create.add_argument("--show-token", action="store_true", help="Print the signed token")
    p_create.add_argument("--output", "-o", help="Write passport JSON to file")

    # ── verify ──
    p_verify = sub.add_parser("verify", help="Verify a passport token")
    p_verify.add_argument("--token", help="Token string")
    p_verify.add_argument("--file", "-f", help="Read token from file")

    # ── revoke ──
    p_revoke = sub.add_parser("revoke", help="Revoke a passport")
    p_revoke.add_argument("--id", required=True, help="Passport ID (urn:aib:agent:org:name)")

    # ── list ──
    sub.add_parser("list", help="List all passports")

    # ── inspect ──
    p_inspect = sub.add_parser("inspect", help="Show full passport details")
    p_inspect.add_argument("--id", required=True, help="Passport ID")

    # ── translate ──
    p_translate = sub.add_parser("translate", help="Translate between identity formats")
    p_translate.add_argument("--from", dest="source_format", required=True, help="Source format (a2a, mcp, did)")
    p_translate.add_argument("--to", dest="target_format", required=True, help="Target format (a2a, mcp, did)")
    p_translate.add_argument("--file", "-f", help="Source JSON file (or stdin)")
    p_translate.add_argument("--domain", help="Domain for DID generation")
    p_translate.add_argument("--slug", help="Agent slug for DID generation")
    p_translate.add_argument("--output", "-o", help="Output file (or stdout)")

    # ── serve ──
    p_serve = sub.add_parser("serve", help="Start the AIB Gateway server")
    p_serve.add_argument("--port", type=int, default=8420, help="Port (default: 8420)")
    p_serve.add_argument("--host", default="0.0.0.0", help="Host (default: 0.0.0.0)")
    p_serve.add_argument("--reload", action="store_true", help="Auto-reload on code changes")

    # ── keygen ──
    p_keygen = sub.add_parser("keygen", help="Manage RS256 signing keys")
    p_keygen.add_argument("--rotate", action="store_true", help="Rotate to a new key")
    p_keygen.add_argument("--jwks", action="store_true", help="Print JWKS (public keys)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        print(f"\n{CYAN}Quick start:{RESET}")
        print(f"  aib create --org mycompany --agent booking --protocols mcp,a2a")
        print(f"  aib list")
        print(f"  aib translate --from a2a --to mcp --file agent-card.json")
        print(f"  aib serve")
        sys.exit(0)

    # Ensure storage dirs exist
    PASSPORTS_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    commands = {
        "create": cmd_create,
        "verify": cmd_verify,
        "revoke": cmd_revoke,
        "list": cmd_list,
        "inspect": cmd_inspect,
        "translate": cmd_translate,
        "serve": cmd_serve,
        "keygen": cmd_keygen,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
