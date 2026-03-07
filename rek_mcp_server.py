#!/usr/bin/env python3
"""
REK MCP Server
Exposes REK reconnaissance capabilities as MCP tools over StdIO (JSON-RPC 2.0).
Compatible with any local MCP client (Ollama + Open WebUI, LM Studio, Jan, Msty, etc.)

Usage:
    python3 rek_mcp_server.py

Configure your local LLM client to launch this as an MCP StdIO server.
"""

import sys
import json
import asyncio
import io
import os
import contextlib
import subprocess
import logging
from typing import Any

# Suppress all warnings/logging so they don't corrupt StdIO JSON stream
import warnings
warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)

# Ensure REK modules are importable from the same directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# Tool definitions (MCP schema)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "enumerate_subdomains",
        "description": (
            "Enumerate subdomains for a target domain using DNS brute-force, "
            "certificate transparency logs (crt.sh), and DNSDumpster. "
            "Returns discovered and DNS-validated subdomains."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain (e.g., example.com)"
                },
                "wordlist_path": {
                    "type": "string",
                    "description": "Path to custom subdomain wordlist file (optional)"
                },
                "concurrency": {
                    "type": "integer",
                    "description": "Max concurrent DNS queries (default: 50)",
                    "default": 50
                },
                "timeout": {
                    "type": "integer",
                    "description": "Request timeout in seconds (default: 10)",
                    "default": 10
                },
                "retries": {
                    "type": "integer",
                    "description": "Number of retries for failed requests (default: 3)",
                    "default": 3
                },
                "github_token": {
                    "type": "string",
                    "description": "GitHub Personal Access Token for parallel email search (optional)"
                },
                "output_file": {
                    "type": "string",
                    "description": "Output file path for results (default: <domain>_results.txt)"
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "check_http_status",
        "description": (
            "Check HTTP/HTTPS status codes, page titles, and server headers "
            "for a list of subdomains or URLs read from a file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_file": {
                    "type": "string",
                    "description": "Path to file containing one URL/subdomain per line"
                },
                "output_file": {
                    "type": "string",
                    "description": "Output CSV file path (default: http_results.csv)",
                    "default": "http_results.csv"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Request timeout in seconds (default: 10)",
                    "default": 10
                },
                "concurrency": {
                    "type": "integer",
                    "description": "Max concurrent requests (default: 100)",
                    "default": 100
                }
            },
            "required": ["input_file"]
        }
    },
    {
        "name": "scan_directories",
        "description": (
            "Scan for directories and files on web servers using wordlists. "
            "Accepts either a single URL or a CSV file from check_http_status filtered by status codes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Single target URL to scan (e.g., https://example.com)"
                },
                "input_file": {
                    "type": "string",
                    "description": "CSV file from check_http_status to filter and scan URLs"
                },
                "status_codes": {
                    "type": "string",
                    "description": "Comma-separated HTTP status codes to include (e.g., 200,301,403)"
                },
                "dir_wordlist": {
                    "type": "string",
                    "description": "Path to custom wordlist file for directory scanning (optional)"
                },
                "depth": {
                    "type": "integer",
                    "description": "Maximum crawl depth, 1-10 (default: 5)",
                    "default": 5
                },
                "timeout": {
                    "type": "integer",
                    "description": "Request timeout in seconds (default: 10)",
                    "default": 10
                },
                "concurrency": {
                    "type": "integer",
                    "description": "Max concurrent requests (default: 50)",
                    "default": 50
                }
            }
        }
    },
    {
        "name": "search_emails",
        "description": (
            "Search for email addresses associated with a domain or GitHub organization/user. "
            "Optionally checks discovered emails against Have I Been Pwned breach database."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "email_domain": {
                    "type": "string",
                    "description": "Domain to search emails for (e.g., example.com)"
                },
                "username": {
                    "type": "string",
                    "description": "GitHub username to search commit history for emails"
                },
                "org": {
                    "type": "string",
                    "description": "GitHub organization name to search"
                },
                "token": {
                    "type": "string",
                    "description": "GitHub Personal Access Token (increases rate limits)"
                },
                "hibp_key": {
                    "type": "string",
                    "description": "Have I Been Pwned API key for breach checking (optional)"
                },
                "limit_commits": {
                    "type": "integer",
                    "description": "Max commits to scan per repository (default: 50)",
                    "default": 50
                },
                "skip_forks": {
                    "type": "boolean",
                    "description": "Skip forked repositories (default: true)",
                    "default": True
                },
                "output_file": {
                    "type": "string",
                    "description": "Output CSV file path (default: email_results.csv)",
                    "default": "email_results.csv"
                }
            }
        }
    },
    {
        "name": "run_playbook",
        "description": (
            "Run an automated multi-phase reconnaissance playbook against a target domain. "
            "Phases include subdomain enumeration, HTTP probing, port scanning, JS analysis, and reporting. "
            "Requires bash and external tools installed via install-script.sh."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain (e.g., example.com)"
                },
                "version": {
                    "type": "string",
                    "description": "Playbook version to run: 'v1' (advanced), 'v2' (URL crawler), or 'standard'",
                    "enum": ["v1", "v2", "standard"],
                    "default": "v1"
                },
                "threads": {
                    "type": "integer",
                    "description": "Thread count for scanning tools (default: 100)",
                    "default": 100
                },
                "chaos_key": {
                    "type": "string",
                    "description": "Chaos Project API key (optional)"
                },
                "github_token": {
                    "type": "string",
                    "description": "GitHub Personal Access Token (optional)"
                },
                "skip_portscan": {
                    "type": "boolean",
                    "description": "Skip port scanning phase (default: false)",
                    "default": False
                },
                "skip_jsanalysis": {
                    "type": "boolean",
                    "description": "Skip JavaScript analysis phase (default: false)",
                    "default": False
                }
            },
            "required": ["domain"]
        }
    }
]

# ---------------------------------------------------------------------------
# StdIO helpers
# ---------------------------------------------------------------------------

def send(obj: dict) -> None:
    """Write a JSON object as a newline-delimited message to stdout."""
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def send_error(req_id: Any, code: int, message: str) -> None:
    send({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

async def tool_enumerate_subdomains(args: dict) -> str:
    from rek import SubdomainScanner

    domain = args["domain"]
    output_file = args.get("output_file") or f"{domain}_results.txt"

    scanner = SubdomainScanner(
        timeout=args.get("timeout", 10),
        wordlist_path=args.get("wordlist_path"),
        concurrency=args.get("concurrency", 50),
        retries=args.get("retries", 3),
        silent=True
    )

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        await scanner.enumerate_subdomains(
            domain=domain,
            output_file=output_file,
            github_token=args.get("github_token")
        )

    all_subs = sorted(scanner.subdomains)
    validated = sorted(scanner.validated_subdomains)

    lines = [
        f"Subdomain enumeration complete for: {domain}",
        f"Total discovered (unvalidated): {len(all_subs)}",
        f"DNS-validated: {len(validated)}",
        f"Output saved to: {output_file}",
        "",
    ]

    if validated:
        lines.append("DNS-Validated Subdomains:")
        lines.extend(f"  {s}" for s in validated)
    elif all_subs:
        lines.append(f"Discovered Subdomains (first 100):")
        lines.extend(f"  {s}" for s in all_subs[:100])
        if len(all_subs) > 100:
            lines.append(f"  ... and {len(all_subs) - 100} more (see {output_file})")

    return "\n".join(lines)


async def tool_check_http_status(args: dict) -> str:
    from rek import HTTPStatusChecker

    input_file = args["input_file"]
    output_file = args.get("output_file", "http_results.csv")

    checker = HTTPStatusChecker(
        timeout=args.get("timeout", 10),
        max_concurrent=args.get("concurrency", 100),
        silent=True
    )

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        checker.run(input_file, output_file)

    return (
        f"HTTP status check complete.\n"
        f"Input:  {input_file}\n"
        f"Output: {output_file}\n"
        f"Results written in CSV format with columns: Subdomain, URL, Status Code, Title, Server, Error"
    )


async def tool_scan_directories(args: dict) -> str:
    from rek import DirectoryScanner

    scanner = DirectoryScanner(
        timeout=args.get("timeout", 10),
        max_concurrent=args.get("concurrency", 50),
        max_depth=args.get("depth", 5),
        silent=True
    )

    input_file = args.get("input_file")
    url = args.get("url")
    dir_wordlist = args.get("dir_wordlist")
    status_codes = None
    if args.get("status_codes"):
        status_codes = [int(c.strip()) for c in args["status_codes"].split(",")]

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        scanner.run(input_file, status_codes, url, dir_wordlist)

    lines = [
        "Directory scan complete.",
        f"Scanned {len(scanner.results)} target(s).",
        "",
    ]
    for target_url, findings in scanner.results.items():
        hits = [f for f in findings if f.get("status_code") in (200, 301, 302, 403)]
        lines.append(f"{target_url}: {len(hits)} paths found")
        for f in hits[:20]:
            lines.append(f"  [{f['status_code']}] {f['url']}")
        if len(hits) > 20:
            lines.append(f"  ... and {len(hits) - 20} more (see results/<domain>/dirs.csv)")

    return "\n".join(lines)


async def tool_search_emails(args: dict) -> str:
    from rek_email_search import EmailSearcher

    output_file = args.get("output_file", "email_results.csv")
    username = args.get("org") or args.get("username")

    searcher = EmailSearcher(timeout=10, silent=True)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        searcher.run(
            domain=args.get("email_domain"),
            username=username,
            token=args.get("token"),
            output_file=output_file,
            max_commits=args.get("limit_commits", 50),
            skip_forks=args.get("skip_forks", True),
            hibp_key=args.get("hibp_key")
        )

    return (
        f"Email search complete.\n"
        f"Output saved to: {output_file}\n"
        f"CSV columns: Email, Repo, GitHubUser, Leaked, LeakedSource, CommitURL"
    )


async def tool_run_playbook(args: dict) -> str:
    domain = args["domain"]
    version = args.get("version", "v1")
    threads = args.get("threads", 100)

    playbook_map = {
        "v1": "playbook/rek-playbook-v1.sh",
        "v2": "playbook/rek-playbook-v2.sh",
        "standard": "playbook/rek-playbook.sh"
    }
    playbook = playbook_map.get(version, "playbook/rek-playbook-v1.sh")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    playbook_path = os.path.join(script_dir, playbook)

    if not os.path.exists(playbook_path):
        return f"Error: Playbook not found at {playbook_path}"

    cmd = ["bash", playbook_path, "-d", domain, "-t", str(threads)]
    if args.get("chaos_key"):
        cmd += ["--chaos-key", args["chaos_key"]]
    if args.get("github_token"):
        cmd += ["--github-token", args["github_token"]]
    if args.get("skip_portscan"):
        cmd.append("--skip-portscan")
    if args.get("skip_jsanalysis"):
        cmd.append("--skip-jsanalysis")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=script_dir
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3600)
        output = stdout.decode("utf-8", errors="replace")
        # Return last 5000 chars to avoid overwhelming the LLM context
        tail = output[-5000:] if len(output) > 5000 else output
        return (
            f"Playbook '{version}' finished for {domain} (exit code {proc.returncode}).\n\n"
            f"--- Output (last 5000 chars) ---\n{tail}"
        )
    except asyncio.TimeoutError:
        return f"Playbook timed out after 1 hour for {domain}."
    except Exception as e:
        return f"Error running playbook: {e}"


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

HANDLERS = {
    "enumerate_subdomains": tool_enumerate_subdomains,
    "check_http_status":    tool_check_http_status,
    "scan_directories":     tool_scan_directories,
    "search_emails":        tool_search_emails,
    "run_playbook":         tool_run_playbook,
}


# ---------------------------------------------------------------------------
# MCP JSON-RPC 2.0 server loop
# ---------------------------------------------------------------------------

async def handle_request(request: dict) -> None:
    req_id = request.get("id")
    method = request.get("method", "")
    params = request.get("params") or {}

    if method == "initialize":
        send({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "rek_mcp_server", "version": "1.0.0"}
            }
        })

    elif method == "initialized":
        # Notification — no response
        pass

    elif method == "ping":
        send({"jsonrpc": "2.0", "id": req_id, "result": {}})

    elif method == "tools/list":
        send({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS}
        })

    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or {}
        handler = HANDLERS.get(tool_name)

        if handler is None:
            send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                    "isError": True
                }
            })
            return

        try:
            result_text = await handler(arguments)
            send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": result_text}]
                }
            })
        except Exception as e:
            send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Tool execution error: {e}"}],
                    "isError": True
                }
            })

    else:
        send_error(req_id, -32601, f"Method not found: {method}")


async def readline_async(loop: asyncio.AbstractEventLoop) -> str | None:
    """Read one line from stdin without blocking the event loop (Windows-compatible)."""
    return await loop.run_in_executor(None, sys.stdin.readline)


async def main() -> None:
    loop = asyncio.get_event_loop()

    while True:
        try:
            line = await readline_async(loop)
        except Exception:
            break

        if not line:
            break

        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            send_error(None, -32700, f"Parse error: {e}")
            continue

        try:
            await handle_request(request)
        except Exception as e:
            send_error(request.get("id"), -32603, f"Internal error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
