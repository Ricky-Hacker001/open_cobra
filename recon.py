#!/usr/bin/env python3
"""
PyCyberX (Starter Edition) – SAFE Multi‑Tool for Cybersecurity Learning

This starter is intentionally constrained to be SAFE and EDUCATIONAL:
- Passive Recon does NOT scrape search engines. It just GENERATES Google dork queries
  you can manually paste into a search engine (respect ToS and laws).
- Vulnerability Checker is HARD-LIMITED to localhost targets (http://localhost or http://127.0.0.1)
  so you only scan apps you control (e.g., DVWA, WebGoat, a local test Flask app).
- Hash Cracker is local‑only and intended for your OWN test hashes.

Author: You + ChatGPT
License: MIT
"""

from __future__ import annotations
import argparse
import hashlib
import itertools
import os
import re
import sys
import textwrap
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Optional

try:
    import requests
except Exception:
    print("[!] 'requests' package not found. Install with: pip install requests", file=sys.stderr)
    raise

# ---------------------------
# Utility & Constants
# ---------------------------
SAFE_LOCAL_PREFIXES = ("http://localhost", "http://127.0.0.1", "https://localhost", "https://127.0.0.1")
REPORTS_DIR = os.path.join(os.getcwd(), "reports")
DEFAULT_WORDLIST = os.path.join(os.getcwd(), "data_wordlist.txt")

DEFAULT_DORKS = [
    # General indexing
    "site:{target}",
    # Interesting files
    "site:{target} ext:sql | ext:env | ext:bak | ext:old | ext:log",
    # Exposed credentials / keys (be ethical!)
    "site:{target} (\"password\" | \"secret_key\" | \"aws_access_key_id\")",
    # Admin panels
    "site:{target} (inurl:admin | intitle:admin)",
    # Error messages that may indicate SQLi
    "site:{target} (\"You have an error in your SQL syntax\" | \"Warning: mysql\")",
    # Directory listing
    "site:{target} intitle:index.of",
    # Backups
    "site:{target} (backup | .git | .svn)",
    # Cloud buckets
    "site:{target} (\"index of\" s3) | site:{target} (\"index of\" bucket)",
]

MISSING_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# ---------------------------
# Passive Recon (SAFE)
# ---------------------------
class PassiveRecon:
    """Generates passive recon artifacts (no live scraping)."""

    @staticmethod
    def generate_google_dorks(target: str, extra_dorks: Optional[List[str]] = None) -> List[str]:
        target = target.strip()
        if not target:
            return []
        dorks = [d.format(target=target) for d in DEFAULT_DORKS]
        if extra_dorks:
            dorks.extend([d.format(target=target) for d in extra_dorks])
        return dorks

    @staticmethod
    def save_dorks(dorks: List[str], out_path: str) -> None:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, 'w', encoding='utf-8') as f:
            for q in dorks:
                f.write(q + "\n")

# ---------------------------
# Vulnerability Checker (LOCAL ONLY)
# ---------------------------
@dataclass
class HeaderAuditResult:
    url: str
    present: Dict[str, str]
    missing: List[str]

class VulnChecker:
    """Safe vulnerability checks restricted to local targets for learning."""

    @staticmethod
    def _ensure_local(url: str) -> None:
        if not url.startswith(SAFE_LOCAL_PREFIXES):
            raise ValueError(
                "This starter limits scanning to localhost only. Use a local DVWA/WebGoat or your own app."
            )

    @staticmethod
    def audit_security_headers(url: str, timeout: int = 10) -> HeaderAuditResult:
        VulnChecker._ensure_local(url)
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        headers = {k: v for k, v in r.headers.items()}
        present = {}
        missing = []
        for h in MISSING_SECURITY_HEADERS:
            if h in headers:
                present[h] = headers[h]
            else:
                missing.append(h)
        return HeaderAuditResult(url=url, present=present, missing=missing)

    @staticmethod
    def light_reflection_hint(html_text: str) -> List[str]:
        """
        A benign helper for XSS learning: given an HTML string (from your own app),
        it detects if typical special chars appear unescaped. This does not send payloads.
        """
        hints = []
        if "<script>" in html_text.lower():
            hints.append("Page contains <script> tag(s); ensure proper output encoding.")
        # Look for common unescaped characters in attribute/HTML context
        if re.search(r"[<>]", html_text):
            hints.append("Found raw '<' or '>' characters; verify output encoding to prevent XSS.")
        if "onerror=" in html_text.lower() or "onload=" in html_text.lower():
            hints.append("Inline event handlers present; consider CSP and avoiding inline JS.")
        return hints

# ---------------------------
# Hash Cracker (Local, Educational)
# ---------------------------
class HashCracker:
    SUPPORTED = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}

    @staticmethod
    def dictionary_attack(hash_value: str, algo: str, wordlist_path: str) -> Optional[str]:
        algo = algo.lower()
        if algo not in HashCracker.SUPPORTED:
            raise ValueError(f"Unsupported algorithm: {algo}")
        hasher = HashCracker.SUPPORTED[algo]
        if not os.path.exists(wordlist_path):
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
        target = hash_value.lower()
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                candidate = line.strip()
                if not candidate:
                    continue
                h = hasher(candidate.encode('utf-8')).hexdigest()
                if h == target:
                    return candidate
        return None

    @staticmethod
    def brute_force(hash_value: str, algo: str, charset: str = "abcdefghijklmnopqrstuvwxyz0123456789", max_len: int = 4) -> Optional[str]:
        """Very small brute force for demo; exponentially slow beyond length 4–5."""
        algo = algo.lower()
        if algo not in HashCracker.SUPPORTED:
            raise ValueError(f"Unsupported algorithm: {algo}")
        hasher = HashCracker.SUPPORTED[algo]
        target = hash_value.lower()
        for length in range(1, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                candidate = ''.join(combo)
                if hasher(candidate.encode('utf-8')).hexdigest() == target:
                    return candidate
        return None

# ---------------------------
# Report Writer
# ---------------------------
class Reporter:
    @staticmethod
    def write_markdown(title: str, body: str, filename: Optional[str] = None) -> str:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_title = re.sub(r"[^a-zA-Z0-9_-]+", "_", title)[:40]
        fname = filename or f"{safe_title}_{ts}.md"
        path = os.path.join(REPORTS_DIR, fname)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"# {title}\n\n")
            f.write(body)
        return path

# ---------------------------
# CLI Glue
# ---------------------------
BANNER = r"""
  ___                      ____        _                
 / _ \ _ __   ___ _ __    / _  \   __ | |__   __ _ _ __ 
| | | | '_ \ / _ \ '_ \  | |     / _ \| '_ \ / _` | '__|
| |_| | |_) |  __/ | | | | |_   | (_) | |_) | (_| | |       
 \___/| .__/ \___|_| |_|  \____/ \___/|_.__/ \__,_|_|   
      |_|                                            
"""

MENU = textwrap.dedent(
    """
    Choose a module:
      [1] Passive Recon (generate Google dorks)
      [2] Vulnerability Checker (LOCALHOST ONLY)
      [3] Hash Cracker (dictionary / tiny brute force)
      [4] Generate Sample Report
      [5] Exit
    """
)


def cmd_passive_recon(args: argparse.Namespace) -> None:
    target = args.target or input("Enter target domain (example.com): ").strip()
    extra = []
    if args.extra_dorks:
        extra = [d.strip() for d in args.extra_dorks.split("||") if d.strip()]
    dorks = PassiveRecon.generate_google_dorks(target, extra)
    if not dorks:
        print("[!] No dorks generated (empty target)")
        return
    os.makedirs("outputs", exist_ok=True)
    out_path = os.path.join("outputs", f"dorks_{target.replace('.', '_')}.txt")
    PassiveRecon.save_dorks(dorks, out_path)
    print(f"[+] Generated {len(dorks)} Google dork queries. Saved to: {out_path}")
    print("[i] Manually paste selected queries into your preferred search engine. Respect ToS and laws.")


def cmd_vuln_checker(args: argparse.Namespace) -> None:
    url = args.url or input("Enter LOCAL target URL (e.g., http://localhost:8080): ").strip()
    try:
        result = VulnChecker.audit_security_headers(url)
    except Exception as e:
        print(f"[!] Error: {e}")
        return

    lines = [f"Target: {result.url}", "", "## Security Header Audit", ""]
    if result.present:
        lines.append("Present headers:")
        for k, v in result.present.items():
            lines.append(f"- {k}: {v}")
        lines.append("")
    if result.missing:
        lines.append("Missing headers:")
        for h in result.missing:
            lines.append(f"- {h}")
    else:
        lines.append("All recommended headers present. Nice!")

    report_md = "\n".join(lines)
    path = Reporter.write_markdown("Local Security Header Audit", report_md)
    print(f"[+] Report written: {path}")


def cmd_hash_cracker(args: argparse.Namespace) -> None:
    mode = args.mode
    algo = args.algo.lower()
    hash_value = args.hash or input("Enter hash value: ").strip()

    if mode == "dict":
        wordlist = args.wordlist or DEFAULT_WORDLIST
        if not os.path.exists(wordlist):
            # Create a tiny default wordlist for demo
            with open(wordlist, 'w', encoding='utf-8') as f:
                f.write("password\nadmin\nletmein\nqwerty\nwelcome\nPyCyberX\n")
        print(f"[i] Using wordlist: {wordlist}")
        try:
            pwd = HashCracker.dictionary_attack(hash_value, algo, wordlist)
        except Exception as e:
            print(f"[!] Error: {e}")
            return
        if pwd is not None:
            print(f"[+] Match found: {pwd}")
        else:
            print("[-] No match in dictionary.")

    elif mode == "brute":
        charset = args.charset or "abc123"
        max_len = args.max_len
        try:
            pwd = HashCracker.brute_force(hash_value, algo, charset=charset, max_len=max_len)
        except Exception as e:
            print(f"[!] Error: {e}")
            return
        if pwd is not None:
            print(f"[+] Match found: {pwd}")
        else:
            print("[-] No match up to given max length.")


def cmd_sample_report(_: argparse.Namespace) -> None:
    body = textwrap.dedent(
        f"""
        Target: demo.local
        Date: {datetime.now().isoformat(timespec='seconds')}

        ## Summary
        - Passive recon generated 8 Google dork queries. (Manual use)
        - Local header audit: example report.
        - Hash cracking: dictionary attack placeholder.

        ## Notes
        This is a SAFE starter template. Extend responsibly and only test systems you own or have explicit permission to test.
        """
    )
    path = Reporter.write_markdown("PyCyberX Sample Report", body)
    print(f"[+] Sample report written: {path}")


# ---------------------------
# Argument Parser & Entry
# ---------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pycyberx",
        description="PyCyberX – SAFE starter multi‑tool for cybersecurity learning",
    )
    sub = p.add_subparsers(dest="command")

    # Passive Recon
    sp = sub.add_parser("recon", help="Generate Google dork queries (no scraping)")
    sp.add_argument("--target", type=str, help="Target domain, e.g., example.com")
    sp.add_argument("--extra-dorks", type=str, help="Extra dorks separated by '||'")
    sp.set_defaults(func=cmd_passive_recon)

    # Vulnerability Checker
    sv = sub.add_parser("vuln", help="Localhost-only security header audit")
    sv.add_argument("--url", type=str, help="Local URL, e.g., http://localhost:8080")
    sv.set_defaults(func=cmd_vuln_checker)

    # Hash Cracker
    sh = sub.add_parser("hash", help="Hash cracker (dictionary or tiny brute force)")
    sh.add_argument("--mode", choices=["dict", "brute"], default="dict")
    sh.add_argument("--algo", choices=["md5", "sha1", "sha256", "sha512"], default="sha256")
    sh.add_argument("--hash", type=str, help="Hash value to crack")
    sh.add_argument("--wordlist", type=str, help="Path to wordlist (dict mode)")
    sh.add_argument("--charset", type=str, help="Charset (brute mode)")
    sh.add_argument("--max-len", type=int, default=4, help="Max length (brute mode)")
    sh.set_defaults(func=cmd_hash_cracker)

    # Sample report
    sr = sub.add_parser("report", help="Generate a sample Markdown report")
    sr.set_defaults(func=cmd_sample_report)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        print(BANNER)
        print(MENU)
        choice = input("Select [1-5]: ").strip()
        # Map menu choice to subcommands
        if choice == "1":
            return main(["recon"])  # prompts for target interactively
        elif choice == "2":
            return main(["vuln"])   # prompts for URL interactively
        elif choice == "3":
            return main(["hash"])   # prompts for hash interactively
        elif choice == "4":
            return main(["report"]) 
        else:
            print("Bye.")
            return 0

    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
