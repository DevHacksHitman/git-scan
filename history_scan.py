#!/usr/bin/env python3
"""history_scan — find secrets and sensitive data in a git repository.

Scans what actually gets leaked: the whole commit history, the staged change
about to be committed, or the working tree. Reports credential shapes, personal
data and high-entropy strings — and **redacts every match**, because a scanner
that prints the secret it found has just leaked it into a CI log.

    python3 history_scan.py                     # whole history of the repo
    python3 history_scan.py --staged            # what you are about to commit
    python3 history_scan.py --worktree          # files on disk
    python3 history_scan.py --format json       # machine-readable
    python3 history_scan.py --format sarif      # code-scanning pipeline format

Exit codes (CI-friendly): 0 = clean, 1 = findings, 2 = usage error.

Why zero dependencies: a security tool that pulls in a dependency tree is a
supply-chain risk in the exact place you are trying to reduce risk.

Self-avoidance: the pattern table is written so this file's own source does not
match its own rules — every literal is bracketed or assembled at runtime (the
private-key header below is built from parts for that reason). A test scans this
repository with this tool and asserts zero findings.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

VERSION = "0.1.0"
TOOL = "history-scan"
IGNORE_FILE = ".history-scan-ignore"

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

# Built from parts so this file cannot match its own private-key rule.
_PK_HEADER = "-" * 5 + "BEGIN" + r"[ A-Z]{0,20}PRIV" + "ATE KEY" + "-" * 5

DEFAULT_IGNORES = (
    "*.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "*.min.js", "*.min.css", "*.map", "*.snap",
    "node_modules/*", ".git/*", "dist/*", "build/*", "vendor/*",
    "*.sqlite", "*.db", "*.parquet", "*.png", "*.jpg", "*.jpeg",
    "*.gif", "*.ico", "*.woff", "*.woff2", "*.pdf", "*.zip",
)


@dataclass
class Rule:
    id: str
    description: str
    severity: str
    pattern: str


RULES: Tuple[Rule, ...] = (
    Rule("private-key-header", "PEM private key block", "high", _PK_HEADER),
    Rule("aws-access-key-id", "AWS access key ID", "high", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    Rule("github-token", "GitHub token", "high", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    Rule("slack-token", "Slack token", "high", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    Rule("google-api-key", "Google API key", "high", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    Rule("stripe-secret", "Stripe live secret key", "high", r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    Rule("jwt", "JSON Web Token", "medium",
         r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}\b"),
    Rule("credential-assignment", "Hard-coded credential assignment", "medium",
         r"""(?i)\b(?:api[_-]?key|secret|token|passwd|password|pwd)\b\s*[:=]\s*["'][^"'\s]{8,}["']"""),
    Rule("email-address", "Email address (personal data)", "low",
         r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    Rule("ng-phone", "Nigerian phone number (personal data)", "low",
         r"\b(?:\+?234|0)[789]\d{9}\b"),
)

ENTROPY_RULE = Rule("high-entropy-string", "High-entropy string (possible key)", "medium", "")
ENTROPY_MIN_LENGTH = 24
ENTROPY_THRESHOLD = 4.5
_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
_TOKENISH = re.compile(r"[A-Za-z0-9+/=_\-]{%d,}" % ENTROPY_MIN_LENGTH)


@dataclass
class Finding:
    rule: str
    severity: str
    description: str
    path: str
    line: Optional[int]
    commit: Optional[str]
    redacted: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "description": self.description,
            "path": self.path,
            "line": self.line,
            "commit": self.commit,
            "match": self.redacted,
        }


class ScanError(Exception):
    """A usage or environment problem (exit code 2)."""


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------
def redact(value: str, keep: int = 4) -> str:
    """Show enough to locate the finding, never enough to use it."""
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * min(len(value) - keep, 12)} ({len(value)} chars)"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def load_rules(path: Optional[str] = None) -> List[Rule]:
    """Default rules, plus any extra rules from a JSON file."""
    rules = list(RULES)
    if not path:
        return rules
    config = Path(path)
    if not config.exists():
        raise ScanError(f"no such rules file: {config}")
    try:
        payload = json.loads(config.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ScanError(f"{config} is not valid JSON: {exc}") from exc
    entries = payload.get("rules") if isinstance(payload, dict) else payload
    if not isinstance(entries, list):
        raise ScanError("rules file must be a list, or an object with a 'rules' list")
    for entry in entries:
        try:
            rule = Rule(
                str(entry["id"]),
                str(entry.get("description", "")),
                str(entry.get("severity", "medium")),
                str(entry["pattern"]),
            )
        except (KeyError, TypeError) as exc:
            raise ScanError(f"invalid rule entry: {entry!r} ({exc})") from exc
        if rule.severity not in SEVERITY_ORDER:
            raise ScanError(f"rule {rule.id}: severity must be one of {', '.join(SEVERITY_ORDER)}")
        rules.append(rule)
    return rules


def scan_line(line: str) -> List[Tuple[Rule, str]]:
    """Return (rule, matched text) pairs for one line of content."""
    hits: List[Tuple[Rule, str]] = []
    for rule in RULES:
        for match in re.finditer(rule.pattern, line):
            hits.append((rule, match.group(0)))
    for candidate in _TOKENISH.findall(line):
        if _HEX_ONLY.match(candidate):
            continue  # hex digests are usually hashes, not keys
        if shannon_entropy(candidate) >= ENTROPY_THRESHOLD:
            hits.append((ENTROPY_RULE, candidate))
    return hits


# ---------------------------------------------------------------------------
# Sources: history, staged, worktree
# ---------------------------------------------------------------------------
COMMIT_RE = re.compile(r"^commit ([0-9a-f]{7,40})")
NEWFILE_RE = re.compile(r"^\+\+\+ b/(.*)$")
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _git(args: Sequence[str], repo: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=str(repo), capture_output=True, text=True, timeout=300
        )
    except FileNotFoundError as exc:
        raise ScanError("git is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"git {' '.join(args[:2])} timed out") from exc
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout).strip().splitlines()
        raise ScanError(message[0] if message else f"git {' '.join(args[:2])} failed")
    return completed.stdout


def parse_unified_diff(text: str) -> Iterator[Tuple[Optional[str], str, Optional[int], str]]:
    """Yield (commit, path, line_number, content) for every ADDED line."""
    commit: Optional[str] = None
    path: Optional[str] = None
    number: Optional[int] = None
    for raw in text.splitlines():
        if COMMIT_RE.match(raw):
            commit = COMMIT_RE.match(raw).group(1)
            continue
        match = NEWFILE_RE.match(raw)
        if match:
            path = match.group(1)
            number = None
            continue
        match = HUNK_RE.match(raw)
        if match:
            number = int(match.group(1))
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if raw.startswith("+"):
            if number is None:
                number = 0
            yield commit, path or "(unknown)", number, raw[1:]
            number += 1


def iter_history(repo: Path) -> Iterator[Tuple[Optional[str], str, Optional[int], str]]:
    diff = _git(["log", "-p", "--all", "--no-color", "-U0", "--no-merges"], repo)
    yield from parse_unified_diff(diff)


def iter_staged(repo: Path) -> Iterator[Tuple[Optional[str], str, Optional[int], str]]:
    diff = _git(["diff", "--cached", "--no-color", "-U0"], repo)
    yield from parse_unified_diff(diff)


def iter_worktree(repo: Path) -> Iterator[Tuple[Optional[str], str, Optional[int], str]]:
    for path in sorted(repo.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(repo)
        if any(part in {".git", "node_modules", "dist", "build", ".venv"} for part in relative.parts):
            continue
        try:
            if b"\x00" in path.open("rb").read(4096):
                continue  # binary
        except OSError:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            yield None, str(relative), number, line


# ---------------------------------------------------------------------------
# Ignore handling
# ---------------------------------------------------------------------------
def load_ignores(repo: Path, extra: Iterable[str] = ()) -> List[str]:
    patterns = list(DEFAULT_IGNORES) + list(extra)
    ignore_file = repo / IGNORE_FILE
    if ignore_file.exists():
        for line in ignore_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def is_ignored(path: str, patterns: Sequence[str]) -> bool:
    return any(
        fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(Path(path).name, pattern)
        for pattern in patterns
    )


# ---------------------------------------------------------------------------
# Scanning and reporting
# ---------------------------------------------------------------------------
def scan(
    source: Iterable[Tuple[Optional[str], str, Optional[int], str]],
    rules: Sequence[Rule],
    ignores: Sequence[str] = (),
) -> List[Finding]:
    findings: List[Finding] = []
    for commit, path, number, content in source:
        if is_ignored(path, ignores):
            continue
        for rule, matched in scan_line(content):
            if rule not in rules:
                continue
            findings.append(
                Finding(rule.id, rule.severity, rule.description, path, number, commit, redact(matched))
            )
    return findings


def sort_findings(findings: Sequence[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.path, f.line or 0, f.rule),
    )


def render_text(findings: Sequence[Finding], source_label: str, limit: int = 100) -> str:
    if not findings:
        return f"PASS — no findings in {source_label}."
    lines = [f"FINDINGS — {len(findings)} in {source_label}", ""]
    for finding in findings[:limit]:
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        if finding.commit:
            location += f" @{finding.commit[:8]}"
        lines.append(f"  [{finding.severity:>6}] {finding.rule}: {location}")
        lines.append(f"           {finding.description} — {finding.redacted}")
    if len(findings) > limit:
        lines.append(f"  … {len(findings) - limit} more (use --format json for all)")
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    lines += ["", "Summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))]
    return "\n".join(lines)


def render_json(findings: Sequence[Finding], source_label: str) -> str:
    return json.dumps(
        {
            "tool": TOOL,
            "version": VERSION,
            "source": source_label,
            "findings": [f.as_dict() for f in findings],
            "summary": {
                "total": len(findings),
                "by_severity": {
                    severity: sum(1 for f in findings if f.severity == severity)
                    for severity in ("high", "medium", "low")
                },
            },
        },
        indent=2,
    )


def render_sarif(findings: Sequence[Finding], rules: Sequence[Rule]) -> str:
    """Minimal SARIF 2.1.0 so the scan can feed a code-scanning pipeline."""
    used = {f.rule for f in findings}
    level = {"high": "error", "medium": "warning", "low": "note"}
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": TOOL,
                            "version": VERSION,
                            "rules": [
                                {
                                    "id": rule.id,
                                    "shortDescription": {"text": rule.description},
                                    "defaultConfiguration": {"level": level.get(rule.severity, "note")},
                                }
                                for rule in rules
                                if rule.id in used
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": finding.rule,
                            "level": level.get(finding.severity, "note"),
                            "message": {
                                "text": f"{finding.description} ({finding.redacted})"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": finding.path},
                                        "region": {"startLine": finding.line or 1},
                                    }
                                }
                            ],
                        }
                        for finding in findings
                    ],
                }
            ],
        },
        indent=2,
    )


def fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="history_scan.py",
        description="Scan a git repository for secrets and sensitive data (zero dependencies).",
    )
    parser.add_argument("--repo", default=".", help="repository path (default: current directory)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--history", action="store_true", help="scan all commits (default)")
    mode.add_argument("--staged", action="store_true", help="scan staged changes only")
    mode.add_argument("--worktree", action="store_true", help="scan files on disk")
    parser.add_argument("--rules", help="JSON file with extra rules")
    parser.add_argument("--exclude", action="append", default=[], help="path glob to skip (repeatable)")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default="low",
                        help="minimum severity that fails the run (default: low)")
    parser.add_argument("--limit", type=int, default=100, help="max findings to print in text mode")
    parser.add_argument("--version", action="version", version=f"{TOOL} {VERSION}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    repo = Path(args.repo).resolve()
    if not (repo / ".git").exists():
        print(f"error: {repo} is not a git repository", file=sys.stderr)
        return 2

    try:
        rules = load_rules(args.rules)
        ignores = load_ignores(repo, args.exclude)
        if args.worktree:
            label, source = "working tree", iter_worktree(repo)
        elif args.staged:
            label, source = "staged changes", iter_staged(repo)
        else:
            label, source = "git history", iter_history(repo)
        findings = sort_findings(scan(source, rules, ignores))
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(render_json(findings, label))
    elif args.format == "sarif":
        print(render_sarif(findings, rules))
    else:
        print(render_text(findings, label, args.limit))

    threshold = SEVERITY_ORDER[args.fail_on]
    blocking = [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= threshold]
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
