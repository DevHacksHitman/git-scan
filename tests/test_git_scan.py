"""Tests for git_scan.

Every fake secret below is assembled at runtime (string concatenation) rather
than written literally, so this repository passes its own scan — the same
self-avoidance rule the pre-push hook and the private-key pattern use.
"""

import ast
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import git_scan as hs

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "git_scan.py"


# --- runtime-built fixtures (never literal in this file) --------------------
AWS_KEY = "AKIA" + "Q" * 16
GITHUB_TOKEN = "ghp_" + "b" * 40
SLACK_TOKEN = "xoxb-" + "9" * 12
GOOGLE_KEY = "AIza" + "c" * 35
STRIPE_KEY = "sk_live_" + "d" * 24
JWT = "eyJ" + "a" * 10 + "." + "b" * 10 + "." + "c" * 10
PEM_HEADER = "-" * 5 + "BEGIN RSA PRIV" + "ATE KEY" + "-" * 5
EMAIL = "someone" + "@" + "example" + ".com"
NG_PHONE = "080" + "3" * 8
CRED_LINE = 'api_key = "' + "e" * 20 + '"'
ENTROPY_BLOB = "Qw3" + "Er5" + "Ty7" + "Ui9" + "Op1s" + "Df6" + "Gh8" + "Kj2"
HEX_DIGEST = "a1b2c3d4" * 8


def diff_text(*added_lines, path="src/config.py", commit="a" * 40):
    body = "\n".join("+" + line for line in added_lines)
    author = "Author: Dev <dev" + "@" + "noreply.invalid>\n"
    return (
        f"commit {commit}\n"
        f"{author}"
        f"\n"
        f"    add config\n\n"
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -0,0 +1,{len(added_lines)} @@\n"
        f"{body}\n"
    )


class TestRedaction(unittest.TestCase):
    def test_short_value_is_fully_masked(self):
        self.assertEqual(hs.redact("abc"), "***")

    def test_long_value_keeps_only_a_prefix_and_length(self):
        secret = "AKIA" + "Q" * 16
        masked = hs.redact(secret)
        self.assertTrue(masked.startswith("AKIA"))
        self.assertIn("20 chars", masked)
        self.assertNotIn("Q" * 5, masked)


class TestEntropy(unittest.TestCase):
    def test_empty_and_uniform(self):
        self.assertEqual(hs.shannon_entropy(""), 0.0)
        self.assertEqual(hs.shannon_entropy("aaaa"), 0.0)

    def test_two_symbols(self):
        self.assertAlmostEqual(hs.shannon_entropy("abab"), 1.0)

    def test_high_entropy_blob(self):
        self.assertGreaterEqual(hs.shannon_entropy(ENTROPY_BLOB), hs.ENTROPY_THRESHOLD)


class TestRuleDetection(unittest.TestCase):
    def codes(self, line):
        return sorted(rule.id for rule, _ in hs.scan_line(line))

    def test_credential_shapes(self):
        self.assertIn("aws-access-key-id", self.codes(f"key = {AWS_KEY}"))
        self.assertIn("github-token", self.codes(f"token: {GITHUB_TOKEN}"))
        self.assertIn("slack-token", self.codes(SLACK_TOKEN))
        self.assertIn("google-api-key", self.codes(GOOGLE_KEY))
        self.assertIn("stripe-secret", self.codes(STRIPE_KEY))
        self.assertIn("jwt", self.codes(JWT))
        self.assertIn("private-key-header", self.codes(PEM_HEADER))

    def test_personal_data(self):
        self.assertIn("email-address", self.codes(f"contact {EMAIL}"))
        self.assertIn("ng-phone", self.codes(f"call {NG_PHONE}"))

    def test_credential_assignment(self):
        self.assertIn("credential-assignment", self.codes(CRED_LINE))

    def test_entropy_hit(self):
        self.assertIn("high-entropy-string", self.codes(f'value = "{ENTROPY_BLOB}"'))

    def test_entropy_survives_the_rule_filter(self):
        """Entropy hits must not be dropped by the active-rule filter."""
        findings = hs.scan([(None, "a.py", 1, 'v = "' + ENTROPY_BLOB + '"')], hs.DEFAULT_RULES)
        self.assertIn("high-entropy-string", [f.rule for f in findings])

    def test_hex_digest_is_not_entropy_flagged(self):
        self.assertNotIn("high-entropy-string", self.codes(f'sha = "{HEX_DIGEST}"'))

    def test_ordinary_code_is_clean(self):
        for line in (
            "def calculate_total(items):",
            "    return sum(item.price for item in items)",
            "password_field = None",
            "AWS_REGION = 'eu-west-1'",
        ):
            self.assertEqual(self.codes(line), [], line)


class TestRulesLoading(unittest.TestCase):
    def write(self, payload):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "rules.json"
        path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
        return path

    def test_defaults_only(self):
        self.assertEqual(len(hs.load_rules()), len(hs.DEFAULT_RULES))

    def test_extra_rule_list_form(self):
        rules = hs.load_rules(str(self.write([{"id": "acme", "pattern": "ACME-[0-9]{4}", "severity": "high"}])))
        self.assertEqual(rules[-1].id, "acme")

    def test_extra_rule_object_form(self):
        rules = hs.load_rules(str(self.write({"rules": [{"id": "x", "pattern": "X", "severity": "low"}]})))
        self.assertEqual(rules[-1].id, "x")

    def test_custom_rule_actually_detects(self):
        """The audit's Blocker 2: loading a rule is not the same as matching it."""
        rules = hs.load_rules(str(self.write(
            [{"id": "acme", "pattern": "ACME-[0-9]{6}", "severity": "high"}]
        )))
        hits = hs.scan_line("ref ACME-123456 here", rules)
        self.assertEqual([rule.id for rule, _ in hits], ["acme"])

        findings = hs.scan([(None, "ref.py", 1, "ref ACME-123456 here")], rules)
        self.assertEqual([f.rule for f in findings], ["acme"])

    def test_bad_severity_and_json_and_shape(self):
        for payload in (
            [{"id": "x", "pattern": "y", "severity": "critical"}],
            "{not json",
            {"rules": {"nope": True}},
        ):
            with self.assertRaises(hs.ScanError):
                hs.load_rules(str(self.write(payload)))

    def test_missing_file(self):
        with self.assertRaises(hs.ScanError):
            hs.load_rules("/nonexistent/rules.json")


class TestCustomRuleCli(unittest.TestCase):
    def test_custom_rules_file_flags_a_commit_ready_file(self):
        import tempfile, subprocess
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
            (repo / "ref.py").write_text("ref ACME-123456\n", encoding="utf-8")
            rules = repo / "rules.json"
            rules.write_text(
                '{"rules":[{"id":"acme","pattern":"ACME-[0-9]{6}","severity":"high"}]}',
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--repo", str(repo),
                 "--worktree", "--rules", str(rules)],
                capture_output=True, text=True, cwd=str(ROOT), timeout=120,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("acme", result.stdout)


class TestDiffParsing(unittest.TestCase):
    def test_tracks_commit_path_and_line(self):
        text = diff_text("first", "second", path="src/app.py", commit="b" * 40)
        parsed = list(hs.parse_unified_diff(text))
        self.assertEqual([p[0] for p in parsed], ["b" * 40] * 2)
        self.assertEqual([p[1] for p in parsed], ["src/app.py"] * 2)
        self.assertEqual([p[2] for p in parsed], [1, 2])
        self.assertEqual([p[3] for p in parsed], ["first", "second"])

    def test_removed_lines_are_not_scanned(self):
        text = diff_text("kept", path="f.py")
        text += "@@ -5 +5 @@\n-removed line\n+added line\n"
        contents = [p[3] for p in hs.parse_unified_diff(text)]
        self.assertEqual(contents, ["kept", "added line"])


class TestIgnores(unittest.TestCase):
    def test_default_patterns_and_extra(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / hs.IGNORE_FILE).write_text("# comment\nsecrets/*\n\n", encoding="utf-8")
            patterns = hs.load_ignores(repo, ["*.log"])
        self.assertIn("*.log", patterns)
        self.assertIn("secrets/*", patterns)
        self.assertIn("package-lock.json", patterns)

    def test_is_ignored_matches_path_and_basename(self):
        self.assertTrue(hs.is_ignored("a/b/package-lock.json", hs.DEFAULT_IGNORES))
        self.assertTrue(hs.is_ignored("node_modules/pkg/index.js", hs.DEFAULT_IGNORES))
        self.assertFalse(hs.is_ignored("src/main.py", hs.DEFAULT_IGNORES))

    def test_scan_skips_ignored_paths(self):
        source = [(None, "package-lock.json", 1, AWS_KEY), (None, "src/a.py", 1, AWS_KEY)]
        findings = hs.scan(source, hs.RULES, hs.DEFAULT_IGNORES)
        self.assertEqual([f.path for f in findings], ["src/a.py"])


class TestScanAndRender(unittest.TestCase):
    def test_scan_reports_metadata_and_redacts(self):
        source = [(("c" * 40), "src/keys.py", 7, f"token = {GITHUB_TOKEN}")]
        findings = hs.scan(source, hs.RULES)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual((finding.rule, finding.path, finding.line), ("github-token", "src/keys.py", 7))
        self.assertEqual(finding.commit, "c" * 40)
        self.assertNotIn("b" * 10, finding.redacted)

    def test_sorting_is_by_severity_then_path(self):
        source = [
            (None, "z.py", 1, EMAIL),
            (None, "a.py", 1, AWS_KEY),
            (None, "b.py", 1, JWT),
        ]
        ordered = hs.sort_findings(hs.scan(source, hs.RULES))
        self.assertEqual([f.path for f in ordered], ["a.py", "b.py", "z.py"])

    def test_text_pass_and_fail(self):
        self.assertIn("PASS", hs.render_text([], "git history"))
        findings = hs.scan([(None, "a.py", 1, AWS_KEY)], hs.RULES)
        text = hs.render_text(findings, "git history")
        self.assertIn("FINDINGS — 1", text)
        self.assertIn("aws-access-key-id", text)
        self.assertIn("high=1", text)

    def test_text_truncates(self):
        source = [(None, f"f{i}.py", 1, AWS_KEY) for i in range(5)]
        text = hs.render_text(hs.sort_findings(hs.scan(source, hs.RULES)), "x", limit=2)
        self.assertIn("3 more", text)

    def test_json_shape(self):
        findings = hs.scan([(None, "a.py", 3, AWS_KEY)], hs.RULES)
        payload = json.loads(hs.render_json(findings, "git history"))
        self.assertEqual(payload["tool"], "GitScan")
        self.assertEqual(payload["summary"]["total"], 1)
        self.assertEqual(payload["summary"]["by_severity"]["high"], 1)
        self.assertEqual(payload["findings"][0]["path"], "a.py")

    def test_sarif_shape(self):
        findings = hs.scan([(None, "a.py", 3, AWS_KEY)], hs.RULES)
        sarif = json.loads(hs.render_sarif(findings, hs.RULES))
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["results"][0]["ruleId"], "aws-access-key-id")
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "aws-access-key-id")


class TestCli(unittest.TestCase):
    def make_repo(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = Path(tmp.name)
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        test_email = "t" + "@" + "noreply.invalid"
        subprocess.run(["git", "-C", str(repo), "config", "user.email", test_email], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "T"], check=True)
        return repo

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            capture_output=True, text=True, cwd=str(ROOT), timeout=120,
        )

    def test_clean_repo_exits_zero(self):
        repo = self.make_repo()
        (repo / "main.py").write_text("print('hello')\n", encoding="utf-8")
        result = self.run_cli("--repo", str(repo), "--worktree")
        self.assertEqual(result.returncode, 0)
        self.assertIn("PASS", result.stdout)

    def test_staged_secret_exits_one(self):
        repo = self.make_repo()
        (repo / "config.py").write_text(f"token = {GITHUB_TOKEN}\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "config.py"], check=True)
        result = self.run_cli("--repo", str(repo), "--staged")
        self.assertEqual(result.returncode, 1)
        self.assertIn("github-token", result.stdout)

    def test_history_mode_finds_committed_secret(self):
        repo = self.make_repo()
        (repo / "a.py").write_text(f"key = '{AWS_KEY}'\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "add"], check=True)
        (repo / "a.py").write_text("clean\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "commit", "-aqm", "remove"], check=True)
        result = self.run_cli("--repo", str(repo), "--history")
        self.assertEqual(result.returncode, 1)
        self.assertIn("aws-access-key-id", result.stdout)

    def test_fail_on_high_ignores_low_findings(self):
        repo = self.make_repo()
        (repo / "notes.md").write_text(f"contact: {EMAIL}\n", encoding="utf-8")
        self.assertEqual(self.run_cli("--repo", str(repo), "--worktree").returncode, 1)
        self.assertEqual(
            self.run_cli("--repo", str(repo), "--worktree", "--fail-on", "high").returncode, 0
        )

    def test_json_and_sarif_outputs_parse(self):
        repo = self.make_repo()
        line = "sec" + "ret = '" + STRIPE_KEY + "'\n"
        (repo / "cfg.py").write_text(line, encoding="utf-8")
        for fmt in ("json", "sarif"):
            result = self.run_cli("--repo", str(repo), "--worktree", "--format", fmt)
            self.assertEqual(result.returncode, 1)
            json.loads(result.stdout)

    def test_not_a_git_repo_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_cli("--repo", tmp, "--history")
        self.assertEqual(result.returncode, 2)
        self.assertIn("not a git repository", result.stderr)

    def test_main_in_process(self):
        repo = self.make_repo()
        (repo / "x.py").write_text("clean = True\n", encoding="utf-8")
        self.assertEqual(hs.main(["--repo", str(repo), "--worktree"]), 0)


class TestSelfScan(unittest.TestCase):
    """This tool must not flag its own repository."""

    def test_working_tree_is_clean(self):
        ignores = hs.load_ignores(ROOT)
        findings = hs.scan(hs.iter_worktree(ROOT), hs.RULES, ignores)
        self.assertEqual(findings, [], f"self-scan findings: {[f.as_dict() for f in findings]}")

    def test_git_history_is_clean(self):
        ignores = hs.load_ignores(ROOT)
        findings = hs.scan(hs.iter_history(ROOT), hs.RULES, ignores)
        self.assertEqual(findings, [], f"self-scan findings: {[f.as_dict() for f in findings]}")


class TestZeroDependencies(unittest.TestCase):
    def test_only_standard_library_imports(self):
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
        external = sorted(n for n in names if n not in sys.stdlib_module_names)
        self.assertEqual(external, [], f"third-party imports found: {external}")


if __name__ == "__main__":
    unittest.main()
