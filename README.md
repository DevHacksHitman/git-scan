# GitScan

A **zero-dependency** secrets and sensitive-data scanner for git repositories.

It scans the whole commit history, the staged change about to be committed, or
the working tree — and it **redacts every match it reports**, because a scanner
that prints the secret it found has just leaked it into your CI log.

| | |
|---|---|
| Dependencies | **0** — standard library only |
| Code | **1 file**, 463 lines (380 logic) |
| Tests | **37**, zero-network, no packages installed in CI |
| Sources | git history (all refs) · staged changes · working tree |
| Detectors | credential shapes · PEM private keys · personal data · high-entropy strings |
| Outputs | text (redacted) · `--format json` · `--format sarif` |
| Exit codes | `0` clean · `1` findings at/above `--fail-on` · `2` usage error |

## Why this exists

Most secrets are not leaked by an attacker. They are leaked by a `git add` —
and once committed, they live in history until the credential is rotated and the
history is rewritten. A scanner is useful only if it runs **before** the push
and reports findings that are actionable but not exploitable.

That is the design here: findings are redacted to a prefix and a length, the
exit code is CI-friendly, and SARIF output drops straight into a code-scanning
pipeline.

## Quickstart

```bash
# whole history of the current repository (all branches)
python3 git_scan.py

# just what you are about to commit
python3 git_scan.py --staged

# files on disk
python3 git_scan.py --worktree --fail-on high

# machine-readable, and pipeline-native
python3 git_scan.py --format json
python3 git_scan.py --format sarif
```

Example output:

```
FINDINGS — 2 in git history

  [  high] github-token: src/config.py:12 @a1b2c3d4
           GitHub token — ghpx*********** (44 chars)
  [  low] email-address: docs/notes.md:3 @a1b2c3d4
           Email address (personal data) — some*********** (19 chars)

Summary: high=1, low=1
```

The secret itself is never printed. The prefix is enough to find the line; the
length is enough to tell a rotated key from the one in use.

## Detectors

| Rule | Severity | Matches |
|---|---|---|
| `private-key-header` | high | PEM private key blocks |
| `aws-access-key-id` | high | AWS access key IDs |
| `github-token` | high | GitHub tokens (all prefixes) |
| `slack-token` | high | Slack tokens |
| `google-api-key` | high | Google API keys |
| `stripe-secret` | high | Stripe live secret keys |
| `jwt` | medium | JSON Web Tokens |
| `credential-assignment` | medium | hard-coded `key`/`secret`/`token`/`password` assignments |
| `high-entropy-string` | medium | 24+ character runs above 4.5 bits/char of entropy (hex digests excluded) |
| `email-address` | low | email addresses (personal data) |
| `ng-phone` | low | Nigerian mobile numbers (personal data) |

Extra rules come from a JSON file:

```json
{"rules": [{"id": "acme-internal", "description": "Acme key", "severity": "high", "pattern": "ACME-[0-9]{6}"}]}
```

## Ignoring files

`node_modules`, lockfiles, build output and binary/media types are ignored by
default. Add your own in `.gitscan-ignore` (one glob per line, `#` for
comments), or with `--exclude 'snapshots/*'`.

## Design decisions

- **Redaction, not reporting.** A finding shows four characters and a length;
  never the value. This is the difference between a useful tool and a liability.
- **Zero dependencies on purpose.** A secrets scanner that installs a dependency
  tree introduces supply-chain risk in the exact place you are reducing it.
- **Self-avoidance by construction.** This file's rules are written so the file
  cannot match itself (the PEM header is assembled from parts at runtime), and
  two tests scan this repository with this tool and assert **zero findings**.
  Without that, a scanner flags its own source forever and gets disabled.
- **`--fail-on` separates signal from noise.** Personal-data hits are `low`, so
  `--fail-on high` gates a build on credentials without failing it on an email
  address in a changelog.
- **SARIF output** so it composes with existing code-scanning dashboards instead
  of requiring a bespoke report renderer.

## Honest limitations

- **Pattern matching, not data-flow analysis.** It finds credential *shapes*. A
  secret assembled at runtime, encoded, or split across lines is not detected.
  For production pipelines, pair this with a mature tool (gitleaks,
  truffleHog) — this is a demonstrator of the technique, not a replacement.
- **Entropy scanning has false positives and false negatives.** Base64 blobs
  with high entropy are flagged even when harmless; short keys are missed. The
  24-character / 4.5-bit thresholds are deliberately conservative.
- **The email rule is noisy** on documentation. That is why it is `low` severity
  and why `--fail-on high` exists.
- **History mode reads `git log -p --all`**, which is expensive on very large
  repositories; there is no incremental state between runs yet.
- **No `.gitscan-ignore` in history mode by path only** — a file ignored
  today is still scanned in the commits where it appears, because the path
  matched is the path at that commit.
- **It does not rotate anything.** If it finds a live credential: rotate first,
  then purge history, then prevent recurrence with a pre-push gate — in that
  order, because until the credential is rotated the rest is cosmetic.

## Tests

```bash
python3 -m unittest discover -s tests -t . -v
```

37 tests, zero network: every detector, redaction, entropy maths, diff parsing,
ignore handling, all three output formats, the CLI exit codes against real
temporary git repositories, the self-scan assertions, and an AST test proving
the tool imports only the standard library.

Note: every fake secret in the test suite is assembled at runtime by string
concatenation rather than written literally — otherwise the test data would trip
the scanner's own self-scan, which is exactly the trap this design avoids.

## Repository hygiene

- Commits use the GitHub noreply identity; no personal addresses in history.
- `githooks/pre-push` is a blocking sensitivity gate. Enable it once per clone:

      git config core.hooksPath githooks

  Its needles are written self-avoidantly (character-class breaks) so the hook
  can never match its own source and block every push forever.

## Roadmap

- Incremental scanning (remember the last scanned commit).
- `--baseline` file so existing findings can be grandfathered while new ones fail.
- Optional `--redact-output-file` for a compliance-safe findings export.
- A GitHub Action wrapper so the scanner runs on every pull request.

## License

MIT — see `LICENSE`.
