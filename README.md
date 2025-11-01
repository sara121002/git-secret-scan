# git-secret-scan
A lightweight Python tool that scans the last N commits of a Git repository for possible secrets (like API keys, passwords, or private keys) using simple heuristics, regex patterns and entropy analysis.

# Features

Scans:

Added lines in recent commits

Commit messages

Detects secrets using:

Regex rules (e.g., AWS, GitHub, API_KEY, PRIVATE KEY)

Entropy analysis (flags random-looking tokens)

Generates a single JSON report containing:

Commit hash

File path

Line number

Snippet of suspicious text

Detection method and confidence

Simple rationale

Optional: extendable with LLM (AI) rescoring for smarter classification.

# Example Usage
Scan current repo, last 15 commits

python scan.py --repo . --n 15 --out report.json

# Output example (report.json):
{
  "repo": ".",
  "commits_scanned": 3,
  "llm": "none",
  "findings": []
}

# Requirements
Python 3.9+

Git installed and available in your system path

(Optional) OpenAI API key for LLM rescoring

# Optional: Enable LLM rescoring

You can extend the script to use an LLM (like OpenAI GPT) to validate findings and reduce false positives.

# Example:
export OPENAI_API_KEY="sk-xxxx"
python scan.py --repo . --n 10 --out report.json --llm gpt

This will add:

A short AI-generated rationale for each finding

An estimated confidence score

Optional llm_label field (secret, likely_secret, not_secret)

# Example Report (LLM enabled)

{
  "commit": "a1b2c3d",
  "file": "config/settings.py",
  "line": 42,
  "finding_type": "generic_secret_kv",
  "context": "added_line",
  "snippet": "API_KEY = 'sk-12345abcdef...'",
  "rationale": "Looks like an API key assignment.",
  "confidence": 0.87,
  "method": "regex",
  "llm_label": "likely_secret"
}
