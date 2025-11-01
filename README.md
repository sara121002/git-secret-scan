# 🔍 git-secret-scan

A Python-based security tool that scans Git repositories for secrets and sensitive data using a combination of LLM analysis, pattern matching, and entropy detection.

## 🌟 Features

### Detection Methods

- **Pattern Matching** - Recognizes common secret patterns:
  - Private keys (RSA, EC, DSA, OpenSSH)
  - AWS credentials (Access Key IDs)
  - GitHub tokens
  - Generic API keys and secrets
- **Entropy Analysis** - Identifies high-entropy strings that might be encoded secrets
- **LLM Validation** - Optional GPT-3.5-turbo powered analysis to reduce false positives

### Scanning Scope

- Analyzes the last N commits in a repository
- Examines both added lines and commit messages
- Provides line-precise locations of findings

## 🚀 Quick Start

1. **Install Dependencies**

```bash
pip install -r requirements.txt
```

2. **Basic Scan** (Pattern matching & entropy only)

```bash
python scan.py --repo . --n 5 --out report.json --llm none
```

3. **Advanced Scan** (With LLM validation)

```bash
# Set your OpenAI API key first
set OPENAI_API_KEY=sk-your-key-here  # Windows
export OPENAI_API_KEY=sk-your-key-here  # Linux/Mac

# Run scan with LLM validation
python scan.py --repo . --n 5 --out report.json --llm gpt-3.5-turbo
```

## 💻 Command-Line Options

```bash
python scan.py [options]

Options:
  --repo PATH          Path to Git repository to scan
  --n NUMBER          Number of recent commits to analyze (default: 50)
  --out FILE          Output JSON report path (default: report.json)
  --llm MODEL         LLM model to use (choices: gpt-3.5-turbo, none)
```

## 📊 Output Format

The tool generates a detailed JSON report:

```json
{
  "repo": ".",
  "commits_scanned": 5,
  "llm": "gpt-3.5-turbo",
  "findings": [
    {
      "commit": "abc123...",
      "file": "config.py",
      "line": 42,
      "finding_type": "generic_secret_kv",
      "context": "added_line",
      "snippet": "API_KEY = 'secret123'",
      "rationale": "Variable name and pattern suggest an API key",
      "confidence": 0.95,
      "method": "regex"
    }
  ]
}
```

## 🎯 Example Detections

1. **API Keys in Config Files**

```python
API_KEY = "sk-1234567890abcdef"
SECRET_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz"
```

2. **AWS Credentials**

```python
aws_access_key_id = "AKIAXXXXXXXXXXXXXXXX"
```

3. **Private Keys**

```
-----BEGIN RSA PRIVATE KEY-----
...
```

4. **High-Entropy Strings** (potential encoded secrets)

```python
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## 📋 Requirements

- Python 3.9 or higher
- Git installed and in system PATH
- For LLM validation:
  - OpenAI API key
  - Internet connection

## 🛡️ Security Note

- The tool may produce false positives
- Always review findings manually
- Consider using `--llm gpt-3.5-turbo` for better accuracy when possible
- The tool does NOT upload your code to OpenAI - only suspicious snippets are sent for validation
