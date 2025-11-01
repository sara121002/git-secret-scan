import re
import argparse, subprocess, math, json, pathlib, sys
from collections import Counter

ap = argparse.ArgumentParser()
ap.add_argument("--repo", required=True)
ap.add_argument("--n", type=int, default=50)
ap.add_argument("--out", default="report.json")
args = ap.parse_args()

def run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if r.returncode != 0: raise RuntimeError(r.stdout)
    return r.stdout

def get_commits(repo, n):
    out = run(["git", "log", f"-n{n}", "--pretty=%H"], cwd=repo)
    return [l.strip() for l in out.splitlines() if l.strip()]

def get_msg(repo, commit):
    return run(["git", "log", "-1", "--pretty=%B", commit], cwd=repo)

def get_diff(repo, commit):
    # unified=0 gives exact added-line numbers
    return run(["git", "show", "--unified=0", commit], cwd=repo)

HUNK = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
FILE = re.compile(r"^\+\+\+ b/(.+)$")
DIFF = re.compile(r"^diff --git a/(.+?) b/(.+)$")

def iter_added(diff_text):
    cur_file, line_no = None, None
    for line in diff_text.splitlines():
        m = DIFF.match(line)
        if m: cur_file = m.group(2); continue
        m = FILE.match(line)
        if m: cur_file = m.group(1); continue
        m = HUNK.search(line)
        if m:
            start = int(m.group(1))
            line_no = start
            continue
        if line.startswith("+") and not line.startswith("+++ "):
            if cur_file is not None and line_no is not None:
                yield cur_file, line_no, line[1:]
                line_no += 1
        elif not line.startswith("@@") and line_no is not None:
            # context line: advance new-side counter
            line_no += 1
PATTERNS = [
    (r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", "private_key"),
    (r"(A3T|AKIA|ASIA)[0-9A-Z]{16}", "aws_access_key_id"),
    (r"ghp_[0-9A-Za-z]{36}", "github_token"),
    (r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*([A-Za-z0-9_\-/.+=]{12,})", "generic_secret_kv"),
]

def regex_findings(text):
    out=[]
    for pat, typ in PATTERNS:
        for m in re.finditer(pat, text):
            out.append({"type": typ, "method":"regex",
                        "match": m.group(0),
                        "snippet": text.strip()[:200]})
    return out

def entropy(s):
        c = Counter(s)
        n = len(s)
        return -sum((v/n)*math.log2(v/n) for v in c.values())

def entropy_candidates(text):
    out=[]
    for token in re.findall(r"[A-Za-z0-9_\-/+=]{20,}", text):
        if entropy(token) >= 4.0:
            out.append({"type":"high_entropy_candidate","method":"entropy",
                        "match": token, "snippet": text.strip()[:200]})
    return out

def scan_commit(repo, commit):
    items=[]
    msg = get_msg(repo, commit)
    for f in regex_findings(msg)+entropy_candidates(msg):
        items.append({"commit":commit,"file":None,"line":None,"context":"commit_message",**f})

    diff = get_diff(repo, commit)
    for path, ln, txt in iter_added(diff):
        for f in regex_findings(txt)+entropy_candidates(txt):
            items.append({"commit":commit,"file":path,"line":ln,"context":"added_line",**f})
    return items

    
def main():
    # ... argparse as before
    commits = get_commits(args.repo, args.n)
    findings=[]
    for c in commits:
        findings.extend(scan_commit(args.repo, c))

    # add simple rationale/confidence
    for f in findings:
        f["rationale"] = "Heuristic (regex/entropy). Needs review."
        f["confidence"] = 0.6 if f["method"]=="regex" else 0.5

    report = {"repo": args.repo, "commits_scanned": len(commits), "llm":"none",
            "findings":[
            {"commit":f["commit"],"file":f["file"],"line":f["line"],
            "finding_type":f["type"],"context":f["context"],
            "snippet":f["snippet"],"match_sample":(f["match"][:60] if isinstance(f["match"],str) else None),
            "rationale":f["rationale"],"confidence":f["confidence"],"method":f["method"]}
            for f in findings
        ]}
    pathlib.Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Findings: {len(report['findings'])}. Report: {args.out}")

if __name__ == "__main__":
    main()


