import argparse, subprocess, textwrap

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
