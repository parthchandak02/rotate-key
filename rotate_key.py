#!/usr/bin/env python3
"""rotate-key: find every copy of every API key on this machine, check which still work,
replace one everywhere in a single step, and catch the habits that leak keys.

  rotate-key                       list every secret, its copies, and whether it still works
  rotate-key NAME                  rotate NAME: prompt (hidden), verify, replace every copy, restart services
  rotate-key NAME --dry-run        show what a rotation would touch
  rotate-key check [NAME]          only run the provider checks
  rotate-key doctor [--fix]        machine hygiene: file permissions, git, iCloud, shell history, ssh, firewall

Config (optional): ~/.config/rotate-key/config.toml. See config.example.toml.
Keys are only ever sent to their own provider, and only to check that they work.
Standard library only; Python 3.11+.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import glob
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

HOME = Path.home()
CONFIG = HOME / ".config/rotate-key/config.toml"
STATE = HOME / ".local/state/rotate-key"

DEFAULTS = {
    "roots": ["~"],                       # searched for .env files
    "depth": 6,
    "extra_files": [],                    # non-.env files that may hold copies (CLI configs etc.)
    "skip_dirs": ["node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".next",
                  "Library", ".Trash", ".cache", ".npm", ".cargo", ".rustup", "go", ".pyenv", ".nvm"],
    "backup_dirs": ["state-snapshots", "backups", "backup"],   # copies here are reported, not rewritten
    "restart": {"launchd": [], "pm2": "auto", "commands": []},
    "checks": {},
}
SECRET_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|AUTH|CREDENTIAL|PRIVATE)")
NOT_SECRET = re.compile(r"(_URL|_URI|_PATH|_FILE|_DIR|_HOST|_PORT|_ID|_USERNAME|_USER|_EMAIL|_MODEL|_REGION)$")
ENV_LINE = re.compile(r"^(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*)$")

# Built-in checks. name pattern -> (method, url, headers, ok-test). {k} is the key.
# Each check uses a free, read-only endpoint of the key's own provider.
BUILTIN = [
    (r"^HEVY", "GET", "https://api.hevyapp.com/v1/workouts/count", {"api-key": "{k}"}, None),
    (r"^(GEMINI|GOOGLE_AI|GOOGLE_API)", "GET", "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1", {"x-goog-api-key": "{k}"}, None),
    (r"^OPENAI", "GET", "https://api.openai.com/v1/models", {"Authorization": "Bearer {k}"}, None),
    (r"^ANTHROPIC", "GET", "https://api.anthropic.com/v1/models", {"x-api-key": "{k}", "anthropic-version": "2023-06-01"}, None),
    (r"^OPENROUTER", "GET", "https://openrouter.ai/api/v1/key", {"Authorization": "Bearer {k}"}, None),
    (r"^(DEEPSEEK|LLM_API_KEY$)", "GET", "https://api.deepseek.com/models", {"Authorization": "Bearer {k}"}, None),
    (r"^FIREWORKS", "GET", "https://api.fireworks.ai/inference/v1/models", {"Authorization": "Bearer {k}"}, None),
    (r"^GROQ", "GET", "https://api.groq.com/openai/v1/models", {"Authorization": "Bearer {k}"}, None),
    (r"^MISTRAL", "GET", "https://api.mistral.ai/v1/models", {"Authorization": "Bearer {k}"}, None),
    (r"^TYPESAFE", "GET", "https://api.typesafe.ai/v1/models", {"Authorization": "Bearer {k}"}, None),
    (r"^(GITHUB|GH)_TOKEN", "GET", "https://api.github.com/user", {"Authorization": "Bearer {k}"}, None),
    (r"^CLOUDFLARE_API_TOKEN", "GET", "https://api.cloudflare.com/client/v4/user/tokens/verify", {"Authorization": "Bearer {k}"}, None),
    (r"^GITGUARDIAN", "GET", "https://api.gitguardian.com/v1/health", {"Authorization": "Token {k}"}, None),
    (r"^SLACK", "POST", "https://slack.com/api/auth.test", {"Authorization": "Bearer {k}"}, '"ok":true'),
    (r"^TELEGRAM_BOT_TOKEN", "GET", "https://api.telegram.org/bot{k}/getMe", {}, '"ok":true'),
    (r"^CURSOR_API_KEY", "GET", "https://api.cursor.com/v0/me", {"Authorization": "Basic {k_basic}"}, None),
    (r"^SEMANTIC_SCHOLAR", "GET", "https://api.semanticscholar.org/graph/v1/paper/search?query=test&limit=1", {"x-api-key": "{k}"}, None),
    (r"^(ELSEVIER|SCOPUS)", "GET", "https://api.elsevier.com/content/search/scopus?query=test&count=1", {"X-ELS-APIKey": "{k}"}, None),
    (r"^CORE_API_KEY", "GET", "https://api.core.ac.uk/v3/search/works?q=test&limit=1", {"Authorization": "Bearer {k}"}, None),
    (r"^(PUBMED|NCBI)", "GET", "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/einfo.fcgi?retmode=json&api_key={k}", {}, None),
    (r"^CAPSOLVER", "POST", "https://api.capsolver.com/getBalance", {"Content-Type": "application/json", "_body": '{{"clientKey":"{k}"}}'}, '"errorId":0'),
]


# ------------------------------------------------------------------ config + discovery

def load_config() -> dict:
    cfg = json.loads(json.dumps(DEFAULTS))
    if CONFIG.exists():
        user = tomllib.loads(CONFIG.read_text())
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    return cfg


def is_env_name(name: str) -> bool:
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def is_template(name: str) -> bool:
    return any(t in name for t in (".example", ".sample", ".template", ".dist"))


def find_files(cfg: dict) -> list[Path]:
    out: set[Path] = set()
    skip = set(cfg["skip_dirs"])
    for root in cfg["roots"]:
        root = Path(os.path.expanduser(root))
        if not root.exists():
            continue
        base = len(root.parts)
        for dp, dn, fn in os.walk(root):
            if Path(dp) == STATE or STATE in Path(dp).parents:
                dn[:] = []
                continue
            depth = len(Path(dp).parts) - base
            dn[:] = [d for d in dn if d not in skip and not (depth >= cfg["depth"])]
            for f in fn:
                if is_env_name(f) and not is_template(f):
                    out.add(Path(dp, f))
    for pattern in cfg["extra_files"]:
        for f in glob.glob(os.path.expanduser(pattern), recursive=True):
            if os.path.isfile(f):
                out.add(Path(f))
    return sorted(out)


def parse_env(path: Path) -> list[tuple[str, str]]:
    pairs = []
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return pairs
    for line in text.splitlines():
        m = ENV_LINE.match(line.strip())
        if not m:
            continue
        name, value = m.group(1), m.group(2).split(" #")[0].strip().strip('"').strip("'")
        if SECRET_NAME.search(name) and not NOT_SECRET.search(name) and looks_secret(value):
            pairs.append((name, value))
    return pairs


def looks_secret(v: str) -> bool:
    if len(v) < 12 or v.startswith(("/", "~", "http", "$", "<", "{")):
        return False
    if re.search(r"(?i)(your|changeme|replace|example|xxxx|placeholder|dummy|test[-_]?key)", v):
        return False
    return True


def fingerprint(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()[:6]


def inventory(cfg: dict):
    """value -> {names, files}. Values are never printed; fingerprints are."""
    files = find_files(cfg)
    secrets: dict[str, dict] = {}
    for f in files:
        for name, value in parse_env(f):
            s = secrets.setdefault(value, {"names": set(), "files": set()})
            s["names"].add(name)
            s["files"].add(f)
    # extra (non-.env) files: only count copies of values already known
    extra = [f for f in files if not is_env_name(f.name)]
    for f in extra:
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        for value, s in secrets.items():
            if value in text:
                s["files"].add(f)
    return secrets


def is_backup(path: Path, cfg: dict) -> bool:
    return any(part in cfg["backup_dirs"] for part in path.parts) or ".bak" in path.name


def short(p) -> str:
    return str(p).replace(str(HOME), "~")


# ------------------------------------------------------------------ provider checks

def find_check(name: str, cfg: dict):
    if name in cfg["checks"]:
        c = cfg["checks"][name]
        hdr = {}
        if "header" in c:
            k, _, v = c["header"].partition(":")
            hdr[k.strip()] = v.strip()
        return (c.get("method", "GET"), c["url"], hdr, c.get("expect"))
    for pat, method, url, hdr, ok in BUILTIN:
        if re.search(pat, name):
            return (method, url, hdr, ok)
    return None


def run_check(name: str, value: str, cfg: dict) -> str:
    spec = find_check(name, cfg)
    if not spec:
        return "no check"
    method, url, hdr, ok = spec
    fill = {"k": value, "k_basic": base64.b64encode(f"{value}:".encode()).decode()}
    headers = {k: v.format(**fill) for k, v in hdr.items() if k != "_body"}
    body = hdr.get("_body", "").format(**fill).encode() or (b"" if method == "POST" else None)
    req = urllib.request.Request(url.format(**fill), data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read(4096).decode(errors="ignore")
            if ok and ok not in text.replace(" ", ""):
                return "REJECTED"
            return "works"
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return "REJECTED"
        detail = e.read(2048).decode(errors="ignore")
        if re.search(r"API_KEY_INVALID|invalid[ _-]?(api[ _-]?)?key|unauthori[sz]ed|expired", detail, re.I):
            return "REJECTED"
        return "out of credit" if e.code == 402 else f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001
        return f"unreachable ({type(e).__name__})"


# ------------------------------------------------------------------ commands

def cmd_list(cfg: dict, only: str | None = None, checks: bool = True):
    secrets = inventory(cfg)
    rows = []
    for value, s in secrets.items():
        names = sorted(s["names"])
        if only and only not in names:
            continue
        live = [f for f in s["files"] if not is_backup(f, cfg)]
        backups = [f for f in s["files"] if is_backup(f, cfg)]
        status = run_check(names[0], value, cfg) if checks else ""
        rows.append((names, fingerprint(value), status, live, backups))
    rows.sort(key=lambda r: (r[0][0], r[1]))
    dupes = defaultdict(int)
    for r in rows:
        dupes[r[0][0]] += 1
    print(f"{'KEY':38} {'ID':6}  {'STATUS':12} COPIES")
    for names, fp, status, live, backups in rows:
        label = "/".join(names)[:38]
        extra = f" +{len(backups)} in backups" if backups else ""
        print(f"{label:38} {fp:6}  {status:12} {len(live)}{extra}  {', '.join(short(f) for f in live)[:100]}")
    multi = [n for n, c in dupes.items() if c > 1]
    print(f"\n{len(rows)} secrets in {len({f for r in rows for f in r[3]})} files.")
    if multi:
        print("Several different values exist for: " + ", ".join(multi) + ". Pick one with --id when rotating.")
    print("Rotate one:  rotate-key NAME   (add --dry-run to preview)")


def restart_services(name: str, new: str, cfg: dict):
    os.environ[name] = new
    uid = os.getuid()
    for label in cfg["restart"].get("launchd", []):
        if subprocess.run(["launchctl", "kickstart", "-k", f"gui/{uid}/{label}"], capture_output=True).returncode == 0:
            print("restarted", label)
    if cfg["restart"].get("pm2") == "auto" and shutil.which("pm2"):
        try:
            procs = json.loads(subprocess.run(["pm2", "jlist"], capture_output=True, text=True, timeout=30).stdout or "[]")
        except Exception:  # noqa: BLE001
            procs = []
        hit = [p["name"] for p in procs if name in (p.get("pm2_env", {}).get("env") or {}) or name in p.get("pm2_env", {})]
        for p in hit:
            subprocess.run(["pm2", "restart", p, "--update-env"], capture_output=True)
            print("restarted pm2", p)
        if hit:
            subprocess.run(["pm2", "save"], capture_output=True)
            for f in glob.glob(str(HOME / ".pm2/dump.pm2*")):
                os.chmod(f, 0o600)
    for cmd in cfg["restart"].get("commands", []):
        subprocess.run(cmd, shell=True)
        print("ran", cmd)


def cmd_rotate(cfg: dict, name: str, dry: bool, pick: str | None):
    secrets = inventory(cfg)
    matches = [(v, s) for v, s in secrets.items()
               if name in s["names"] and any(not is_backup(f, cfg) for f in s["files"])]
    if not matches:
        sys.exit(f"No secret named {name} found. Run `rotate-key` to see what exists.")
    if len(matches) > 1 and not pick:
        print(f"{name} has {len(matches)} different values. Choose one with --id:")
        for v, s in matches:
            print(f"  --id {fingerprint(v)}  {', '.join(short(f) for f in sorted(s['files']))[:110]}")
        sys.exit(1)
    if pick:
        matches = [(v, s) for v, s in matches if fingerprint(v) == pick]
        if not matches:
            sys.exit(f"No {name} with id {pick}.")
    old, s = matches[0]
    live = sorted(f for f in s["files"] if not is_backup(f, cfg))
    backups = sorted(f for f in s["files"] if is_backup(f, cfg))
    print(f"{name} ({fingerprint(old)}): {len(live)} file(s) to update")
    for f in live:
        print("  ", short(f))
    if backups:
        print(f"  ({len(backups)} copies in backup/snapshot folders are left alone; revoke the old key and they're harmless)")
    if dry:
        print("\n--dry-run: nothing changed.")
        return

    new = getpass.getpass(f"New value for {name} (hidden): ").strip()
    if len(new) < 12:
        sys.exit("Too short to be an API key. Nothing changed.")
    if new == old:
        sys.exit("Same as the current value. Nothing changed.")
    status = run_check(name, new, cfg)
    if status == "REJECTED":
        sys.exit(f"The provider rejected the new {name}. Nothing changed.")
    print(f"New key check: {status}")

    stamp = STATE / time.strftime("%Y%m%d-%H%M%S")
    stamp.mkdir(parents=True, exist_ok=True)
    for d in (STATE, stamp):
        os.chmod(d, 0o700)
    for f in live:
        dest = stamp / str(f).lstrip("/").replace("/", "__")
        shutil.copy2(f, dest)
        os.chmod(dest, 0o600)
        mode = f.stat().st_mode
        f.write_text(f.read_text().replace(old, new))
        os.chmod(f, stat.S_IMODE(mode) & 0o600 or 0o600)
        print("updated", short(f))
    restart_services(name, new, cfg)
    print(f"\nDone. Backups of changed files: {short(stamp)} (delete after you've confirmed things work).")
    print("Revoke the old key at the provider, then open a new terminal tab.")


# ------------------------------------------------------------------ doctor

HISTORY_PATTERNS = [
    r"sk-(?:ant-|proj-|or-)?[A-Za-z0-9_\-]{20,}", r"AIza[0-9A-Za-z_\-]{35}", r"gh[pousr]_[A-Za-z0-9]{36}",
    r"xox[baprs]-[A-Za-z0-9\-]{20,}", r"AKIA[0-9A-Z]{16}",
    r"(?i)\b[A-Z_]*(?:API_KEY|TOKEN|SECRET|PASSWORD)\s*=\s*[\"']?[A-Za-z0-9_\-\.]{16,}",
    r"(?i)authorization:\s*bearer\s+[A-Za-z0-9_\-\.]{20,}", r"(?i)(?:api-key|x-api-key)\s*:\s*[A-Za-z0-9_\-]{16,}",
]


def doctor(cfg: dict, fix: bool):
    issues = 0

    def report(level, msg, how=""):
        nonlocal issues
        issues += level in ("warn", "FAIL")
        print(f"[{level:^5}] {msg}" + (f"\n        fix: {how}" if how else ""))

    secrets = inventory(cfg)
    files = sorted({f for s in secrets.values() for f in s["files"]})

    loose = [f for f in files if f.stat().st_mode & 0o077]
    if loose:
        if fix:
            for f in loose:
                os.chmod(f, 0o600)
            report("fixed", f"{len(loose)} secret files were readable by other users; now owner-only")
        else:
            report("warn", f"{len(loose)} secret files are readable by other users: " + ", ".join(short(f) for f in loose[:4]),
                   "rotate-key doctor --fix  (chmod 600)")

    for f in files:
        top = subprocess.run(["git", "-C", str(f.parent), "rev-parse", "--show-toplevel"], capture_output=True, text=True)
        if top.returncode:
            continue
        tracked = subprocess.run(["git", "-C", top.stdout.strip(), "ls-files", "--error-unmatch", str(f)], capture_output=True).returncode == 0
        ignored = subprocess.run(["git", "-C", top.stdout.strip(), "check-ignore", "-q", str(f)], capture_output=True).returncode == 0
        if tracked:
            report("FAIL", f"{short(f)} is committed to git", "git rm --cached it, add to .gitignore, rotate every key in it, rewrite history")
        elif not ignored:
            report("warn", f"{short(f)} is not git-ignored (one `git add -A` from being committed)", "add it to .gitignore")

    icloud = [f for f in files if str(f).startswith((str(HOME / "Desktop"), str(HOME / "Documents"), str(HOME / "Library/Mobile Documents")))]
    if icloud and (HOME / "Library/Mobile Documents/com~apple~CloudDocs/Documents").exists():
        report("warn", f"{len(icloud)} secret files sync to iCloud (Desktop/Documents): " + ", ".join(short(f) for f in icloud[:3]),
               "move them outside Desktop/Documents, or keep the keys in Keychain")

    for rc in [".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile"]:
        p = HOME / rc
        if p.exists():
            n = sum(1 for l in p.read_text(errors="ignore").splitlines()
                    if re.match(r"^\s*(export\s+)?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Z_]*=[^$\s(]{12,}", l))
            if n:
                report("warn", f"~/{rc} hard-codes {n} secret(s)", "load them from Keychain instead (see README)")

    hist = [HOME / h for h in (".zsh_history", ".bash_history", ".python_history", ".node_repl_history", ".psql_history")]
    for h in hist:
        if not h.exists():
            continue
        lines = h.read_bytes().decode(errors="ignore").splitlines(keepends=True)
        bad = [i for i, l in enumerate(lines) if any(re.search(p, l) for p in HISTORY_PATTERNS)]
        if not bad:
            continue
        if fix:
            keep = [l for i, l in enumerate(lines) if i not in set(bad)]
            h.write_text("".join(keep))
            os.chmod(h, 0o600)
            report("fixed", f"removed {len(bad)} line(s) containing secrets from ~/{h.name}")
        else:
            report("warn", f"~/{h.name} has {len(bad)} line(s) with secrets in them",
                   "rotate-key doctor --fix  (then close other terminal tabs so they don't write the lines back)")

    for f in glob.glob(str(HOME / "Library/LaunchAgents/*.plist")):
        try:
            env = subprocess.run(["plutil", "-extract", "EnvironmentVariables", "json", "-o", "-", f], capture_output=True, text=True)
            d = json.loads(env.stdout) if env.returncode == 0 else {}
        except Exception:  # noqa: BLE001
            d = {}
        n = sum(1 for k, v in d.items() if SECRET_NAME.search(k) and looks_secret(str(v)))
        if n:
            report("warn", f"{Path(f).name} has {n} secret(s) in its EnvironmentVariables", "have the job read an env file or Keychain instead")

    gh = HOME / ".config/gh/hosts.yml"
    if gh.exists() and "oauth_token:" in gh.read_text(errors="ignore"):
        report("warn", "GitHub CLI token is stored in plain text (~/.config/gh/hosts.yml)",
               "gh auth logout && gh auth login   (stores it in Keychain)")
    for k in glob.glob(str(HOME / ".ssh/id_*")):
        if k.endswith(".pub"):
            continue
        if subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", k], capture_output=True).returncode == 0:
            report("warn", f"SSH key {short(k)} has no passphrase",
                   f"ssh-keygen -p -f {short(k)}  then add  UseKeychain yes / AddKeysToAgent yes  to ~/.ssh/config")
    for f in (".git-credentials", ".netrc"):
        if (HOME / f).exists():
            report("warn", f"~/{f} stores passwords in plain text", "delete it and use the macOS keychain credential helper")

    if sys.platform == "darwin":
        fv = subprocess.run(["fdesetup", "status"], capture_output=True, text=True).stdout
        report("ok" if "On" in fv else "FAIL", "FileVault " + ("on" if "On" in fv else "OFF"),
               "" if "On" in fv else "System Settings > Privacy & Security > FileVault")
        sf = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        fw_on = "enabled" in subprocess.run([sf, "--getglobalstate"], capture_output=True, text=True).stdout
        if fw_on:
            report("ok", "macOS firewall on")
        else:
            report("warn", "macOS firewall is off", f"sudo {sf} --setglobalstate on")
        net = subprocess.run(["netstat", "-an", "-p", "tcp"], capture_output=True, text=True).stdout
        ssh_on = re.search(r"\*\.22\s.*LISTEN", net)
        if ssh_on:
            ak = HOME / ".ssh/authorized_keys"
            n = sum(1 for l in ak.read_text().splitlines() if l.strip() and not l.startswith("#")) if ak.exists() else 0
            report("info", f"Remote Login (SSH) is on, {n} key(s) allowed in ~/.ssh/authorized_keys",
                   "fine if you use it; keep authorized_keys to keys you recognise, and prefer reaching it over a VPN")
        if re.search(r"\*\.(5900|3283)\s.*LISTEN", net):
            report("info", "Screen Sharing / Remote Management is on", "fine if you use it; turn it off in System Settings > General > Sharing if not")
        ls = subprocess.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], capture_output=True, text=True).stdout.splitlines()[1:]
        wide = {}
        for l in ls:
            parts = l.split()
            if len(parts) > 8 and re.search(r"^(\*|0\.0\.0\.0|\[::\]):\d+$", parts[8]):
                wide[f"{parts[0]}:{parts[8].rsplit(':', 1)[-1]}"] = parts[1]
        if wide and not fw_on:
            report("warn", f"{len(wide)} services accept connections from your network: {', '.join(sorted(wide)[:8])}",
                   "turn the firewall on, and bind dev servers to 127.0.0.1")
        elif wide:
            apps = subprocess.run([sf, "--listapps"], capture_output=True, text=True).stdout
            exposed = []
            for name, pid in sorted(wide.items()):
                exe = subprocess.run(["ps", "-o", "comm=", "-p", pid], capture_output=True, text=True).stdout.strip()
                signed = "Authority=" in subprocess.run(["codesign", "-dvv", exe], capture_output=True, text=True).stderr
                if signed or any(seg and seg in apps for seg in (exe, exe.split("/Contents/")[0])):
                    exposed.append(name)
            if exposed:
                report("info", f"firewall lets {len(exposed)} listening service(s) through: {', '.join(exposed[:8])}",
                       "expected for things devices on your network use; remove others with socketfilterfw --remove")
            blocked = len(wide) - len(exposed)
            if blocked:
                report("ok", f"firewall blocks outside connections to {blocked} other listening service(s)")

    print(f"\n{issues} issue(s)." + ("" if fix else " Run `rotate-key doctor --fix` for the ones marked fixable."))


# ------------------------------------------------------------------ main

def main():
    argv = sys.argv[1:]
    if argv and argv[0] not in ("list", "check", "doctor", "rotate", "-h", "--help") and not argv[0].startswith("-"):
        argv = ["rotate"] + argv
    ap = argparse.ArgumentParser(prog="rotate-key", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list", help="list every secret, its copies and status (default)").add_argument("--no-check", action="store_true")
    c = sub.add_parser("check", help="run provider checks")
    c.add_argument("name", nargs="?")
    r = sub.add_parser("rotate", help="replace a key everywhere")
    r.add_argument("name")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--id", help="which value, when a name has several (from `rotate-key list`)")
    d = sub.add_parser("doctor", help="machine hygiene checks")
    d.add_argument("--fix", action="store_true", help="chmod loose files, scrub secrets from shell history")
    a = ap.parse_args(argv)
    cfg = load_config()
    if a.cmd in (None, "list"):
        cmd_list(cfg, checks=not getattr(a, "no_check", False))
    elif a.cmd == "check":
        cmd_list(cfg, only=a.name)
    elif a.cmd == "rotate":
        cmd_rotate(cfg, a.name.upper(), a.dry_run, a.id)
    elif a.cmd == "doctor":
        doctor(cfg, a.fix)


if __name__ == "__main__":
    main()
