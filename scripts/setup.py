#!/usr/bin/env python3
"""security-tiers setup — probe the machine, interview the operator, write the manifest.

Why this exists: an agent harness cannot tell a library card from an exchange key,
so it treats both as dangerous and the operator turns everything off. This script
replaces that with two inputs the harness does not have:

  * what this machine actually is (exposure, users, encryption, file permissions);
  * what the operator says matters.

Output is ``$HERMES_HOME/security-tiers.yaml``, which the matching plugin renders
into every new session. Nothing is enforced here — the decision is yours, and the
file is plain YAML you can edit forever after.

    python3 scripts/setup.py                 # probe, interview, write the manifest
    python3 scripts/setup.py --check         # probe only, print findings
    python3 scripts/setup.py --check --json  # the same, machine-readable
    python3 scripts/setup.py --yes           # accept every proposed default
    python3 scripts/setup.py --answers a.json  # scripted/agent-driven interview
    python3 scripts/setup.py --classify OPENROUTER_API_KEY

Needs only python3 and PyYAML.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - only for the --check path
    yaml = None

TIERS = ("throwaway", "low", "money", "root")
RANK = {name: index for index, name in enumerate(TIERS)}

SECRET_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS\b|CREDENTIAL|AUTH)", re.I)
NOT_A_SECRET = re.compile(
    r"(PATH|HOME|DIR|HOST|PORT|URL|USER|LANG|TERM|SHELL|PWD|LOG|MODE|LEVEL|"
    r"ENABLED|TIMEOUT|COUNT|LIMIT|FILE|NAME|TOKENIZER|MAX_|REDACT|SECRETS_)",
    re.I,
)

# Name-based proposal, used only to pre-fill the interview. Highest risk wins.
HEURISTIC = (
    ("money", re.compile(r"(KRAKEN|BINANCE|COINBASE|BITFINEX|LEDN|STRIPE|PAYPAL|BILLING|"
                         r"AWS_|LIGHTSAIL|SATURN|POLYMARKET|METAMASK|WALLET|SEED|MNEMONIC)", re.I)),
    ("root", re.compile(r"(SSH|PRIVATE_KEY|CLOUDFLARE|CF_API|CF_TOKEN|TELEGRAM|GITHUB|GH_TOKEN|"
                        r"GMAIL|EMAIL|IMAP|SMTP|MAIL_|GOOGLE_REFRESH|SENDGRID|TWILIO|BANK)", re.I)),
    ("low", re.compile(r"(OPENROUTER|ANTHROPIC|OPENAI|DEEPSEEK|GEMINI|GOOGLE_API|HUGGINGFACE|HF_TOKEN|"
                       r"MISTRAL|GROQ|XAI|TOGETHER|REPLICATE|GLM|MINIMAX|KIMI|DASHSCOPE)", re.I)),
    ("throwaway", re.compile(r"(TEST|DEMO|SANDBOX|THROWAWAY|SCRATCH|MAILINATOR|DISPOSABLE)", re.I)),
)

# --------------------------------------------------------------------------- utils


def hermes_home() -> Path:
    env = (os.environ.get("HERMES_HOME") or "").strip()
    if env:
        return Path(env).expanduser()
    return Path.home() / ".hermes"


def first_existing(*paths: Path) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


# -------------------------------------------------------------------------- probes

LOOPBACK4 = {"0100007F"}
LOOPBACK6 = {"00000000000000000000000001000000"}


def listening_ports() -> list[str]:
    """Ports accepting connections on something other than loopback, read from /proc."""
    ports: set[str] = set()
    for name in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(name).read_text(encoding="utf-8", errors="replace").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            cols = line.split()
            if len(cols) < 4 or cols[3] != "0A":       # 0A = LISTEN
                continue
            addr, _, port_hex = cols[1].partition(":")
            if addr in LOOPBACK4 or addr in LOOPBACK6:
                continue
            try:
                ports.add(str(int(port_hex, 16)))
            except ValueError:
                continue
    return sorted(ports, key=int)


def login_shells() -> list[str]:
    try:
        import pwd as accounts
    except ImportError:                                # not a Unix host
        return []
    try:
        return [e.pw_name for e in accounts.getpwall()
                if e.pw_uid >= 1000 and not e.pw_shell.rstrip().endswith(("nologin", "false"))]
    except Exception:
        return []


def disk_encrypted() -> bool:
    for marker in Path("/sys/block").glob("*/dm/uuid"):
        try:
            if marker.read_text(encoding="utf-8").strip().startswith("CRYPT-LUKS"):
                return True
        except OSError:
            continue
    return False


def probe(findings: list[dict]) -> None:
    """Collect facts about the machine.

    Pure stdlib reads: no shell, no child processes, no elevated calls. Every probe
    degrades to a skip so an unusual host produces fewer findings, never a crash.
    """

    def add(id_, label, value, risk, why):
        findings.append({"id": id_, "label": label, "value": value, "risk": risk, "why": why})

    # virtualisation: a VM's console belongs to whoever runs the hypervisor
    virt = "unknown"
    try:
        dmi = Path("/sys/class/dmi/id/product_name").read_text(encoding="utf-8").strip()
        if dmi:
            virtualised = re.search(r"(kvm|vmware|virtualbox|qemu|hyper-v|xen|amazon ec2|google compute)",
                                    dmi, re.I)
            virt = dmi if virtualised else "none"
    except OSError:
        pass
    physical = virt in ("none", "")
    add("virt", "Platform", "physical" if physical else virt, "info",
        "a virtual machine is reachable by whoever runs the hypervisor")

    # who else can get a shell
    shells = login_shells()
    add("users", "Login accounts with a shell", ", ".join(shells) or "unknown",
        "low" if len(shells) <= 1 else "elevated",
        "a second login can read every file this account can read")

    # inbound exposure
    ports = listening_ports()
    add("listeners", "Ports listening beyond loopback", ", ".join(ports) or "none",
        "elevated" if ports else "low",
        "reachable by anything that can route here — the LAN, or the internet if the router "
        "forwards it")

    # encryption at rest
    encrypted = disk_encrypted()
    add("disk", "Disk encryption at rest", "yes (LUKS)" if encrypted else "not detected", "info",
        "physical access without encryption is total disclosure")

    # ssh key permissions — the finding that is usually actionable
    loose, total = [], 0
    ssh_dir = Path.home() / ".ssh"
    if ssh_dir.is_dir():
        for key in ssh_dir.iterdir():
            if not key.is_file() or key.suffix in (".pub", ".known_hosts", ".old"):
                continue
            try:
                with key.open("rb") as handle:
                    head = handle.read(64)
            except OSError:
                continue
            if b"PRIVATE KEY" not in head:
                continue
            total += 1
            mode = key.stat().st_mode
            if mode & 0o077:
                loose.append(f"{key.name} ({oct(mode & 0o777)})")
    add("ssh", "SSH private keys", f"{total} key(s)", "info", "")
    if loose:
        add("ssh_perms", "SSH keys readable by group/other", ", ".join(loose), "high",
            "any other login can copy the key; chmod 600 them")

    # credential file permissions + how many entries they hold
    env_files = [p for p in (hermes_home() / ".env",
                             Path.home() / ".hermes" / ".env") if p.is_file()]
    for path in dict.fromkeys(env_files):
        try:
            mode = path.stat().st_mode & 0o777
            names = [ln.split("=", 1)[0].strip() for ln in
                     path.read_text(encoding="utf-8", errors="replace").splitlines()
                     if "=" in ln and not ln.lstrip().startswith("#")]
        except OSError:
            continue
        add(f"env:{path}", "Credential file", f"{path} — {oct(mode)}, {len(names)} entries",
            "elevated" if mode & 0o077 else "low",
            "group/world-readable means every other login can read it; chmod 600")

    # harness posture
    cfg_path = first_existing(hermes_home() / "config.yaml",
                              Path.home() / ".hermes" / "config.yaml")
    posture = {}
    if cfg_path and yaml is not None:
        try:
            cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            sec = cfg.get("security") or {}
            posture = {
                "redact_secrets": sec.get("redact_secrets", True),
                "allow_private_urls": sec.get("allow_private_urls", False),
                "approvals": (cfg.get("approvals") or {}).get("mode", "manual"),
            }
        except Exception:
            posture = {}
    if posture:
        add("posture", "Harness posture",
            f"redact_secrets={posture['redact_secrets']} "
            f"allow_private_urls={posture['allow_private_urls']} "
            f"approvals={posture['approvals']}",
            "info", "redact_secrets=true masks every credential-shaped string in tool output")

    if os.geteuid() == 0:
        add("root", "Running as root", "yes", "high",
            "every tool call has full control of the box")


def ambient(findings: list[dict]) -> str:
    """Aggregate finding severities into one word the interview can start from."""
    weights = {"high": 4, "elevated": 2, "low": 0, "info": 0}
    score = sum(weights.get(f["risk"], 0) for f in findings)
    if any(f["risk"] == "high" for f in findings) or score >= 8:
        return "high"
    if score >= 2:
        return "elevated"
    return "low"


# -------------------------------------------------------------- credential discovery


def discover() -> list[dict]:
    """Credential-shaped names the harness already holds. Names only, never values."""
    found: dict[str, dict] = {}

    def consider(name: str, source: str) -> None:
        name = name.strip()
        if not name or len(name) < 3 or not SECRET_NAME.search(name) or NOT_A_SECRET.search(name):
            return
        entry = found.setdefault(name, {"name": name, "sources": [], "tier": propose_tier(name)})
        if source not in entry["sources"]:
            entry["sources"].append(source)

    for path in dict.fromkeys(p for p in (
            hermes_home() / ".env",
            Path.home() / ".hermes" / ".env",
            Path.home() / ".env",
    ) if p.is_file()):
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    consider(line.split("=", 1)[0], str(path.name))
        except OSError:
            pass
    for name in os.environ:
        consider(name, "environment")
    order = {t: i for i, t in enumerate(TIERS)}
    return sorted(found.values(), key=lambda e: (-order[e["tier"]], e["name"]))[:60]


def propose_tier(name: str) -> str:
    for tier, pattern in HEURISTIC:
        if pattern.search(name):
            return tier
    return "low"


# ------------------------------------------------------------------------ interview

QUESTIONS = (
    {
        "id": "machine",
        "prompt": "What is this machine?",
        "choices": ["locked-room", "shared-space", "cloud-vps", "laptop"],
        "help": "locked-room = physical box, controlled access. cloud-vps = someone else's hypervisor.",
    },
    {
        "id": "who",
        "prompt": "Who else can log into it?",
        "choices": ["just-me", "household", "team", "unsure"],
    },
    {
        "id": "hurt",
        "prompt": "Which leaks would actually cost you something? (comma-separated numbers)",
        "choices": ["money", "identity", "personal-data", "client-data", "nothing"],
        "multi": True,
    },
    {
        "id": "type_passwords",
        "prompt": "Should the agent type passwords into pages for you?",
        "choices": ["below-money", "everything", "never"],
        "help": "below-money = it types throwaway/low, refuses money/root.",
    },
    {
        "id": "rotate",
        "prompt": "When should it advise rotating a credential?",
        "choices": ["money-on-exposure", "anything-on-exposure", "never"],
    },
    {
        "id": "default_tier",
        "prompt": "What should an unlisted credential be treated as?",
        "choices": ["low", "throwaway", "money"],
        "help": "the default is what happens before anyone has decided.",
    },
)

_SETTINGS_FROM_ANSWER = {
    "type_passwords": {"below-money": "money", "everything": "none", "never": "throwaway"},
    "rotate": {"money-on-exposure": "money", "anything-on-exposure": "low", "never": "none"},
}


def proposed_answers(findings: list[dict], creds: list[dict]) -> dict:
    """Probe-informed defaults, used by --yes and as the pre-filled prompt value."""
    level = ambient(findings)
    physical = any(f["id"] == "virt" and f["value"] == "physical" for f in findings)
    users = next((f for f in findings if f["id"] == "users"), None)
    single = bool(users and users["risk"] == "low")
    machine = "locked-room" if physical and single else ("cloud-vps" if not physical else "shared-space")
    hurt = ["money", "identity"]
    if level != "low":
        hurt.append("personal-data")
    return {
        "machine": machine,
        "who": "just-me" if single else "unsure",
        "hurt": hurt,
        "type_passwords": "below-money",
        "rotate": "money-on-exposure",
        "default_tier": "low",
        "ambient": level,
        "credentials": {c["name"]: c["tier"] for c in creds},
    }


def ask(question: dict, default) -> object:
    choices = question["choices"]
    shown = " / ".join(f"[{i + 1}] {c}" for i, c in enumerate(choices))
    if question.get("multi"):
        pretty = ", ".join(str(default)) if isinstance(default, list) else str(default)
        raw = input(f"\n{question['prompt']}\n  {shown}\n  default: {pretty}\n> ").strip()
        if not raw:
            return default
        picked = []
        for token in raw.replace(" ", "").split(","):
            if token.isdigit() and 1 <= int(token) <= len(choices):
                picked.append(choices[int(token) - 1])
            elif token in choices:
                picked.append(token)
        return picked or default
    hint = f" (default: {default})" if default else ""
    if question.get("help"):
        print(f"  {question['help']}")
    raw = input(f"\n{question['prompt']}\n  {shown}{hint}\n> ").strip()
    if not raw:
        return default
    if raw.isdigit() and 1 <= int(raw) <= len(choices):
        return choices[int(raw) - 1]
    return raw if raw in choices else default


def interview(answers: dict, interactive: bool) -> dict:
    resolved = dict(answers)
    if not interactive:
        return resolved
    for question in QUESTIONS:
        resolved[question["id"]] = ask(question, resolved.get(question["id"]))
    return resolved


# ------------------------------------------------------------------------- manifest

# Always written, whatever discovery finds: the credential shapes that show up on every
# machine. Discovery can only see names in .env and the environment, so a vault-only
# setup would otherwise produce an almost empty manifest.
BASELINE_RULES: tuple[tuple[str, list[str], str], ...] = (
    ("throwaway",
     ["*_TEST*", "*_DEMO*", "*sandbox*", "*throwaway*", "*mailinator*", "*LIBRARY*",
      "*GUEST*WIFI*"],
     "test, demo and one-off credentials — costing nothing is the point"),
    ("low",
     ["*OPENROUTER*", "*DEEPSEEK*", "*GROQ*", "*TOGETHER*", "*REPLICATE*", "*HF_TOKEN*",
      "*HUGGINGFACE*", "*GEMINI*", "*MISTRAL*", "*XAI*"],
     "prepaid inference and free tiers — loss capped by the balance"),
    ("money",
     ["*KRAKEN*", "*BINANCE*", "*COINBASE*", "*BITFINEX*", "*LEDN*", "*STRIPE*", "*PAYPAL*",
      "*AWS_SECRET*", "*AWS_ACCESS*", "*LIGHTSAIL*", "*BILLING*", "*METAMASK*", "*WALLET*",
      "*MNEMONIC*", "*SEED_PHRASE*"],
     "moves or bills money"),
    ("root",
     ["id_rsa*", "id_ed25519*", "id_ecdsa*", "*PRIVATE*KEY*", "*.ssh/*", "*SSH*KEY*",
      "*CLOUDFLARE*", "CF_API*", "*CF_TOKEN*", "*TELEGRAM*BOT*", "*GITHUB_TOKEN*",
      "*GH_TOKEN*", "*GOOGLE_REFRESH*", "*EMAIL_PASSWORD*", "*IMAP*", "*SMTP*",
      "*APP_PASS*", "*bank*", "*credit*card*"],
     "fleet, identity and money movement — the keys to everything else"),
)


def covered_by_baseline(name: str) -> bool:
    """True when a baseline glob already handles this name, so no per-machine row is needed."""
    low = name.lower()
    return any(fnmatch.fnmatchcase(low, pattern.lower())
               for _tier, patterns, _note in BASELINE_RULES for pattern in patterns)


def render_manifest(ans: dict, findings: list[dict], creds: list[dict]) -> str:
    rotate_from = _SETTINGS_FROM_ANSWER["rotate"].get(ans.get("rotate", ""), "money")
    type_from = _SETTINGS_FROM_ANSWER["type_passwords"].get(ans.get("type_passwords", ""), "money")
    default_tier = ans.get("default_tier", "low")
    if default_tier not in RANK:
        default_tier = "low"

    lines = [
        "# security-tiers — the operator's ladder. Generated by scripts/setup.py;",
        "# edit freely, this file is the policy. The plugin re-reads it at session start.",
        "#",
        "# One axis: what a leak would actually cost. Not where the machine sits, not how",
        "# secret the string looks. Unmatched items take `settings.default_tier`; highest",
        "# matching tier wins.",
        "",
        "version: 1",
        "",
        "settings:",
        f"  default_tier: {default_tier}",
        f"  rotate_advice_from: {rotate_from}",
        f"  type_passwords_from: {type_from}",
        "  one_caution_per_item: true",
        "",
        "tiers:",
        "  throwaway:",
        '    rule: "Type it, paste it, echo it. Never warn. Never advise rotation."',
        "  low:",
        '    rule: "Use freely in files, commands and chat. No unsolicited rotate advice."',
        "  money:",
        '    rule: "Out of chat, out of world-readable files. Env or vault. Rotate only after a real exposure."',
        "  root:",
        '    rule: "Vault or env only. Never printed. Rotate only after a real exposure."',
        "",
        "items:",
    ]
    if creds:
        for cred in creds:
            if covered_by_baseline(cred["name"]):
                continue
            tier = ans.get("credentials", {}).get(cred["name"], cred["tier"])
            if tier not in RANK:
                tier = default_tier
            note = ", ".join(cred["sources"][:2])
            lines += [
                f"  - match: [{json.dumps('*' + cred['name'] + '*')}]",
                f"    tier: {tier}",
                f"    note: {json.dumps('found in ' + note)}",
            ]

    # Baseline rules: always present, so a machine whose credentials live in a vault
    # rather than a .env file still gets a usable ladder instead of an empty file.
    lines += ["", "# baseline rules — always written; edit or delete as you see fit"]
    for tier, patterns, note in BASELINE_RULES:
        joined = ", ".join(json.dumps(p) for p in patterns)
        lines += [
            f"  - match: [{joined}]",
            f"    tier: {tier}",
            f"    note: {json.dumps(note)}",
        ]

    lines += [
        "",
        "# --- environment this file was generated against (" + time.strftime("%Y-%m-%d") + ") ---",
    ]
    for finding in findings:
        if finding["risk"] in ("high", "elevated"):
            value = str(finding["value"])[:90]
            lines.append(f"# [{finding['risk']}] {finding['label']}: {value}")
    if ans.get("ambient"):
        lines.append(f"# ambient risk: {ans['ambient']}")
    return "\n".join(lines) + "\n"


def write_manifest(text: str, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = path.with_name(f"{path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(path, backup)
        print(f"  backed up existing manifest -> {backup.name}")
    path.write_text(text, encoding="utf-8")
    if yaml is not None:
        yaml.safe_load(text)  # fail loudly rather than leave a manifest the plugin cannot read
    return path


# ----------------------------------------------------------------------------- cli


def print_findings(findings: list[dict]) -> None:
    print("\nEnvironment")
    print("-" * 72)
    for f in findings:
        print(f"  [{f['risk']:8}] {f['label']}: {f['value']}")
        if f.get("why") and f["risk"] in ("high", "elevated"):
            print(f"             {f['why']}")
    print(f"\n  ambient risk: {ambient(findings)}")


def print_credentials(creds: list[dict]) -> None:
    if not creds:
        print("\nNo credential-shaped names found in .env or the environment.")
        return
    print(f"\nCredentials found ({len(creds)}) — proposed tier, you decide:")
    print("-" * 72)
    for cred in creds:
        print(f"  {cred['tier']:9} {cred['name']:34} {', '.join(cred['sources'][:2])}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Set up the security-tiers credential ladder.")
    ap.add_argument("--check", action="store_true", help="probe only, change nothing")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--yes", action="store_true", help="accept every proposed default")
    ap.add_argument("--answers", help="JSON file of interview answers")
    ap.add_argument("--manifest", help="write here instead of $HERMES_HOME/security-tiers.yaml")
    ap.add_argument("--classify", help="print the tier of one item and exit")
    args = ap.parse_args(argv)

    findings: list[dict] = []
    probe(findings)
    creds = discover()

    if args.classify:
        doc = {}
        target = Path(args.manifest) if args.manifest else hermes_home() / "security-tiers.yaml"
        if target.exists() and yaml is not None:
            doc = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        answered = (json.loads(Path(args.answers).read_text(encoding="utf-8"))
                    if args.answers else {})
        tier = answered.get("credentials", {}).get(args.classify) or propose_tier(args.classify)
        chosen = None
        for entry in doc.get("items") or []:
            for pattern in entry.get("match") or []:
                from fnmatch import fnmatchcase
                if fnmatchcase(args.classify.lower(), str(pattern).lower()):
                    if chosen is None or RANK.get(entry["tier"], -1) > RANK.get(chosen, -1):
                        chosen = entry["tier"]
        print(chosen or tier)
        return 0

    answers = proposed_answers(findings, creds)
    if args.answers:
        answers.update(json.loads(Path(args.answers).read_text(encoding="utf-8")))

    if args.check:
        if args.json:
            print(json.dumps({"findings": findings, "ambient": ambient(findings),
                              "credentials": creds, "proposed": answers}, indent=2))
        else:
            print_findings(findings)
            print_credentials(creds)
            print("\nRun `python3 scripts/setup.py` to interview and write the manifest.")
        return 0

    interactive = not (args.yes or args.answers or not sys.stdin.isatty())
    if not args.json:
        print_findings(findings)
        print_credentials(creds)

    answers = interview(answers, interactive)
    text = render_manifest(answers, findings, creds)
    target = Path(args.manifest).expanduser() if args.manifest else hermes_home() / "security-tiers.yaml"
    write_manifest(text, target)

    if args.json:
        print(json.dumps({"manifest": str(target), "answers": answers,
                          "ambient": ambient(findings)}, indent=2))
        return 0

    print(f"\nWrote {target}")
    print(f"  default {answers['default_tier']} | rotate advice from "
          f"{_SETTINGS_FROM_ANSWER['rotate'].get(answers['rotate'], 'money')} | type passwords below "
          f"{_SETTINGS_FROM_ANSWER['type_passwords'].get(answers['type_passwords'], 'money')}")
    print("\nNext:")
    print("  1. Restart the agent (or start a new session) so the block is injected.")
    print("  2. `hermes plugins enable security-tiers` if it is not enabled.")
    print("  3. Tell the agent a tier out loud once — it records it in this file.")
    if str((answers.get("ambient") or "")).lower() != "low":
        print("\n  Your probe flagged elevated ambient risk. Consider also:")
        print("    hermes config set security.redact_secrets false   # stop masking everything")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
