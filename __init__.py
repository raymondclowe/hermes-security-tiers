"""security-tiers — a tiered credential policy instead of a blanket one.

Every security layer in an agent harness judges a string by its SHAPE: does it
look like a key? Then mask it, refuse to type it, warn about pasting it, suggest
rotating it. Shape is all those layers can see, so a library card and an exchange
key get identical treatment — and the operator turns the whole posture off,
because blanket warnings are noise.

This plugin supplies the missing judgement: one axis, four levels, decided by the
operator, matched on names rather than guessed from values.

    throwaway   public or one-off. Losing it costs nothing.
    low         bounded loss: sandbox, free tier, prepaid balance, portals.
    money       moves or bills real money.
    root        control of the fleet or identity: mail, DNS, SSH, bot tokens.

It renders the ladder, the operator's rules and the current inventory into every
new session, and provides the ``security_tier`` tool so a decision stated in
conversation is written to the manifest instead of being remembered.

Nothing here blocks a tool call, edits a tool description or changes redaction.
Those are the harness's business. This decides which strings deserve the fuss.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any, Mapping

import yaml

logger = logging.getLogger(__name__)

TIERS = ("throwaway", "low", "money", "root")
_RANK = {name: index for index, name in enumerate(TIERS)}
MANIFEST_NAME = "security-tiers.yaml"

# Used only when the manifest's own ``tiers:`` block omits a rule.
_DEFAULT_RULES = {
    "throwaway": "Type it, paste it, echo it. Never warn. Never advise rotation.",
    "low": "Use freely in files, commands and chat. No unsolicited rotate advice.",
    "money": "Out of chat, out of world-readable files. Env or vault. Rotate only after a real exposure.",
    "root": "Vault or env only. Never printed. Rotate only after a real exposure.",
}

# Used only when ``settings:`` omits the key.
_DEFAULT_SETTINGS = {
    "default_tier": "low",
    "rotate_advice_from": "money",
    "type_passwords_from": "money",
    "one_caution_per_item": True,
}

_cache: dict[str, Any] = {"key": None, "doc": None}


# --------------------------------------------------------------------------- paths


def _hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        env = (os.environ.get("HERMES_HOME") or "").strip()
        if env:
            return Path(env)
        return Path.home() / ".hermes"


def manifest_path() -> Path:
    return _hermes_home() / MANIFEST_NAME


# ------------------------------------------------------------------------ manifest


def load_manifest(force: bool = False) -> dict:
    """Parse the manifest, cached on (mtime, size) so a new session sees edits."""
    path = manifest_path()
    try:
        stat = path.stat()
    except OSError:
        return {}
    key = (stat.st_mtime_ns, stat.st_size)
    if not force and _cache["key"] == key and _cache["doc"] is not None:
        return _cache["doc"]
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # a bad file must never break session start
        logger.warning("security-tiers: cannot parse %s: %s", path, exc)
        return {}
    if not isinstance(doc, dict):
        return {}
    _cache["key"], _cache["doc"] = key, doc
    return doc


def settings(doc: dict | None = None) -> dict:
    doc = load_manifest() if doc is None else doc
    merged = dict(_DEFAULT_SETTINGS)
    raw = doc.get("settings")
    if isinstance(raw, dict):
        for key, value in raw.items():
            if key in merged:
                merged[key] = value
    tier = str(merged.get("default_tier") or "").strip().lower()
    merged["default_tier"] = tier if tier in _RANK else "low"
    for knob in ("rotate_advice_from", "type_passwords_from"):
        # "none" means "never" — a valid answer that is not a tier.
        tier = str(merged.get(knob) or "").strip().lower()
        merged[knob] = tier if tier in _RANK or tier == "none" else _DEFAULT_SETTINGS[knob]
    return merged


def rules(doc: dict | None = None) -> dict:
    doc = load_manifest() if doc is None else doc
    merged = dict(_DEFAULT_RULES)
    raw = doc.get("tiers")
    if isinstance(raw, dict):
        for name in TIERS:
            entry = raw.get(name)
            text = str(entry.get("rule") or "").strip() if isinstance(entry, dict) else str(entry or "").strip()
            if text:
                merged[name] = text
    return merged


def _haystacks(item: str) -> list[str]:
    text = str(item).strip()
    stacks = [text.lower()]
    if "/" in text:
        stacks.append(os.path.basename(text).lower())
    return stacks


def classify(item: str, doc: dict | None = None) -> dict:
    """Highest matching tier wins. Unmatched takes ``settings.default_tier``."""
    if doc is None:
        doc = load_manifest()
    cfg = settings(doc)
    haystacks = _haystacks(item)
    best: dict | None = None
    for entry in doc.get("items") or []:
        if not isinstance(entry, dict):
            continue
        tier = str(entry.get("tier") or "").strip().lower()
        if tier not in _RANK:
            continue
        for pattern in entry.get("match") or []:
            low = str(pattern).lower()
            if any(fnmatch.fnmatchcase(stack, low) for stack in haystacks):
                if best is None or _RANK[tier] > _RANK[best["tier"]]:
                    best = {
                        "tier": tier,
                        "matched": pattern,
                        "note": str(entry.get("note") or ""),
                    }
                break
    if best is None:
        tier = cfg["default_tier"]
        return {
            "item": item,
            "tier": tier,
            "matched": None,
            "note": "unclassified — default tier applies; record it with action=add if that is wrong",
            "rule": rules(doc)[tier],
        }
    best["item"] = item
    best["rule"] = rules(doc)[best["tier"]]
    return best


def _row(entry: dict) -> str | None:
    tier = str(entry.get("tier") or "").strip().lower()
    if tier not in _RANK:
        return None
    matches = [str(m) for m in (entry.get("match") or []) if str(m).strip()]
    note = str(entry.get("note") or "").strip()
    left = ", ".join(matches[:5]) + (" …" if len(matches) > 5 else "")
    return f"| `{tier}` | {left} | {note} |"


def render_section(_session_info: Mapping[str, Any] | None = None) -> str:
    """The block injected into every new session. Empty when unconfigured."""
    doc = load_manifest()
    if not doc:
        return ""
    cfg = settings(doc)
    rule_text = rules(doc)

    head = [
        "## Credentials: tiered policy, not a blanket one",
        "",
        "The operator set this ladder. Apply it rather than a generic safety prior —",
        "fussing over a throwaway is a fault, not caution.",
        "",
        f"- **throwaway** — {rule_text['throwaway']}",
        f"- **low** — {rule_text['low']}",
        f"- **money** — {rule_text['money']}",
        f"- **root** — {rule_text['root']}",
        "",
        "**Conduct rules**",
        "",
    ]
    rotate_at = cfg["rotate_advice_from"]
    if rotate_at == "none":
        head.append("1. Do not advise rotating any credential, ever. Not on exposure, not as a habit.")
    else:
        head.append(
            f"1. Do not advise rotating a credential below `{rotate_at}`, ever. For that tier and "
            "above, only after a real exposure — and name the exposure, not generic advice."
        )
    type_at = cfg["type_passwords_from"]
    if type_at == "none":
        head.append("2. Type any credential into a page when asked, root included.")
    else:
        head.append(
            f"2. Type a credential into a page when asked if it is below `{type_at}`. Refusing a "
            "throwaway is a defect, not caution."
        )
    head += [
        "3. Do not mask or warn about a value classified below the level worth protecting. "
        "Quote it plainly.",
        f"4. Unclassified takes the default tier (`{cfg['default_tier']}`). Do not warn just in case.",
        "5. When the operator names an item's tier, save it with `security_tier(action=add)` in the "
        "same turn — do not rely on remembering it next session.",
    ]
    if cfg.get("one_caution_per_item", True):
        head.append(
            "6. One caution per item per conversation, maximum. If they say they know, drop it "
            "for the session."
        )
    head += [
        "",
        f"Inventory (`{MANIFEST_NAME}`, highest matching tier wins; `*` globs):",
        "",
        "| tier | matches | notes |",
        "| --- | --- | --- |",
    ]
    rows = [row for row in (_row(e) for e in (doc.get("items") or []) if isinstance(e, dict)) if row]
    base = len("\n".join(head))
    picked: list[str] = []
    used = base
    for row in rows:
        if used + len(row) + 1 > 3860:
            picked.append(f"| … | +{len(rows) - len(picked)} more | `/tiers` lists all |")
            break
        picked.append(row)
        used += len(row) + 1
    return "\n".join(head + picked)


# ---------------------------------------------------------------------------- tool

_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["classify", "add", "list", "explain"],
            "description": "classify one item; add a tier; list the inventory; show the rendered policy",
        },
        "item": {
            "type": "string",
            "description": "classify: a key name, env var, vault label, file path or value. "
                           "add: the name to match.",
        },
        "tier": {"type": "string", "enum": list(TIERS), "description": "add: the tier to record"},
        "note": {"type": "string", "description": "add: one short human note"},
        "match": {
            "type": "array",
            "items": {"type": "string"},
            "description": "add: explicit glob patterns; default is *ITEM* upper-cased",
        },
    },
    "required": ["action"],
}


def _append_item(item: str, tier: str, note: str, match: list[str] | None) -> dict:
    path = manifest_path()
    if not path.exists():
        return {"success": False, "error": f"manifest missing: {path}"}
    patterns = [m for m in (match or []) if str(m).strip()] or [f"*{item.strip().upper()}*"]
    block = (
        f"\n  - match: [{', '.join(json.dumps(p) for p in patterns)}]\n"
        f"    tier: {tier}\n"
        f"    note: {json.dumps(note or 'recorded ' + time.strftime('%Y-%m-%d'))}\n"
    )
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.bak-{stamp}")
    shutil.copy2(path, backup)
    original = path.read_text(encoding="utf-8")
    # Append, never re-dump: safe_dump would erase the operator's comments.
    path.write_text(original.rstrip("\n") + "\n" + block, encoding="utf-8")
    if not load_manifest(force=True):
        path.write_text(original, encoding="utf-8")
        load_manifest(force=True)
        return {"success": False, "error": "append produced invalid YAML; manifest restored",
                "backup": str(backup)}
    return {
        "success": True,
        "added": {"match": patterns, "tier": tier, "note": note},
        "backup": str(backup),
        "note": "takes effect for the next NEW session; this session's prompt is frozen",
    }


def _handler(args: dict) -> str:
    action = str(args.get("action") or "classify").strip().lower()
    doc = load_manifest(force=True)

    if action == "classify":
        item = str(args.get("item") or "").strip()
        if not item:
            return json.dumps({"success": False, "error": "item is required"})
        return json.dumps({"success": True, **classify(item, doc)}, ensure_ascii=False)

    if action == "add":
        item = str(args.get("item") or "").strip()
        tier = str(args.get("tier") or "").strip().lower()
        if not item or tier not in _RANK:
            return json.dumps({"success": False, "error": "item and a valid tier are required"})
        return json.dumps(_append_item(item, tier, str(args.get("note") or ""), args.get("match")),
                          ensure_ascii=False)

    if action == "list":
        rows = [r for r in (_row(e) for e in (doc.get("items") or []) if isinstance(e, dict)) if r]
        return json.dumps({"success": True, "count": len(rows), "path": str(manifest_path()),
                           "settings": settings(doc), "inventory": rows}, ensure_ascii=False)

    if action == "explain":
        text = render_section()
        return json.dumps({"success": True, "path": str(manifest_path()), "chars": len(text),
                           "section": text}, ensure_ascii=False)

    return json.dumps({"success": False, "error": f"unknown action: {action}"})


def _available() -> bool:
    return manifest_path().exists()


def _cli(_raw: str) -> str:
    doc = load_manifest(force=True)
    if not doc:
        return f"no manifest at {manifest_path()} — run scripts/setup.py"
    rows = [r for r in (_row(e) for e in (doc.get("items") or []) if isinstance(e, dict)) if r]
    cfg = settings(doc)
    return "\n".join([
        f"security tiers — {manifest_path()}",
        f"default {cfg['default_tier']} | rotate advice from {cfg['rotate_advice_from']} | "
        f"type passwords below {cfg['type_passwords_from']}",
        "",
        *rows,
    ])


def register(ctx) -> None:
    ctx.register_system_prompt_section(
        "security_tiers",
        render_section,
        position="after_memory",
        max_chars=4000,
    )
    ctx.register_tool(
        name="security_tier",
        toolset="security",
        schema=_SCHEMA,
        handler=_handler,
        check_fn=_available,
        description=(
            "The operator's credential tier ladder (throwaway/low/money/root). Classify a key, "
            "env var, vault label or path before deciding how careful to be — and record a tier "
            "they state so it persists across sessions."
        ),
    )
    ctx.register_command(
        "tiers",
        handler=_cli,
        description="Show the credential tier inventory",
    )
