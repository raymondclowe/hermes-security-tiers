---
name: security-tiers
description: Interview the operator into a credential ladder, then obey it.
---

# security-tiers

Use when the operator says the agent is paranoid about credentials, complains about
rotation nagging or masked keys, or asks to tune security.

The plugin renders the policy into every session; this skill covers the part a plugin
cannot do — getting the decisions out of the human, once, and writing them down.

## 1. Probe before asking anything

Never open with a questionnaire. The machine knows facts the human should not have to
supply from memory:

```bash
python3 "$HERMES_HOME/plugins/security-tiers/scripts/setup.py" --check
```

Read the output. It gives you, in this order: platform, logins, inbound ports, disk
encryption, SSH key permissions, credential-file permissions, harness posture, whether
the agent runs as root.

`--check --json` when you want to reason over it rather than show it.

Show the operator the two or three findings that actually change their answer, with
the risk level. Skip `info` rows. Do not editorialise: `[elevated] Login accounts with a
shell: you, deploy` already carries its own weight.

## 2. Ask the six questions — in chat, not in a form

Ask **one message at a time**, in this order, and put your recommended answer first
with the probe reason attached. Six questions in one block gets you six guesses.

1. **What is this machine?** locked room / shared space / cloud VPS / laptop.
   *Recommend from `virt` + `users`.*
2. **Who else can get a shell?** just me / household / team / unsure.
   *Recommend from `users`.*
3. **Which leaks would cost you something?** money / identity / personal data /
   client data / nothing. Multi-select. *Recommend from discovered credential names:
   if there is an exchange key, `money` is already true whether they say it or not.*
4. **Should I type passwords into pages for you?** below money / everything / never.
   *Recommend `below money` unless the probe found a high finding, in which case say
   why and still recommend `below money` — the tier ladder is not the place to fix a
   loose SSH key.*
5. **When should I advise rotating?** money on exposure / anything on exposure / never.
   *Recommend `money on exposure`. If they have already snapped at a rotation warning,
   offer `never` and mean it.*
6. **Unlisted credentials default to?** low / throwaway / money. *Recommend `low`.*

If they answer a question with "whatever you think", take the recommendation and move
on. Do not re-ask.

## 3. Write the manifest

EITHER run the interactive script and hand the terminal over:

```bash
python3 "$HERMES_HOME/plugins/security-tiers/scripts/setup.py"
```

OR — better in chat — write their answers to JSON and run it scripted:

```bash
cat > /tmp/answers.json <<'JSON'
{"machine": "locked-room", "who": "just-me", "hurt": ["money","identity"],
 "type_passwords": "below-money", "rotate": "money-on-exposure",
 "default_tier": "low",
 "credentials": {"OPENROUTER_API_KEY": "low", "KRAKEN_API_KEY": "money"}}
JSON
python3 "$HERMES_HOME/plugins/security-tiers/scripts/setup.py" --answers /tmp/answers.json
```

`credentials` is optional; the probe already proposed a tier per discovered name, and
anything you leave out keeps its proposal. Only override where the human overruled it.

Then confirm the file parses and the tier they care about lands where they expect:

```bash
python3 "$HERMES_HOME/plugins/security-tiers/scripts/setup.py" --classify METAMASK_VAULT_PASSWORD
```

## 4. Obey it

- Call `security_tier(action="classify", item=...)` before deciding how careful to be
  about a name you have not handled this session.
- When they state a tier — *"that one's a throwaway"*, *"no, that's a real key"* — call
  `security_tier(action="add", ...)` **in the same turn**. A stated decision that is not
  written down is lost at the next session, and re-asking is the failure this exists to
  prevent.
- One caution per item per conversation. If they say they know, drop it.
- Never advise rotating below `settings.rotate_advice_from`. If they set `none`, that
  advice is off, including after an exposure.

## 5. Rules that override the ladder

- A credential classified `money` or `root` stays out of chat and out of world-readable
  files even when the operator is relaxed about `low`. The ladder relaxes the *fuss*,
  not the handling of the top two tiers.
- An exposure is a fact, not a policy question. If a `root` key appeared in a public
  place, say so once, plainly, with what was exposed. That is not nagging; it is the
  one warning the ladder keeps.
- Do not flip `security.redact_secrets` yourself. Print the command, let them decide.

## Pitfalls

- **Do not classify by value.** No entropy guesses, no prefix sniffing — that is the
  bug being fixed.
- **Do not re-dump the manifest with a YAML library.** Their comments are the
  documentation; `security_tier(action="add")` appends instead.
- **A new session is required.** Editing the manifest mid-session changes nothing
  visible until the next one; say so instead of claiming it took effect.
- **The repo's `.gitignore` excludes `security-tiers.yaml`.** A real manifest maps that
  machine's credential names. Never commit one to a public repo — commit the example.
