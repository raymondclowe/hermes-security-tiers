# Spec — what the tiers mean and what the plugin guarantees

Version 1. Kept deliberately small: if a rule here needs a paragraph, it is probably
being enforced somewhere else and should not be in this file.

## 1. The axis

A tier answers one question: **what does it cost if this leaks?**

Not "how secret does the string look", not "how much do we trust the vendor", not
"where is the machine". Those are inputs to a human's decision, not a substitute
for it.

| Tier | Losing it costs | Typical |
| --- | --- | --- |
| `throwaway` | nothing worth measuring | library card, signup address, guest wifi, test key |
| `low` | bounded: a few dollars, a re-doable action | prepaid inference key, sandbox token, school portal |
| `money` | money, or the account that holds money | exchange keys, cloud billing, payment processor |
| `root` | control of identity or infrastructure | SSH private keys, DNS, mail, cloud root, bot tokens, banking |

The ordering is total and monotonic: `throwaway < low < money < root`. There is no
"medium-high". Adding a level breaks the point of the ladder.

`settings.default_tier` applies when nothing matches. It defaults to `low` because
the failure this project exists to fix is over-warning, not under-warning: an
unlisted credential should be treated normally, not treated as suspicious.

## 2. Matching

An item is matched as:

1. the string as given, lowercased;
2. if it contains `/`, also its basename, lowercased.

Both are tested with `fnmatch` against each `match:` glob in each row, so `*` is
permitted to cross `/`. A row may carry several globs.

**Highest matching tier wins.** Order in the file is irrelevant; specificity is not
rewards-based. A credential that matches both a `low` row and a `root` row is `root`.

Items are typically credential names, env var names, vault labels or file paths.
The plugin never inspects a *value* — no entropy scan, no prefix sniffing. Values
are the reason the harness cannot tell tiers apart; using them would reproduce the bug.

## 3. Settings

| Key | Values | Meaning |
| --- | --- | --- |
| `default_tier` | a tier | tier for anything unmatched |
| `rotate_advice_from` | a tier, or `none` | lowest tier that may ever be advised to rotate; `none` = never advise |
| `type_passwords_from` | a tier, or `none` | lowest tier the agent must refuse to type; `none` = type anything |
| `one_caution_per_item` | bool | at most one caution per item per conversation |

Unknown values fall back to the built-in default and never raise. A typo must not
stop a session.

`none` is a first-class value, not an error case: "never nag me about rotation" is a
legitimate policy.

## 4. Rendering

One section per new session, `position="after_memory"`, hard cap 3900 characters
(the plugin's own budget; core caps at 4000).

Contents, in order: heading, one line per tier with its rule, the numbered conduct
rules derived from `settings`, then a `| tier | matches | notes |` table.

If the inventory does not fit, rows are dropped from the end and a single marker row
reports how many — never a half-written table cell, never a silent truncation.

`tiers.<name>.rule` overrides the built-in wording. Absent means built-in.

A missing or unparseable manifest renders **nothing**. Session start is more
important than the policy.

## 5. Recording a decision

`security_tier(action="add", item=..., tier=..., note=..., match=[...])`:

- default glob is `*ITEM*`, upper-cased;
- the row is **appended** to the file as YAML text — the file is never re-serialised,
  because a round-trip through a YAML dumper deletes every comment the operator wrote;
- the previous file is copied to `security-tiers.yaml.bak-<timestamp>`;
- if the append produces a file that will not parse, the original is restored and the
  call fails loudly with the backup path.

The change takes effect at the next **new** session. A running session's prompt is
frozen; the tool says so rather than implying otherwise.

## 6. What is out of scope

For consumers reading this before installing:

- Tool descriptions and their prohibitions belong to the harness. This plugin does not
  rewrite them, and will not silently override another tool's safety text.
- Redaction (`security.redact_secrets`) is a harness setting with harness-wide blast
  radius. This plugin renders advice; it does not flip the switch. The setup script
  prints the exact command instead of running it.
- Approval gates are not tiered. Nothing here bypasses a confirmation.

If a future version does any of those, it goes in this section first.
