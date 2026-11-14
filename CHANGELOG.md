# Changelog

## 1.0.0 — 2026-11-14

First release.

- Four-tier ladder (`throwaway` / `low` / `money` / `root`) matched on credential
  names, env vars, vault labels and file paths. Highest match wins; unmatched takes
  `settings.default_tier`.
- `scripts/setup.py`: probes the machine (virtualisation, login accounts, listeners,
  disk encryption, SSH key permissions, credential-file permissions, harness posture,
  passwordless sudo), discovers credential names without reading values, interviews
  the operator, and writes a commented manifest.
- `security_tier` tool (`classify` / `add` / `list` / `explain`) and a `/tiers`
  command. `add` appends to the manifest rather than re-serialising it, so comments
  survive; a failed append restores the original.
- Session block carries the ladder, the operator's conduct rules and the live
  inventory, capped and truncation-marked.
- 15 stdlib tests covering precedence, defaults, matching, budgets and round-trip.
