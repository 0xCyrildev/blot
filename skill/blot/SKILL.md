---
name: blot
description: |
  Redact credentials out of text before it is shared — logs, diffs, transcripts, report drafts,
  configs, incident channels. Drive blot's loop: read the candidate report, decide which shapes are
  real secrets, teach blot those shapes as rules, re-run until --verify passes. blot is offline,
  stdlib-only and one file; the judgement in the loop is yours, and the rule you must not break is
  that you never read the unredacted input or ask blot to quote a secret.
  Triggers on: blot, redact, scrub this log, sanitize before posting, secrets in this text,
  take the tokens out, hide the credentials, prepare this for the issue.
user-invocable: true
---

# blot — the redaction loop

`blot` removes recognised credentials and leaves readable placeholders (`<JWT:1>`) that stay
consistent within a run. It recognises by **shape and by name**, so an in-house key it has never seen
passes through. You are the layer that closes that gap. It never calls a network: nothing leaves the
machine, including you reading it.

## The rule that governs everything else

**Never read the input file, and never ask blot to print a secret.** You get `--candidates` and
`--json`, which describe what survived — site name, character set, length, entropy, a masked shape,
the redacted line — precisely so you can decide without seeing it. If you find yourself wanting the
raw value, that is the signal to write a broader rule, not to look.

## Loop

1. **Sweep.**
   `blot in.log --candidates --json --out in.safe.txt`
   stdout is the report; the redacted text is already at `--out`. Read only the report.
2. **Decide**, per candidate, one of:
   - **blot it** — it is a credential. Add a rule (step 3).
   - **leave it** — an identifier, a URL, a git sha, a filename. Say why in one line.
   - **unsure** — blot it. Over-redaction costs a reader some detail; a miss costs the whole secret.
3. **Teach blot.** Write `rules.json`, then re-run:
   ```json
   {"rules": [{"name": "ACME_KEY",
               "regex": "(?i)(?P<keep>\\bacme[_-]?api[_-]?key\\s*[:=]\\s*)(?P<sec>\\S{8,})",
               "screen": ["acme"]}]}
   ```
   `sec` is required and is what gets replaced; `keep` is the context you want to stay visible.
   `screen` is optional: literals without which the regex cannot match, tested against the lowercased
   line — a screen that is wrong silently un-does the rule, so if you are unsure, omit it.
   `blot --dump-rules built.json` gives you the built-in set to copy a shape from.
   `blot in.log --rules rules.json --candidates --json --out in.safe.txt`
4. **Gate.** `blot in.log --rules rules.json --out in.safe.txt --strict` must exit **0**. `--strict`
   runs `--verify` and then refuses with **4** if any unnamed shape is still standing — which is how
   you learn your rule set is incomplete without publishing the log to find out. Exit **3** means a
   recognised secret survived, and it names the lines. `--verify` ignores `--keep` on purpose: never
   let the exceptions that produced a redaction certify it.

## Exit codes

`0` clean · `2` usage or I/O failure (nothing was written) · `3` **not clean**, a recognised secret is
still live · `4` **unnamed** — nothing recognised survived, but a candidate shape did, so go back to
step 3.

## Flags worth reaching for

- `--pii` — emails, IPv4, phone numbers too.
- `--paranoid` — blot any high-entropy value sitting at a key, quote or `--flag=` site. Use it when
  the text matters less than the secrets, and expect it to eat useful lines.
- `--stable` — labels derived from the secret's hash, so the same token gets the same label across
  separate runs. Needed when one incident spans several logs.
- `--map secrets.map.json` — the reverse table, `0600`, never overwritten. **This file is the only
  copy of what was removed.** Do not commit it, do not attach it, do not paste it into the issue.
- `--keep TYPE` — spare a type. Names a rule, not a secret: a value can still be caught by another.
- `-` or no file — stdin. `blot a.txt - b.txt` mixes both.

## What you are reporting to a human

Say how many secrets were removed and of which kinds (`blot` prints that to stderr), which candidates
you left alone and why, and state the limit out loud: **`--verify` proves nothing recognised survived,
not that nothing survived.**
