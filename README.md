```
██████  ▄▄▄▄▄▄▄▄▄        ▀▀▀▀▀▀██████                  ▄▄▄▄▄▄▄▄▄▄▄▄         ▄▄▄▄▄▄██████▄▄▄▄▄▄▄▄
███████▀▀▀▀▀▀▀██████▄          ██████             ▄██████▀▀▀▀▀▀▀▀██████▄    ▀▀▀▀▀▀██████▀▀▀▀▀▀▀▀
████████▄▄▄▄▄██████▀▀          ███████▄▄▄▄▄▄▄▄    ▀▀██████▄▄▄▄▄▄██████▀▀          ██████▄▄▄▄▄▄▄▄

                             the secret leaves. the context stays.
```
[![ci](https://github.com/0xCyrildev/blot/actions/workflows/ci.yml/badge.svg)](https://github.com/0xCyrildev/blot/actions/workflows/ci.yml)
[![python: 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](#install)
[![deps: none](https://img.shields.io/badge/dependencies-none-brightgreen)](#install)

Pipe a log, a diff, a transcript or a report draft through blot and every credential it recognises
becomes a readable placeholder. The same secret always becomes the same placeholder, so a bug report
stays internally consistent after redaction — `<JWT:1>` twice means one token, and a reviewer can
still tell *which* field leaked.

![blot on a log](docs/img/redact.png)

## Install

```sh
pipx install git+https://github.com/0xCyrildev/blot.git   # or: pip install ...
curl -o blot https://raw.githubusercontent.com/0xCyrildev/blot/main/blot.py && chmod +x blot
```

One file, stdlib only, no network, no config, no telemetry. It has never heard of an API.

## Use

```sh
cargo build --verbose 2>&1 | blot > safe-log.txt        # the common case
blot draft.md --out draft.published.md --map draft.map.json
cat transcript.txt | blot --verify > /dev/null          # exits 3 rather than claiming a clean
blot app.env --rules learned.json --strict              # exits 4 until every shape has a rule
blot --pii --paranoid build.log                         # emails/IPs, plus high-entropy strays
```

It knows AWS keys, GitHub/GitLab/npm/PyPI/Hugging Face/Cloudflare/Grafana/Sentry/SendGrid/Stripe/
Slack/Discord/Twilio/Google-shaped tokens, JWTs, `Authorization:` headers, basic auth, cookies,
`postgres://user:pass@host` URLs, PEM and PGP-private-key blocks (as one secret, not thirty, and a key
that fits on one JSON line is still one secret), wallet seeds — the whole BIP39 English list, not a
guess at it — and chain credentials: `0x`+64 hex at a `*_KEY`/`*_PK`/`*_SIGNER`/`*_DEPLOYER` site,
`suiprivkey1…`, 87-88-character Solana base58 secret keys, JSON byte-array keypairs, Etherscan-family
`apikey=`, and RPC URLs with the key inside them (`alchemy.com/v2/`, `infura.io/v3/`, `quiknode.pro/`,
`ankr.com/<net>/`, `helius-rpc.com/?api-key=`). A Solana *address* is left in place, because that is
what the log is about. Plus a curated list of key names — `password`, `APP_KEY`, `SECRET_KEY_BASE`,
`*_SECRET`, `*_TOKEN`. `blot --list-types` prints the lot; `--keep TYPE` spares one on purpose.

## The long tail, and the agent that closes it

Detection is by shape and by name, so somebody's in-house key passes through. blot does not phone
home to fix that. It hands the judgement to a reviewer — human or agent — **without ever showing them
a secret**:

```sh
blot app.env --candidates --json --out app.safe.txt   # what survived, described not quoted
blot app.env --rules learned.json --out app.safe.txt --verify
```

`--candidates` reports each survivor's site name, character set, length, entropy and a masked shape
(`sk_l… 34 chars`), plus the redacted line it came from and a rule you can paste. `--rules FILE`
applies the shapes that reviewer named; `--dump-rules` hands you the built-in set to extend instead of
inventing one. `--json` puts all of it on stdout so the loop is scriptable. `skill/blot/SKILL.md` is
the playbook for driving it from an agent — symlink it into `~/.qoder/skills` and the loop becomes
`/blot`.

![the loop](docs/img/candidates.png)

## Two gates, not one

`--verify` re-scans the text blot produced and refuses to call it clean if anything recognisable is
still live. It deliberately ignores `--keep`: auditing a redaction against the same exceptions that
produced it is how a leak gets certified clean.

`--strict` adds the second gate — the candidate sweep has to come back empty too. That is the
difference between *nothing recognised survived* and *nothing recognisable survived*, and it is the
difference an agent can act on: 4 names the shapes, `--rules` teaches them, 0 means both gates passed.

| exit | meaning |
|---|---|
| 0 | clean — both gates passed |
| 2 | usage or I/O failure; nothing was written |
| 3 | a recognised secret is still live, with line numbers |
| 4 | nothing recognised survived, but an unnamed shape did |

![verify refusing](docs/img/verify.png)

## Limits, honestly

No longer limits: an unknown shape can be found (`--candidates`), refused (`--strict`) and learned
(`--rules`); a pathological rule is probed against short adversarial inputs and rejected before it can
hang the run; the reverse map refuses to land inside a git work tree; and a 111 MB log costs 27 MB of
memory, because lines are streamed through rather than collected and joined.

What is still true:

- **A secret that is unnamed, unstructured and low-entropy is invisible.** `--candidates` is what
  catches the next `footprint=`; nothing catches a value that looks exactly like the text around it.
- **Over-redaction is a failure too,** and the answer is a trade rather than a solution: the key-name
  list is curated rather than `.*key.*=`, a git sha beside `commit` stays put, and `--paranoid` buys
  reach with precision when you would rather lose the line than lose the token. One chain-specific
  example of the trade: an ed25519 secret key and a Solana *signature* are both 87-88 base58
  characters and indistinguishable on the page, so both are blotted; addresses are spared because they
  are 32-44 characters, nowhere near that length.
- **A bare seed that is mostly English but not on the list is missed.** The membership bar is 80% of
  BIP39, which is what keeps a twelve-word sentence in your report; a phrase under the bar is caught
  when it sits at a `seed=`, `mnemonic=` or `recovery_phrase=` site, because there the name says what
  the value is.
- **`--map` is the only copy** of the label-to-secret table — 0600, never silently overwritten.
  Publish it and you have published everything.
- **`--stable` is only as secret as its key file.** Labels are HMAC-SHA256 under
  `~/.config/blot/stable.key` (`--stable-key` to move it); lose it and every label changes, leak it
  and the labels in your report are a lookup table again.
- Not a DLP, not a compliance scanner, not a substitute for rotating what you leaked.

## Develop

```sh
python3 tests/test_blot.py    # 126 tests, stdlib only, no install step
```

MIT. If blot cost you a credential, the failure was the credential being there — but do open an
issue, the detectors only get better by being argued with.
