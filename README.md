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
blot --pii --paranoid build.log                         # emails/IPs, plus high-entropy strays
```

It knows AWS keys, GitHub/GitLab/npm/PyPI/Hugging Face/Cloudflare/Grafana/Sentry/SendGrid/Stripe/
Slack/Discord/Twilio/Google-shaped tokens, JWTs, `Authorization:` headers, basic auth, cookies,
`postgres://user:pass@host` URLs, PEM private key blocks (as one secret, not thirty), BIP39-shaped
word runs, and a curated list of key names — `password`, `APP_KEY`, `SECRET_KEY_BASE`, `*_SECRET`,
`*_TOKEN`. `blot --list-types` prints the lot; `--keep TYPE` spares one on purpose.

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

## It checks its own work

`--verify` re-scans the text blot produced and refuses to call it clean if anything recognisable is
still live. It deliberately ignores `--keep`: auditing a redaction against the same exceptions that
produced it is how a leak gets certified clean.

![verify refusing](docs/img/verify.png)

## Limits, honestly

- **Detection is by shape and by name.** A secret in a format blot does not know passes through —
  that is what `--candidates` is for. `--verify` uses the same eyes, so it proves *nothing recognised
  survived*, not *nothing survived*.
- **Over-redaction is also a failure.** That is why the key-name list is curated rather than
  `.*key.*=`, and why a git sha next to the word `commit` is left alone. `--paranoid` trades
  precision for reach when you would rather lose the line than lose the token.
- **A rule you supply is a regex you run.** blot compiles `--rules` as written and does not defend
  against a pathological one; it refuses a rule that could not work.
- **`--map` is the only copy** of the label-to-secret table, created 0600 and never overwritten.
  Publish that file and you have published everything.
- Not a DLP, not a compliance scanner, not a substitute for rotating what you leaked.

## Develop

```sh
python3 tests/test_blot.py    # 46 tests, stdlib only, no install step
```

MIT. If blot cost you a credential, the failure was the credential being there — but do open an
issue, the detectors only get better by being argued with.
