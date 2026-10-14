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

It knows AWS keys, GitHub/Stripe/Slack/Google/OpenAI-shaped tokens, JWTs, `Authorization:` headers,
basic auth, cookies, `postgres://user:pass@host` URLs, PEM private key blocks (as one secret, not
thirty), BIP39-shaped word runs, and a curated list of key names — `password`, `APP_KEY`,
`SECRET_KEY_BASE`, `*_SECRET`, `*_TOKEN`. `blot --list-types` prints the lot; `--keep TYPE` spares
one on purpose.

## It checks its own work

`--verify` re-scans the text blot produced and refuses to call it clean if anything recognisable is
still live. It deliberately ignores `--keep`: auditing a redaction against the same exceptions that
produced it is how a leak gets certified clean.

![verify refusing](docs/img/verify.png)

## Limits, honestly

- **Detection is by shape and by name.** A secret in a format blot does not know passes through.
  `--verify` uses the same eyes, so it proves *nothing recognised survived* — not *nothing survived*.
- **Over-redaction is also a failure.** That is why the key-name list is curated rather than
  `.*key.*=`, and why a git sha next to the word `commit` is left alone. `--paranoid` trades
  precision for reach when you would rather lose the line than lose the token.
- **`--map` is the only copy** of the label-to-secret table, created 0600 and never overwritten.
  Publish that file and you have published everything.
- Not a DLP, not a compliance scanner, not a substitute for rotating what you leaked.

## Develop

```sh
python3 tests/test_blot.py    # 34 tests, stdlib only, no install step
```

MIT. If blot cost you a credential, the failure was the credential being there — but do open an
issue, the detectors only get better by being argued with.
