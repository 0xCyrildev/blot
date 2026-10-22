```
██████  ▄▄▄▄▄▄▄▄▄        ▀▀▀▀▀▀██████                  ▄▄▄▄▄▄▄▄▄▄▄▄         ▄▄▄▄▄▄██████▄▄▄▄▄▄▄▄
███████▀▀▀▀▀▀▀██████▄          ██████             ▄██████▀▀▀▀▀▀▀▀██████▄    ▀▀▀▀▀▀██████▀▀▀▀▀▀▀▀
████████▄▄▄▄▄██████▀▀          ███████▄▄▄▄▄▄▄▄    ▀▀██████▄▄▄▄▄▄██████▀▀          ██████▄▄▄▄▄▄▄▄

                         I take the secret out. I leave the context alone.
```
[![ci](https://github.com/0xCyrildev/blot/actions/workflows/ci.yml/badge.svg)](https://github.com/0xCyrildev/blot/actions/workflows/ci.yml)
[![python: 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](#install)
[![deps: none](https://img.shields.io/badge/dependencies-none-brightgreen)](#install)

I wrote this because I kept pasting build logs into issue trackers at midnight and noticing afterwards that one of them had a token in it. Not my token, usually, but definitely somebody's. So I built a filter that pulls credentials out, leaves behind something a reviewer can still read, and refuses to tell you it finished when it did not.

Pipe a log, a diff, a transcript or a report draft through me and every credential I recognise becomes a placeholder like `<JWT:1>`. The same secret always becomes the same placeholder, so your bug report stays internally consistent and you can still see which field leaked.

![blot on a log](docs/img/redact.png)

## Install

```sh
pipx install git+https://github.com/0xCyrildev/blot.git   # or: pip install ...
curl -o blot https://raw.githubusercontent.com/0xCyrildev/blot/main/blot.py && chmod +x blot
```

I am one Python file on the standard library, with no config, no telemetry and no network code. That last part is the whole point, since you are running me precisely so the text does not go anywhere.

## Use

```sh
cargo build --verbose 2>&1 | blot > safe-log.txt
blot draft.md --out draft.published.md --map draft.map.json
cat transcript.txt | blot --verify > /dev/null      # exits 3 rather than claiming a clean
blot app.env --rules learned.json --strict          # exits 4 until every shape has a rule
blot --pii --paranoid build.log                     # emails and IPs, plus high entropy strays
blot --stable incident.txt                          # same secret, same label, across separate runs
```

I know the vendor shapes you would expect: AWS, GitHub, GitLab, npm, Stripe, Slack, Discord, Sentry, Twilio, Google, JWTs, `Authorization:` headers and URLs carrying `user:pass@host`. Then there is the half that made this year interesting. Private key blocks collapse into one secret even when the whole key fits on one JSON line, PGP armor included. Wallet seeds are matched against the real 2048 word BIP39 list rather than a guess at it. EVM private keys at a `*_KEY` or `*_PK` site, `suiprivkey1…`, Solana base58 secret keys, JSON byte array keypairs, Etherscan family `apikey=` and RPC URLs with the key pasted straight into them all go too. A Solana address stays in your report, because that is the thing the log is actually about. `--list-types` prints everything, and `--keep TYPE` spares one on purpose.

## The long tail

Your in house key walks right past me, and I am not going to phone home to learn better, so I hand that judgement to a reviewer without showing either of us a secret.

```sh
blot app.env --candidates --json --out app.safe.txt   # what survived, described not quoted
blot app.env --rules learned.json --out app.safe.txt --verify
```

`--candidates` reports each survivor's site name, character set, length, entropy and masked shape, plus the redacted line it came from and a rule you can paste back. `--rules FILE` teaches me the shapes that reviewer named, and `skill/blot/SKILL.md` is the playbook for running the loop from an agent.

![the loop](docs/img/candidates.png)

## Two gates

`--verify` re scans what I produced and refuses to call it clean if anything recognisable is still standing. It ignores `--keep` deliberately, because auditing a redaction against the exceptions that produced it is how a leak earns a stamp of approval. `--strict` adds the other gate, that the candidate sweep must come back empty too, which is the difference between nothing recognised surviving and nothing recognisable surviving.

| exit | meaning |
|---|---|
| 0 | clean, both gates passed |
| 2 | usage or I/O failure, nothing was written |
| 3 | a recognised secret is still live, with line numbers |
| 4 | nothing recognised survived, but an unnamed shape did |

![verify refusing](docs/img/verify.png)

## Limits I have not solved

A secret that is unnamed, unstructured and low entropy is invisible to me. Over redaction is also a failure, so the key name list is curated and a git sha beside `commit` stays where it is. An ed25519 secret key and a Solana signature are the same 87 to 88 base58 characters and I cannot tell them apart, so both go, which is the correct direction to be wrong in. A bare phrase that is only mostly on the BIP39 list slips under the bar unless it sits at a `seed=` or `mnemonic=` site, where the name says what it is. `--map` is the only copy of the label to secret table, written 0600 and never silently overwritten. `--stable` is only as secret as `~/.config/blot/stable.key`. I am not a DLP, and I am not a substitute for rotating the thing you leaked.

## Develop

```sh
python3 tests/test_blot.py    # 126 tests, stdlib only, no install step
```

MIT. If I cost you a credential, the failure was the credential being in the file, but open an issue anyway, because these detectors only improve by being argued with.
