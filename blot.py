#!/usr/bin/env python3
"""blot — take the live secrets out of text you are about to show someone.

Pipe a log, a diff, a transcript, a curl command or a report draft through it. Every credential it
recognises becomes a readable placeholder (`<JWT:2>`); the same secret always becomes the same
placeholder, so a bug report stays internally consistent after redaction. `--verify` re-scans the text
it produced and exits 3 rather than claiming a clean it did not check.

No network, no config, no telemetry. Stdlib only, one file.

  cargo build --verbose 2>&1 | blot > safe-log.txt
  blot draft.md --out draft.published.md --map draft.map.json    # the map is the only copy (0600)
  cat transcript.txt | blot --verify > /dev/null                 # exits 3 if anything survived

Detection is by shape and by name, so the long tail is somebody's in-house key. That tail is handled
by a reviewer rather than by a network call: `--candidates` reports what survived redaction, described
and never quoted, `--rules FILE` teaches blot the shapes that reviewer named, and `--json` lets the
whole loop be driven by an agent that is never shown a secret. `--dump-rules FILE` starts from the
built-in set instead of from nothing.

  blot app.log --json --candidates --out app.safe.txt   # an agent reads the report, not the log
  blot app.log --rules learned.json --strict            # ...and blot applies what it decided

Exit codes: 0 clean · 2 usage or I/O failure, nothing written · 3 a recognised secret is still live ·
4 refused by --strict, because nothing recognised survived but an unnamed shape did. Lines are
streamed, so memory tracks how many secrets a run found rather than how large the input was.
"""
import argparse
import hashlib
import hmac
import io
import json
import math
import os
import re
import string
import sys
import time

PROG = os.path.basename(sys.argv[0]).split(".")[0]
VERSION = "1.2.0"

# Named groups: `keep` is the context that stays visible (so a reader can still tell WHICH field was
# blotted), `sec` is the secret, `q`/`tail` preserve quoting. Order matters: specific prefixed forms
# first, generic key=value next, so a `token: ghp_...` line reports as GHTOKEN and not KV.
#
# The third field is a screen: literals such that ANY text the regex can match must contain at least
# one of them, case-insensitively. It is a necessary condition, never a heuristic — a screen that is
# wrong in that direction silently loses secrets, which is the one failure this tool cannot have. The
# regexes are long alternations and cost ~40x what a substring test costs on a line that cannot match
# (KV alone was 8.5s of an 18s run over a 12 MB log). An empty tuple means "always run it".
# Base58 (Bitcoin/Solana): alphanumerics minus the four characters that read alike — no 0, O, I, l.
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Bech32's data part: a 32-character alphabet, and `suiprivkey1` is a bech32 string's HRPs + `1`.
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _ci(word):
    """A case-insensitive literal written out, without the (?i) flag.

    Case folding is not local to the token: `(?<![a-z0-9])` and `(?=[A-Z])` mean different things
    folded and unfolded, and with (?i) set, `(?:[a-z0-9]+(?:[_.-]|(?=[A-Z])))*` — "a name ending in
    this token" — matched a lowercase run as any number of zero-width-split pieces. On a 64-hex
    private key that is `(a+)+` and the match never returned. The guard has to stay unfolded, so the
    literals are spelled out instead."""
    return "".join("[%s%s]" % (c.lower(), c.upper()) for c in word)


# A field name that ENDS in one of these as its own word: the token starts at a word boundary or at a
# camelCase junction, and nothing but a quote and spacing may follow it before the `:`/`=`. Both halves
# matter — `monkey=` ends in the letters key and `keyword=` starts with them. KV is deliberately not
# generalised to this, because `test_paranoid_reaches_the_vendor_names_the_list_cannot_hold` requires
# the default to stay quiet on `MYVENDOR_KEY=`; the chain rules below pair the name with a value shape
# narrow enough to be worth a label of its own.
EVM_TOKENS = ("key", "pk", "private", "signer", "deployer", "mnemonic")
JSON_TOKENS = ("key", "keypair", "keystore", "secret", "private", "wallet", "mnemonic")


def name_site(tokens):
    return (r"(?:(?<![A-Za-z0-9])|(?<=[a-z])(?=[A-Z]))(?:%s)[\"']?\s*[:=]\s*"
            % "|".join(_ci(t) for t in tokens))


NAME_SITE = name_site(EVM_TOKENS)
NAME_SITE_JSON = name_site(JSON_TOKENS)
RPC_FAMILIES = ("etherscan", "bscscan", "polygonscan", "arbiscan", "basescan", "ftmscan", "hecoinfo",
                "snowtrace")

RULES = [
    ("AWS", re.compile(r"\b(?P<sec>(?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANVA|APINA)[0-9A-Z]{12,20})\b"),
     ("akia", "asia", "aida", "aroa", "agpa", "aipa", "anva", "apina")),
    ("GHTOKEN", re.compile(r"\b(?P<sec>gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
     ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")),
    ("GOOGLEKEY", re.compile(r"\b(?P<sec>AIza[0-9A-Za-z_\-]{30,40})\b"), ("aiza",)),
    ("SLACK", re.compile(r"\b(?P<sec>xox[baprs]-[0-9A-Za-z-]{10,})\b"),
     ("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-")),
    ("SLACKWEBHOOK", re.compile(
        r"(?P<sec>https://hooks\.slack\.com/(?:services|wf/[TS])/[A-Za-z0-9/_\-]{8,})"),
     ("hooks.slack.com",)),
    ("DISCORDHOOK", re.compile(
        r"(?i)(?P<sec>https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/"
        r"\d{15,21}/[A-Za-z0-9_\-]{24,})"), ("/api/webhooks/",)),
    ("GITLAB", re.compile(r"\b(?P<sec>glpat-[A-Za-z0-9_\-]{20}(?:_\d{8})?)\b"), ("glpat-",)),
    ("NPM", re.compile(r"\b(?P<sec>npm_[A-Za-z0-9]{36})\b"), ("npm_",)),
    ("PYPI", re.compile(r"\b(?P<sec>pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,})"), ("pypi-agei",)),
    ("HUGGINGFACE", re.compile(r"\b(?P<sec>hf_[A-Za-z0-9]{34,})\b"), ("hf_",)),
    ("CLOUDFLARE", re.compile(r"\b(?P<sec>cfut_[A-Za-z0-9_\-]{20,})\b"), ("cfut_",)),
    ("GRAFANA", re.compile(r"\b(?P<sec>gl(?:sa|da|c|dc)_[A-Za-z0-9=_\-]{20,})\b"),
     ("glsa_", "glda_", "glc_", "gldc_")),
    ("SENTRY", re.compile(r"\b(?P<sec>sntrys_[A-Za-z0-9_\-]{40,})\b"), ("sntrys_",)),
    ("SENDGRID", re.compile(
        r"\b(?P<sec>SG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64})\b"), ("sg.",)),
    ("STRIPEWH", re.compile(r"\b(?P<sec>whsec_[A-Za-z0-9]{16,})\b"), ("whsec_",)),
    ("GOOAUTH", re.compile(r"\b(?P<sec>ya29\.[A-Za-z0-9_\-]{25,})"), ("ya29.",)),
    ("TWILIOSID", re.compile(
        r"(?i)(?P<keep>\baccount[_-]?sid\s*[:=]\s*)(?P<sec>(?:AC|SK)[0-9a-f]{32})\b"), ("sid",)),
    ("DIGITALOCEAN", re.compile(r"\b(?P<sec>dop_v1_[0-9a-f]{64})\b"), ("dop_v1_",)),
    ("VAULT", re.compile(r"\b(?P<sec>hvs_[A-Za-z0-9]{20,})\b"), ("hvs_",)),
    ("DOCKERHUB", re.compile(r"\b(?P<sec>dckr_pat_[A-Za-z0-9]{24,})\b"), ("dckr_pat_",)),
    ("NEWRELIC", re.compile(r"\b(?P<sec>NRAK-[A-Z0-9]{20,})\b"), ("nrak-",)),
    # A PEM block that arrived base64'd onto one line — what a secret looks like inside JSON, an env
    # var or a Terraform tfvars file, where the ----- markers the PEM state machine waits for never
    # appear. "LS0tLS1CRUdJTi" is `-----BEGIN` in base64, so it cannot fire on ordinary text.
    ("B64PEM", re.compile(r"\b(?P<sec>LS0tLS1CRUdJTi[A-Za-z0-9+/=]{20,})"), ("ls0tls1crudjti",)),
    ("AZURE", re.compile(
        r"(?i)(?P<keep>\baccountkey\s*[:=]\s*)(?P<sec>[A-Za-z0-9+/]{40,}={0,2})"), ("accountkey",)),
    # A JWK's "d" is the private exponent. Requiring "kty" in the same span is what keeps this off
    # every other `"d":` in the world — a description, a dimension, a debug flag.
    ("JWK", re.compile(
        r'''(?i)"kty"\s*:\s*"[A-Za-z]+"\s*,[^{}]*?"d"\s*:\s*"(?P<sec>[A-Za-z0-9+/=]{20,})"'''),
     ('"kty"',)),
    # Header names that always carry a credential, and are not "authorization".
    ("HDR", re.compile(
        r"(?i)(?P<keep>\b(?:x-api-key|x-goog-api-key|x-amz-security-token|anthropic-api-key|"
        r"openai-api-key|x-slack-token|x-linkedin-access-token)\s*[:=]\s*)"
        r"(?P<sec>[^\s\"']{12,})"), ("key", "token")),
    ("STRIPE", re.compile(r"\b(?P<sec>(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{10,})\b"),
     ("sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_")),
    ("LLMTOKEN", re.compile(r"\b(?P<sec>sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,})\b"), ("sk-",)),
    # eyJ is `{"` in base64url; every real JWT starts with it, so this cannot hit ordinary prose.
    # The screen is "eyj" because screens are tested against the lowercased line — the literal this
    # one screens for is mixed case, and a screen copied from the regex would never fire.
    ("JWT", re.compile(r"\b(?P<sec>eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{8,})"),
     ("eyj",)),
    ("URLCREDS", re.compile(
        r"(?P<sec>[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@'\"]{1,64}:[^\s@/'\"]{1,128}@[^\s/'\"]*)"),
     ("://",)),
    ("BEARER", re.compile(
        r"(?i)(?P<keep>\b(?:authorization|proxy-authorization|x-api-token)\s*[:=]\s*)?"
        r"(?P<sec>bearer\s+[A-Za-z0-9._~+/=-]{12,})"), ("bearer",)),
    ("BASIC", re.compile(r"(?i)(?P<keep>\bbasic\s+)(?P<sec>[A-Za-z0-9+/]{12,}={0,2})"), ("basic",)),
    ("AUTHSCHEME", re.compile(
        r"(?i)(?P<keep>\b(?:ssws|dhba|aws4-hmac-sha256)\s+)(?P<sec>[A-Za-z0-9._~+/=\-]{16,})"),
     ("ssws", "dhba", "aws4-hmac-sha256")),
    # `Authorization: <bare token>` with no scheme word at all, which API gateways do constantly.
    # Runs after BEARER/BASIC/AUTHSCHEME, and its lookahead leaves their work to them.
    ("AUTHHEADER", re.compile(
        r"(?i)(?P<keep>\bauthorization\s*[:=]\s*)(?!bearer\b|basic\b|digest\b|ssws\b|dhba\b)"
        r"(?P<sec>[A-Za-z0-9._~+/=\-]{16,})"), ("authorization",)),
    ("COOKIE", re.compile(
        r"(?i)(?P<keep>\b(?:cookie|set-cookie)\s*[:=]\s*)(?P<sec>[^\r\n\"']{8,})"), ("cookie",)),
    # --- chain keys, part 1: the site itself names the service ------------------------------------
    # Every shape below is something a public object also has, so none of them may fire on shape
    # alone: `0x`+64 hex is a transaction hash, 87-88 base58 is also a signature, 32-44 base58 is every
    # address on Solana. What makes a match is either a name nobody gives a public thing, or a length
    # no public object reaches.
    ("RPCURL", re.compile(
        r"(?i)(?P<keep>https?://(?:[a-z0-9\-]+\.)*"
        r"(?:alchemy\.com/v2/|infura\.io/v3/|quiknode\.pro/(?:[a-z0-9\-]+/)*|"
        r"ankr\.com/[a-z0-9\-]{2,}/|helius-rpc\.com/\?api-key=))(?P<sec>[A-Za-z0-9_\-]{16,})"),
     ("alchemy.com/v2/", "infura.io/v3/", "quiknode.pro/", "ankr.com/",
      "helius-rpc.com/?api-key=")),
    # The family is in the pattern, not inferred: `?apikey=<31 alnum>` on a host nobody has heard of is
    # not evidence that Etherscan was leaked. Etherscan and its forks all take the key in the query
    # string, and the key is mixed-case alphanumerics with no prefix to screen on.
    ("ETHERSCAN", re.compile(
        r"(?i)(?P<keep>(?:https?://)?(?:[a-z0-9.\-]*[.\-])?(?:%s)(?:\.[a-z]{2,})?(?:/api)?"
        r"(?:[\w=?&+.\%%\-]*[&?])?[_.\-]?api[_-]?key\s*[:=]\s*)"
        r"(?P<sec>[A-Za-z0-9]{24,40})" % "|".join(RPC_FAMILIES)),
     RPC_FAMILIES),
    # Sui writes a secret key as a bech32 string: `suiprivkey1` then the 32-character data alphabet.
    # No boundary guard on purpose — a key concatenated onto other text is still the key, and forcing
    # a boundary would turn a miss into a leak.
    ("SUIPRIVKEY", re.compile(r"(?i)(?P<sec>suiprivkey1[%s]{50,})" % BECH32), ("suiprivkey1",)),
    # At a name whose whole job is to hold a phrase, the value does not stop at the first space. KV's
    # `sec` class excludes whitespace, so `mnemonic=witch collapse practice feed ...` blotted `witch`
    # and left the other eleven words of the seed on the page. Three names only — seed, mnemonic,
    # recovery — because those are the fields where "everything after the =" really is the secret.
    # Words may be space- or comma-separated; a comma list is how most backup dumps read.
    ("KVPHRASE", re.compile(
        r"(?i)(?P<keep>[\"']?(?<![a-z])(?:seed|mnemonic|recovery)"
        r"(?:[ _-]?(?:phrase|passphrase|words?|key|backup))?[\"']?\s*[:=]\s*)"
        r"(?P<q>[\"']?)(?P<sec>[A-Za-z][A-Za-z0-9+/]*"
        r"(?:(?:[ \t]+|,[ \t]*)[A-Za-z][A-Za-z0-9+/]*){1,})(?P<tail>(?P=q))"),
     ("seed", "mnemonic", "recovery")),
    # Curated on purpose, not `.*key.*=`: over-redacting a log is also a failure, and it is the one
    # that quietly destroys the report you were trying to publish. Long tail -> --paranoid.
    # The boundaries on `pass` and the otp family are load-bearing: without them `bypass:`,
    # `compass:` and `footprint:` all contain a secret name and get blotted anyway.
    ("KV", re.compile(
        r"(?i)(?P<keep>[\"']?(?:(?<![a-z])pass(?:word|phrase|ed|wd)?(?![a-z])|"
        r"(?<![a-z])pwd(?![a-z])|secret|secret[_-]?key(?:[_-]?base)?|"
        r"api[_-]?key|apikey|app[_-]?key|master[_-]?key|encryption[_-]?key|signing[_-]?key|"
        r"access[_-]?key(?:[_-]?id)?|access[_-]?token|private[_-]?key|auth[_-]?token|"
        r"refresh[_-]?token|session[_-]?token|bearer[_-]?token|id[_-]?token|token|seed|mnemonic|"
        r"recovery[_-]?phrase|\b(?:totp|hotp|otp|mfa[_-]?code)\b|client[_-]?secret|"
        r"webhook[_-]?secret)[\"']?\s*[:=]\s*)(?P<q>[\"']?)(?P<sec>[^\"'\s,;}\]]{5,})"
        r"(?P<tail>(?P=q))"),
     ("pass", "pwd", "secret", "key", "token", "seed", "mnemonic", "recovery", "phrase", "otp")),
    # --- chain keys, part 2: the shape decides, and these run after KV -----------------------------
    # After KV on purpose. `API_KEY=0x…` and `PRIVATE_KEY=0x…` are already named secrets, and calling
    # one of them an EVM private key would be a claim about which chain was leaked that the line does
    # not support. These three fire on the sites KV's curated list cannot see.
    ("EVMPRIVKEY", re.compile(
        r"(?P<keep>" + NAME_SITE + r")(?P<q>[\"']?)(?P<sec>0x[0-9a-fA-F]{64})(?P<tail>(?P=q))"),
     ("0x",)),
    # A Solana keypair dumped as JSON is 64 bytes of decimal in brackets — no encoding, no prefix, so
    # the array is only a keypair because of the name in front of it. 32 entries minimum: fewer than
    # that is a coordinate, a colour, a page of results.
    ("SOLKEYJSON", re.compile(
        r"(?P<keep>" + NAME_SITE_JSON + r")\[\s*(?P<sec>\d{1,3}(?:\s*,\s*\d{1,3}){31,127})\s*\]"),
     ("key", "secret", "private", "wallet")),
    # An ed25519 secret key is 64 bytes, which is 87 or 88 base58 characters and has no other marking,
    # so this is the one built-in with no screen literal — see GATED_NO_SCREEN. A signature is the same
    # length and is public; blotting it is the deliberate side of that trade, and an address (32-44
    # characters) is nowhere near this length and stays in the report.
    ("SOLPRIVKEY", re.compile(r"\b(?P<sec>[%s]{87,88})\b" % BASE58), ()),
]

PII = (("EMAIL", re.compile(r"\b(?P<sec>[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+)\b"), ("@",)),
       ("IPV4", re.compile(r"\b(?P<sec>(?:\d{1,3}\.){3}\d{1,3})\b"), (".",)),
       ("PHONE", re.compile(r"\b(?P<sec>\+?\d[\d\s\-()]{8,14}\d)\b"), ()))

# ` BLOCK` is load-bearing, not decoration: PGP's ASCII armor writes `-----BEGIN PGP PRIVATE KEY
# BLOCK-----` and `[A-Z ]*PRIVATE KEY` cannot reach past the space before it, so the single most
# common private-key export format passed straight through. PUBLIC KEY blocks stay unmatched on
# purpose — a public key is not a secret, and blotting one removes the fingerprint a reader needs.
PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----")
PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----")

# A wallet seed is 12, 15, 18, 21 or 24 words drawn from ONE fixed list of 2048. That is what makes
# it detectable without a vendor prefix, and it is why the list is embedded rather than guessed at:
# a seed detector with a hole in it loses seeds silently. Generated from python-mnemonic's
# wordlist/english.txt and cross-checked word-for-word against @scure/bip39's copy — the two
# independent sources agree exactly. `TestSeedPhrase` re-asserts the shape so a bad edit cannot pass.
BIP39 = (
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol",
    "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already",
    "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused",
    "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle",
    "announce", "annual", "another", "answer", "antenna", "antique", "anxiety",
    "any", "apart", "apology", "appear", "apple", "approve", "april", "arch",
    "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around",
    "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork",
    "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete",
    "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august",
    "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
    "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor",
    "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana",
    "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket",
    "battle", "beach", "bean", "beauty", "because", "become", "beef", "before",
    "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
    "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike",
    "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket",
    "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue",
    "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus",
    "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce",
    "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze",
    "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken",
    "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget",
    "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden",
    "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage",
    "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp",
    "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon",
    "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet",
    "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog",
    "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling",
    "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk",
    "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap",
    "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar",
    "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify",
    "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb",
    "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club",
    "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee",
    "coil", "coin", "collect", "color", "column", "combine", "come", "comfort",
    "comic", "common", "company", "concert", "conduct", "confirm", "congress",
    "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy",
    "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country",
    "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft",
    "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek",
    "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch",
    "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry",
    "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain",
    "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance",
    "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris",
    "decade", "december", "decide", "decline", "decorate", "decrease", "deer",
    "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise",
    "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy",
    "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail",
    "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary",
    "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner",
    "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss",
    "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy",
    "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey",
    "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama", "drastic",
    "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop",
    "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty",
    "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily",
    "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort",
    "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element",
    "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge",
    "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless",
    "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy",
    "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry",
    "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion",
    "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics",
    "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange",
    "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit",
    "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain",
    "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric", "face",
    "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family", "famous",
    "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue",
    "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel",
    "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction",
    "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger",
    "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix",
    "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip", "float",
    "flock", "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog",
    "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork",
    "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile",
    "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost",
    "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future",
    "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage",
    "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze",
    "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant",
    "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare",
    "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
    "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip",
    "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity",
    "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt",
    "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit", "hair",
    "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh", "harvest",
    "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog",
    "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill",
    "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday",
    "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital",
    "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor",
    "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid",
    "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness",
    "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse",
    "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry",
    "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury",
    "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside",
    "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve",
    "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar",
    "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke",
    "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just",
    "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind",
    "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife",
    "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp",
    "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava",
    "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave",
    "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length",
    "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library",
    "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion",
    "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster", "local",
    "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love",
    "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics",
    "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make",
    "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple",
    "marble", "march", "margin", "marine", "market", "marriage", "mask", "mass",
    "master", "match", "material", "math", "matrix", "matter", "maximum", "maze",
    "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody",
    "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit",
    "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk",
    "million", "mimic", "mind", "minimum", "minor", "minute", "miracle", "mirror",
    "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model",
    "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon",
    "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain",
    "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle",
    "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth",
    "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near",
    "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest",
    "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble",
    "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note",
    "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut",
    "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious",
    "occur", "ocean", "october", "odor", "off", "offer", "office", "often", "oil",
    "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online",
    "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit",
    "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich",
    "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over",
    "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair",
    "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade",
    "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol",
    "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant",
    "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit",
    "person", "pet", "phone", "photo", "phrase", "physical", "piano", "picnic",
    "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe",
    "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play",
    "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar",
    "pole", "police", "pond", "pony", "pool", "popular", "portion", "position",
    "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice",
    "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent",
    "price", "pride", "primary", "print", "priority", "prison", "private", "prize",
    "problem", "process", "produce", "profit", "program", "project", "promote",
    "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding",
    "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase",
    "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality",
    "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit",
    "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally",
    "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven",
    "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive",
    "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region",
    "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain",
    "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair",
    "repeat", "replace", "report", "require", "rescue", "resemble", "resist",
    "resource", "response", "result", "retire", "retreat", "return", "reunion",
    "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride",
    "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk", "ritual",
    "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance",
    "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal",
    "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle",
    "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same",
    "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say",
    "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science",
    "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea",
    "search", "season", "seat", "second", "secret", "section", "security", "seed",
    "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence",
    "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
    "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine",
    "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove",
    "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight",
    "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since",
    "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski",
    "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice",
    "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small", "smart",
    "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap",
    "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid", "solution",
    "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup",
    "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
    "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit",
    "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread",
    "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff",
    "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel",
    "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone",
    "stool", "story", "stove", "strategy", "street", "strike", "strong", "struggle",
    "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success",
    "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny",
    "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise",
    "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm",
    "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom",
    "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank",
    "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell",
    "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that",
    "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three",
    "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt",
    "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco",
    "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow",
    "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch",
    "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town",
    "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap",
    "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick",
    "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly",
    "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel",
    "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist",
    "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle",
    "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique",
    "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update",
    "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use",
    "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague",
    "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault",
    "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version",
    "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video",
    "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit",
    "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume",
    "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want",
    "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way",
    "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend",
    "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when",
    "where", "whip", "whisper", "wide", "width", "wife", "wild", "will", "win",
    "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise",
    "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work",
    "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong",
    "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone",
    "zoo"
)
BIP39_SET = frozenset(BIP39)
assert len(BIP39) == 2048 and len(BIP39_SET) == 2048, "the embedded wordlist is not BIP39 English"

SEED_COUNTS = (24, 21, 18, 15, 12)          # longest first: a 24-word dump is one secret, not two
SEED_MIN_WORDS = 12
# "at least 80% of the window is on the list", as ceil(4c/5): 12->10, 15->12, 18->15, 21->17,
# 24->20. Not 100%, because a seed transcribed from a photo of a sheet has words misread in it.
SEED_MIN_HITS = {c: (4 * c + 4) // 5 for c in SEED_COUNTS}
SEED_RUN = re.compile(r"[A-Za-z]+(?:[ \t]+[A-Za-z]+)*")

# The last-resort rule fires only where a bare token really is a value — after a key, inside a quote,
# or as a --flag= argument. Applied to arbitrary prose it eats every long base64-looking word.
ENTROPY_SITE = re.compile(
    r"(?P<keep>(?:[\w.\-]+\s*[:=]\s*[\"']?|--[\w.\-]+=|[\"']))(?P<sec>[A-Za-z0-9+/_\-]{24,}={0,3})")
BENIGN_CONTEXT = re.compile(r"(?i)\b(?:commit|tree|parent|blob|sha1|sha256|checksum|integrity|"
                            r"merkle|blockhash|digest|etag|detached|head)\b")
HEX = set("0123456789abcdefABCDEF")
# How much text either side of a bare hex string counts as "context for it". Whole-line context made
# every 40-hex secret on a line that merely said `blob` immune, so the decision is local.
CTX_WINDOW = 48
# A value at a key/quote/--flag= site is blotted by the last-resort rule above this many bits per
# character. 3.0 spare bits is roughly "not English, not a version number, not a git sha".
PARANOID_MIN_BITS = 3.0
# --json lists every blot, which on a log where every line carries a secret would otherwise grow
# without bound. Past this the report says so rather than lying by omission.
MAX_FINDINGS = 20000
# A label with 16+ credential-shaped characters still glued to it: `<JWT:1>eyJhbGciOiJI...` is what a
# half-redacted secret looks like, and verify must not be fooled by the label in front of it.
LABEL_TAIL = re.compile(r"<[A-Z][A-Z0-9_]*:[^>]*>[^\s<]*[A-Za-z0-9_/+\-]{16,}")


ALL_TYPES = {t for t, _, _ in RULES} | {t for t, _, _ in PII} | {"PRIVKEY", "SEEDPHRASE", "ENTROPY"}
# The types that can appear *inside a label*, which is not the same set as the rule names: URLCREDS
# is the rule, `URLCREDENTIALS` is what gets printed. A guard built from rule names alone would not
# recognise the label that rule leaves behind and would blot inside it.
LABEL_TYPES = ALL_TYPES | {"URLCREDENTIALS"}


def label_pattern(types):
    """Recognise a placeholder, and only a placeholder.

    The guard this builds is what stops a later, more generic rule from re-blotting text an earlier
    rule already replaced — so its false-positive cost is a secret that survives, and it used to pay
    it: matched case-insensitively with an optional `>`, `<ss` inside `password=pa<ss1word99` looked
    like a label and shielded the secret. Type names come from the set this tool can actually emit,
    compared case-sensitively, and the tag must be followed by a colon. The closing `>` stays
    optional: a rule whose character class stops at `>` can match a truncated label, and one that
    then re-blots it corrupts the only token pointing back to the secret.

    The set has to include what --rules adds. An earlier version matched only `<[A-Z]+:`, so the
    placeholder left by a rule named INTERNAL_KEY was not recognised as a placeholder and got blotted
    a second time."""
    alt = "|".join(sorted((re.escape(t) for t in types), key=lambda s: (-len(s), s)))
    return re.compile(r"<(?:%s):[A-Za-z0-9]*>?" % alt)


# --- candidate sweep -----------------------------------------------------------------------------
# What an agent looks at: everything that survived redaction and still *shaped* like a secret. The
# sweep runs on the blotted line, so by construction it never sees what a rule already caught, and
# because a candidate is reported rather than replaced it can be far less careful than a detector —
# the cost of a noisy candidate is one glance, the cost of a noisy rule is a useless report.
SECRETISH = re.compile(r"(?i)(?:key|secret|token|pass|pwd|passwd|credential|auth|salt|signature|"
                       r"private|cert|seed|mnemonic|otp|bearer|api)")
# The same words as plain substrings, for the per-line prefilter: the 16-branch regex cost 5.7s per
# 12 MB where these cost 0.5s, and it runs on every line rather than on the few that carry a name.
# Soundness needs only that every line SECRETISH can match is let through — "passwd" contains "pass",
# so the shorter list is still a superset of what matters. The deciding test is inside _sweep.
SECRET_WORDS = ("key", "secret", "token", "pass", "pwd", "credential", "auth", "salt", "signature",
                "private", "cert", "seed", "mnemonic", "otp", "bearer", "api")
NAMED_SITE = re.compile(r"(?i)(?P<key>[\w.\-]{2,64})\s*[:=]\s*[\"']?(?P<sec>[^\s\"',;}\]]{6,})")
ANON_SITE = re.compile(r"(?P<keep>[\w.\-]+\s*[:=]\s*[\"']?)(?P<sec>[A-Za-z0-9+/_\-]{20,}={0,3})")
DIGIT_RUN = re.compile(r"(?<![\w.])(?P<sec>\d{13,19})(?![\w.])")
# PANs in the wild are spaced or dashed, and ISO timestamps are the thing most likely to be mistaken
# for one, so the groupings are spelled out rather than left to `(?:\d[ -]?){12,22}`.
CARD_RUN = re.compile(r"(?<![\d.\-])(?P<sec>\d{13,19}|\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}"
                      r"|\d{4}[ -]\d{6}[ -]\d{5})(?![\d.\-])")
# The classes below are what the *unnamed* half of a leak looks like: a secret with no key name in
# front of it. They are reported, never replaced, so they can be far less careful than a detector —
# the cost of a noisy candidate is one glance, the cost of a noisy rule is a useless report.
BARE_SECRET = re.compile(r"(?P<sec>\b[A-Za-z0-9+/_\-]{20,}={0,3}\b)")
BARE_MIN_BITS = 4.0
HEX_SECRET = re.compile(r"\b(?P<sec>(?:0x)?[0-9a-fA-F]{40}|(?:0x)?[0-9a-fA-F]{64})\b")
UUID_SECRET = re.compile(r"\b(?P<sec>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                         r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b")
# A TOTP seed is 16-32 characters of base32 and appears in provisioning dumps with no name at all.
BASE32_SECRET = re.compile(r"\b(?P<sec>[A-Z2-7]{16,32}={0,1})\b")
# Union of what the classes that carry no key name need: a long token, a long digit run, a spaced
# PAN, a UUID prefix, a base32 seed. Together with SECRETISH (which is what the named class needs)
# it is a necessary condition for any candidate at all, so a line with none of them skips eight
# regexes. The spaced and dashed shapes are spelled out because `\\d{13,}` and `[A-Za-z0-9+/_-]{20,}`
# do not match them — leaving those out would hide card numbers and UUIDs, not just skip work.
CAND_ANY = re.compile(r"[A-Za-z0-9+/_\-]{20,}|\d{13,}|[A-Z2-7]{16,}"
                      r"|\d{4}[ -]\d{4}[ -]\d{4}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-")
DIGITS = set("0123456789")
ALNUM = set(string.ascii_letters + string.digits)
B64 = ALNUM | set("+/=_-")


def classify(tok):
    s = set(tok)
    if s <= DIGITS:
        return "digits"
    if s <= DIGITS | set("abcdefABCDEFxX"):
        return "hex"
    if s <= ALNUM:
        return "alnum"
    if s <= B64:
        return "base64ish"
    return "mixed"


def mask(tok):
    """A candidate is described, never quoted. Four leading characters are enough to recognise a
    vendor prefix; the length and the character set carry the rest of what a rule needs."""
    if len(tok) < 12:
        return "%d chars" % len(tok)
    return "%s… %d chars" % (tok[:4], len(tok))


def suggest_rule(name, tok):
    """A starting point an agent can accept or edit, in the shape --rules takes."""
    site = re.escape(name) if name else r"[\w.\-]+"
    return {"name": (name or "unnamed").upper().replace("-", "_").replace(".", "_"),
            "regex": r"(?i)(?P<keep>\b%s\s*[:=]\s*)(?P<sec>[^\s\"',;}\]]{%d,})"
                     % (site, min(len(tok), 8)),
            "screen": [name.lower()] if name else []}


def near(text, lo, hi, window=CTX_WINDOW):
    return text[max(0, lo - window):hi + window]


# Every rule has at least one screen literal, so "none of them are on this line" is a necessary
# condition for "no rule can match this line". Testing that as one alternation costs one C pass
# instead of ~70 Python-level substring checks per line, which is what the per-rule screens add up
# to on a 200k-line log.
SCREEN_ANY = re.compile("|".join(re.escape(s) for _t, _rx, sc in RULES for s in sc))
# SOLPRIVKEY is the one built-in that cannot screen: a run of 87-88 base58 characters is the whole
# evidence, and no literal inside it is necessary. Rather than disable the shortcut for every rule
# (which costs ~40 regex searches per line, on every line), the union gains a branch that is a
# necessary condition for exactly that rule. The lookbehind matters: without it, a 40,000-character
# word would make the engine try 87 characters at every position.
SOL_BASE58_GATE = re.compile(r"(?<![%s])[%s]{87,88}" % (BASE58, BASE58))
GATED_NO_SCREEN = {"SOLPRIVKEY"}


def entropy(tok):
    """Bits per character. The threshold below is written in bits, so this must be log2: measured in
    nats, the ceiling for a hex string is ln(16)=2.77, and no 40-hex key could ever reach 3.0."""
    if not tok:
        return 0.0
    counts = {}
    for c in tok:
        counts[c] = counts.get(c, 0) + 1
    n = float(len(tok))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def luhn(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


STABLE_KEY_BYTES = 32
STABLE_KEY_MIN_BYTES = 16
STABLE_TAG_HEX = 8


def stable_key_path(override=None):
    """Where the --stable key lives: --stable-key, else $XDG_CONFIG_HOME/blot/stable.key."""
    if override:
        return os.path.expanduser(override)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "blot", "stable.key")


def load_stable_key(path, force=False):
    """Read the HMAC key behind --stable, generating one on first use. Returns (key, created, error).

    Refusing is the default wherever the alternative is a quietly weaker label. A group-readable key
    hands the label→secret dictionary to whoever can read that directory, which is the exact property
    an unsalted hash used to give away; a short key is one brute-force away from the same place. Both
    are worth an error message over a silent degradation."""
    try:
        with open(path, "rb") as fh:
            key = fh.read().strip()
            mode = os.fstat(fh.fileno()).st_mode & 0o777
    except FileNotFoundError:
        key = os.urandom(STABLE_KEY_BYTES)
        parent = os.path.dirname(path) or "."
        try:
            os.makedirs(parent, mode=0o700, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            return None, False, "cannot create the --stable key at %s: %s" % (
                path, getattr(exc, "strerror", None) or exc)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        return key, True, None
    except OSError as exc:
        return None, False, "%s: %s" % (path, getattr(exc, "strerror", None) or exc)
    if not force and (mode & 0o077):
        return None, False, (
            "%s: the --stable key is mode %03o. Whoever can read it can rebuild, for any guess they "
            "like, the label that guess produces — which is the property --stable is meant to keep for "
            "you alone. chmod 600 it, or pass --force on a box with no real permissions."
            % (path, mode))
    if len(key) < STABLE_KEY_MIN_BYTES:
        return None, False, ("%s: the --stable key is %d bytes. Under %d it is a guess away from being "
                             "found and --stable becomes decoration."
                             % (path, len(key), STABLE_KEY_MIN_BYTES))
    return key, False, None


class Blotter:
    """One Blotter per run: the label table lives here, which is what makes redaction consistent."""

    def __init__(self, stable=False, keep=(), pii=False, paranoid=False, screen=True, rules=None,
                 candidates=False, stable_key=None):
        self.stable = stable
        if stable and stable_key is None:
            stable_key, _created, err = load_stable_key(stable_key_path())
            if err:
                raise InputError(err)
        self.stable_key = stable_key
        self.keep = {k.upper() for k in keep}
        self.pii = pii
        self.paranoid = paranoid
        self.candidates = candidates
        # screen=False runs every regex on every line whether or not it can match. It exists so the
        # suite can prove the screens cost nothing in correctness, not just in seconds.
        self.screen = screen
        # Rules loaded from --rules go first: a pattern someone wrote for their own stack beats a
        # generic guess, and the label it produces is the one they will read in the report.
        self.rules = list(rules or []) + RULES
        # A custom rule may arrive with no screen, and then the union-of-screens shortcut is not
        # sound for it, so the shortcut is only built when every active rule screens for something —
        # or is one of the built-ins whose shape the shortcut carries itself.
        self._prefilter = SCREEN_ANY if all(sc or typ in GATED_NO_SCREEN
                                            for typ, _rx, sc in self.rules) else None
        # The placeholder guard has to know the labels *this* run can emit, --rules names included,
        # or a generic rule re-blots inside a label a custom one left behind.
        self.label_re = label_pattern(LABEL_TYPES | {t for t, _, _ in self.rules})
        self.labels = {}
        self.counts = {}
        self.cands = {}
        self.findings = []
        self.findings_capped = False
        self.lines = 0
        self._n = {}
        self._lineno = 0
        self._hit_lines = {}
        self._line_secrets = {}
        self._in_pem = False
        self._pem_lines = 0

    def label(self, typ, secret):
        if secret in self.labels:
            return self.labels[secret]
        if self.stable:
            # Keyed, not a bare digest: `<KV:bfd361>` from unsalted sha1[:6] was a confirmation
            # oracle, one candidate string per dictionary entry with nothing to hide the match. HMAC
            # over the same secret with a key only the operator holds keeps the labels consistent
            # across runs and unbuildable from the redacted text alone.
            tag = hmac.new(self.stable_key, secret.encode("utf-8", "replace"),
                           hashlib.sha256).hexdigest()[:STABLE_TAG_HEX]
        else:
            self._n[typ] = self._n.get(typ, 0) + 1
            tag = str(self._n[typ])
        lab = "<%s:%s>" % (typ, tag)
        self.labels[secret] = lab
        self.counts[typ] = self.counts.get(typ, 0) + 1
        return lab

    def _apply(self, text, typ, rx):
        """Return (new_text, n_replacements). Rules that must not run are skipped by the caller."""
        hits = [0]

        def sub(m):
            # A later, more generic rule must not eat a placeholder an earlier one left behind:
            # `password: 1>` inside `<PASSWORD:1>` is not a credential, and re-blotting it corrupts
            # the label that is the report's only reference back to the secret.
            if self.label_re.search(m.group(0)):
                return m.group(0)
            hits[0] += 1
            gd = m.groupdict()
            keep = gd.get("keep") or ""
            q = gd.get("q") or ""
            sec = m.group("sec")
            if typ == "URLCREDS":
                scheme, rest = sec.split("://", 1)
                host = rest.rpartition("@")[2]
                # Through the label table like every other secret. It used to return a fixed
                # "<URLCREDENTIALS>" string, which meant the run's count under-reported and --map
                # silently omitted the credential, so the file sold as the complete inverse of the
                # redaction was missing a row.
                lab = self.label("URLCREDENTIALS", sec)
                self._note(typ, lab)
                return "%s%s://%s@%s" % (keep, scheme, lab, host)
            lab = self.label(typ, sec)
            self._note(typ, lab)
            return "%s%s%s%s" % (keep, q, lab, q)

        new = rx.sub(sub, text)
        return new, hits[0]

    def _note(self, typ, lab):
        """Where a secret was, for --json: the label and the line, never the value."""
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append({"line": self._lineno, "type": typ, "label": lab})
        else:
            self.findings_capped = True

    def _seed_spans(self, text):
        """Maximal runs of plain words that contain a BIP39-length window clearing the membership bar.

        The whole run is taken, not just the window. A seed is ordered words, so blotting twelve of a
        thirteen-word run and leaving the thirteenth in place hands a reader the complete phrase with
        one word missing from the label instead of from the secret; taking the run over-redacts an
        adjacent "restored" and hides nothing. Membership is summed with a prefix array so the scan is
        one pass per run rather than one slice per window, and a run whose total membership cannot
        reach the bar is dropped without looking at any window at all — that is what keeps a 40,000
        word log line linear."""
        spans = []
        for run in SEED_RUN.finditer(text):
            words = run.group(0).split()
            n = len(words)
            if n < SEED_MIN_WORDS:
                continue
            prefix = [0] * (n + 1)
            for i, w in enumerate(words):
                # Every BIP39 word is lowercase, so try the set first and only fold case for a word
                # that missed — `.lower()` on every word of every long line is an allocation each.
                hit = w in BIP39_SET or (len(w) <= 8 and w.lower() in BIP39_SET)
                prefix[i + 1] = prefix[i] + (1 if hit else 0)
            if prefix[n] < SEED_MIN_HITS[SEED_MIN_WORDS]:
                continue
            for i in range(n - SEED_MIN_WORDS + 1):
                if any(prefix[i + c] - prefix[i] >= SEED_MIN_HITS[c]
                       for c in SEED_COUNTS if i + c <= n):
                    spans.append((run.start(), run.end()))
                    break
        return spans

    def blot_line(self, line):
        """Returns (blotted_line, hit_count). Interior PEM lines collapse to nothing: a key block is
        one secret, not thirty, and a report should say so once."""
        self._lineno += 1
        if self._in_pem:
            self._pem_lines += 1
            if PEM_END.search(line):
                self._in_pem = False
            return "", self._pem_lines
        out = line
        hits = 0
        pos = 0
        while True:
            m = PEM_BEGIN.search(out, pos)
            if not m:
                break
            lab = self.label("PRIVKEY", "<pem-block>")
            self._note("PRIVKEY", lab)
            hits += 1
            end = PEM_END.search(out, m.end())
            if end:
                # Replace the block, not just its opening marker: inside JSON, an env var or a tfvars
                # file the whole key sits on one line and BEGIN/END share it. The text around it is
                # the reader's context and stays where it is.
                out = out[:m.start()] + lab + out[end.end():]
                pos = m.start() + len(lab)
            else:
                # Nothing after a BEGIN marker on its own line is prose — it is key material, and the
                # block is still open. `_in_pem` is set only here, so a block that closed on this line
                # cannot swallow the next one.
                out = out[:m.start()] + lab
                self._in_pem = True
                self._pem_lines = 1
                break
        # A 12-word phrase needs at least 11 separators, which is cheaper to count than to scan.
        if out.count(" ") + out.count("\t") >= SEED_MIN_WORDS - 1:
            for a, b in self._seed_spans(out):
                lab = self.label("SEEDPHRASE", out[a:b])
                self._note("SEEDPHRASE", lab)
                out = out[:a] + lab + out[b:]
                hits += 1
        low = out.lower()
        if (not self.screen or self._prefilter is None or self._prefilter.search(low)
                or SOL_BASE58_GATE.search(out)):
            for typ, rx, screen in self.rules:
                if typ in self.keep:
                    continue
                if self.screen and screen and not any(s in low for s in screen):
                    continue
                new, n = self._apply(out, typ, rx)
                if n:
                    out, hits = new, hits + n
                    low = out.lower()
        if self.pii:
            for typ, rx, screen in PII:
                if typ in self.keep:
                    continue
                if self.screen and screen and not any(s in low for s in screen):
                    continue
                new, n = self._apply(out, typ, rx)
                if n:
                    out, hits = new, hits + n
                    low = out.lower()
        if self.paranoid:
            out, n = self._entropy_pass(out)
            hits += n
        if hits:
            self.lines += 1
        # out.lower() rather than the loop's `low`: --paranoid rewrites the line after it, and a
        # prefilter should read the text the sweep is about to read.
        if self.candidates and (not self.screen or CAND_ANY.search(out)
                                or any(w in out.lower() for w in SECRET_WORDS)):
            self._sweep(out)
        return out, hits

    def _sweep(self, out):
        """Note what survived, aggregated by shape so a 200k-line log reports one row per distinct
        looking secret rather than one per line. The specific classes run first and mark the spans
        they took, so a PAN is not also reported as a bare digit run."""
        taken = []

        def note(kind, site, tok, span=None):
            if self.label_re.search(tok):
                return
            if span and any(t[0] <= span[0] and span[1] <= t[1] for t in taken):
                return
            if span:
                taken.append(span)
            self._cand(kind, site, tok, out, span and out[span[0]:span[1]])

        for m in NAMED_SITE.finditer(out):
            key, tok = m.group("key"), m.group("sec")
            # No entropy floor here: a name that says KEY is the signal, and `password=
            # correcthorsebattery` is a real secret with a low entropy score. A noisy candidate costs
            # one glance; a missed one costs the leak.
            if SECRETISH.search(key):
                note("named", key, tok)
        for m in ANON_SITE.finditer(out):
            tok = m.group("sec")
            if entropy(tok) >= 3.5:
                note("entropy", m.group("keep").rstrip("=:\"' "), tok, (m.start("sec"), m.end("sec")))
        for rx, kind in ((CARD_RUN, "card"), (UUID_SECRET, "uuid"), (HEX_SECRET, "hex"),
                         (BASE32_SECRET, "base32")):
            for m in rx.finditer(out):
                if kind == "card":
                    digits = re.sub(r"\D", "", m.group("sec"))
                    if len(digits) in (13, 14, 15, 16, 19) and luhn(digits):
                        note(kind, "", digits, (m.start("sec"), m.end("sec")))
                else:
                    note(kind, "", m.group("sec"), (m.start("sec"), m.end("sec")))
        for m in DIGIT_RUN.finditer(out):
            note("digits", "", m.group("sec"), (m.start("sec"), m.end("sec")))
        for m in BARE_SECRET.finditer(out):
            if entropy(m.group("sec")) >= BARE_MIN_BITS:
                note("bare", "", m.group("sec"), (m.start("sec"), m.end("sec")))

    def _cand(self, kind, site, tok, line, hide=None):
        key = (kind, site.lower(), classify(tok), len(tok))
        self._line_secrets.setdefault(self._lineno, set()).add(hide or tok)
        self._hit_lines[self._lineno] = line
        if key in self.cands:
            self.cands[key]["count"] += 1
            return
        self.cands[key] = {"kind": kind, "site": site or None, "charset": classify(tok),
                           "length": len(tok), "entropy": round(entropy(tok), 2),
                           "shape": mask(tok), "line": self._lineno, "count": 1,
                           "suggested_rule": suggest_rule(site, tok) if kind == "named" else None}

    def candidate_report(self):
        """Candidates with their context, every secret-shaped span on that line masked out — the
        context is where a report would otherwise leak exactly what it is reporting on."""
        rows = sorted(self.cands.values(), key=lambda c: (-c["count"], c["kind"], c["line"]))
        for row in rows:
            line = self._hit_lines[row["line"]]
            for tok in sorted(self._line_secrets[row["line"]], key=len, reverse=True):
                line = line.replace(tok, mask(tok))
            row["context"] = line.strip()[:160]
        return rows

    def _entropy_pass(self, out):
        n = 0
        pos = 0
        while True:
            m = ENTROPY_SITE.search(out, pos)
            if not m:
                return out, n
            sec = m.group("sec")
            bare_hex = len(sec) in (40, 64) and set(sec) <= HEX
            # A 40-hex next to the word `commit` is a git sha: eating it destroys the thing the log is
            # for, so context decides, not the character set. Context means *beside* it, not anywhere.
            if bare_hex and BENIGN_CONTEXT.search(near(out, m.start("sec"), m.end("sec"))):
                pos = m.end("sec")
                continue
            if entropy(sec) >= PARANOID_MIN_BITS and not self.label_re.search(sec):
                lab = self.label("ENTROPY", sec)
                self._note("ENTROPY", lab)
                out = out[:m.start("sec")] + lab + out[m.end("sec"):]
                n += 1
                pos = m.start("sec")
            else:
                pos = m.end("sec")

PROBE_STEPS = range(8, 27, 2)
PROBE_BUDGET = 0.05


def probe_rule(name, rx):
    """A --rules regex is compiled as written, so a catastrophic one would hang the run rather than
    fail it, and Python gives no way to interrupt a match already underway. So grow the input a
    little at a time and refuse the first rule that stops being linear: an exponential matcher
    crosses the budget within two or three steps, on a string nobody would call long, and the worst
    time wasted is a few hundred milliseconds at load."""
    for n in PROBE_STEPS:
        for probe in ("a" * n, "a" * n + "!", "ab" * n + "!"):
            started = time.monotonic()
            try:
                rx.search(probe)
            except Exception as exc:  # a backreference or assertion that fails only at match time
                return "%s: %s" % (name, exc)
            if time.monotonic() - started > PROBE_BUDGET:
                return ("%s: over %d ms on a %d-character probe — refusing it rather than risking "
                        "a hang on real input" % (name, PROBE_BUDGET * 1000, n))
    return None


def load_rules(path):
    """Read a --rules file: a list of {"name","regex","screen"}, or an object with a "rules" list.
    Returns (rules, error). A malformed rule is an error rather than a skip: a detector that failed
    to load quietly is a secret kept quietly."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as exc:
        return None, "%s: %s" % (path, getattr(exc, "strerror", None) or exc)
    except ValueError as exc:
        return None, "%s: not valid JSON (%s)" % (path, exc)
    items = doc.get("rules") if isinstance(doc, dict) else doc
    if not isinstance(items, list):
        return None, "%s: expected a list, or an object with a 'rules' list" % path
    rules = []
    for i, r in enumerate(items):
        if not isinstance(r, dict) or not r.get("name") or not r.get("regex"):
            return None, "%s: rule %d needs a name and a regex" % (path, i)
        name = str(r["name"]).upper()
        try:
            rx = re.compile(r["regex"])
        except re.error as exc:
            return None, "%s: rule %s: %s" % (path, name, exc)
        if "sec" not in rx.groupindex:
            return None, "%s: rule %s has no (?P<sec>...) group, so nothing would be replaced" \
                         % (path, name)
        err = probe_rule(name, rx)
        if err:
            return None, "%s: rule %s" % (path, err)
        rules.append((name, rx, tuple(str(s).lower() for s in r.get("screen") or ())))
    return rules, None


def dump_rules(path):
    """Write the built-in set out so someone (or some agent) can edit a copy of it rather than
    invent one. Screens are included because they are the part that is easiest to get wrong."""
    doc = {"rules": [{"name": t, "regex": rx.pattern, "screen": list(s)} for t, rx, s in RULES]}
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
    except OSError as exc:
        return "%s: %s" % (path, getattr(exc, "strerror", None) or exc)
    return None


def in_git_worktree(path):
    """The nearest .git above the directory `path` would be written to, or None. The classic way a
    reverse map leaks is not a permissions slip — it is one `git add -A` away, because the map is
    written next to the file being redacted and that file is usually in a repository."""
    d = os.path.abspath(os.path.dirname(path) or ".")
    while True:
        if os.path.exists(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


class InputError(Exception):
    """A source that cannot be read, or is not text. Reported as a message and exit 2."""


CHUNK = 1 << 16


def open_source(name):
    """A text stream for `-` (or stdin) or a named file. Decoded leniently, because a log that is not
    valid UTF-8 must not raise halfway through a pipe and lose the redaction already done; with
    newline translation off, because the default text mode turns \r\n into \n and blot would
    otherwise rewrite a Windows-authored file's line endings while claiming only to have redacted
    it."""
    if name == "-":
        raw = getattr(sys.stdin, "buffer", None)
        if raw is None:
            return sys.stdin
        return io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="")
    return open(name, encoding="utf-8", errors="replace", newline="")


def iter_input(files):
    """Yield lines one at a time: memory holds the current line and the report's accumulators, not
    the log. The splitting matches a whole-file `text.split("\n")` exactly — a source ending in a
    newline yields a final empty line, an empty source yields one empty line — because that trailing
    element is what decides whether the output gets a newline of its own."""
    for name in files or ["-"]:
        try:
            src = open_source(name)
        except OSError as exc:
            raise InputError("%s: %s" % (name, getattr(exc, "strerror", None) or exc))
        with src:
            buf = ""
            while True:
                try:
                    chunk = src.read(CHUNK)
                except OSError as exc:
                    raise InputError("%s: %s" % (name, getattr(exc, "strerror", None) or exc))
                if not chunk:
                    yield buf
                    break   # this source is done; the next one in `blot a.txt -` still has to run
                if "\x00" in chunk:
                    raise InputError("%s: contains a NUL byte — that is a binary, not text you were "
                                     "about to paste." % name)
                head = (buf + chunk).split("\n")
                for line in head[:-1]:
                    yield line
                buf = head[-1]


def preflight(files):
    """Fail before a single byte is written if a named source cannot be opened. Reading the whole
    input up front used to give this for free; streaming has to ask."""
    for name in files:
        if name == "-":
            continue
        try:
            os.stat(name)
        except OSError as exc:
            return "%s: %s" % (name, getattr(exc, "strerror", None) or exc)
    return None


class _Discard:
    def write(self, _s):
        pass

    def flush(self):
        pass


def redact_stream(blotter, files, dest, check=None, discard=False):
    """Redact `files` into `dest` (stdout if none) line by line, verifying each produced line against
    `check` as it appears. Returns (bad_lines, error)."""
    bad, last, handle = [], "", None
    try:
        if discard:
            sink = _Discard()
        elif dest:
            handle = open(dest, "w", encoding="utf-8", newline="")
            sink = handle
        else:
            sink = sys.stdout
        first = True
        for raw in iter_input(files):
            text, _hits = blotter.blot_line(raw.rstrip("\n"))
            if not first:
                sink.write("\n")
            sink.write(text)
            first, last = False, text
            if check is not None and text:
                # No line-level "this line already has a placeholder on it" exemption: `_apply`
                # refuses to blot inside a label per match, which is what stops a re-scan from
                # chewing up its own output. The older guard read a placeholder as proof the whole
                # line was finished, so a kept secret sharing a line with any label passed verify.
                if check.blot_line(text)[1] or LABEL_TAIL.search(text):
                    bad.append(blotter._lineno)
        if last:
            sink.write("\n")
        sink.flush()
    except BrokenPipeError:
        # `blot big.log | head -5` is a normal way to use this. Detach stdout so the interpreter's
        # shutdown flush doesn't turn a clean run into a stack trace.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError):
            pass
    except InputError as exc:
        if handle:
            handle.close()
            handle = None
            # A truncated redaction is worse than no output at all: it looks like a finished one,
            # and the line that stopped it may be the secret.
            try:
                os.remove(dest)
            except OSError:
                pass
        return bad, str(exc)
    except OSError as exc:
        return bad, "%s: %s" % (dest or "stdout", getattr(exc, "strerror", None) or exc)
    finally:
        if handle:
            try:
                handle.close()
            except OSError:
                pass
    return bad, None


def main(argv=None):
    ap = argparse.ArgumentParser(prog=PROG,
                                 description="blot live secrets out of text before you share it")
    ap.add_argument("files", nargs="*", help="files to read (default: stdin)")
    ap.add_argument("-o", "--out", help="write here instead of stdout")
    ap.add_argument("--verify", action="store_true",
                    help="re-scan the produced text; exit 3 if anything recognisable survived")
    ap.add_argument("--stable", action="store_true",
                    help="label each secret from HMAC-SHA256 over it with a private key, so the same "
                         "token gets the same label across SEPARATE runs (default numbering is "
                         "per-run). The key is what makes that safe: an unsalted hash of the secret "
                         "alone lets anyone holding the redacted text confirm a guess offline — one "
                         "candidate, one digest, compare — which leaves a weak secret as good as "
                         "published. Consistency you can rely on, opacity nobody else gets. Lose the "
                         "key and every label changes; leak it and you have handed out the "
                         "dictionary. See --stable-key.")
    ap.add_argument("--stable-key", metavar="FILE",
                    help="key file for --stable (default $XDG_CONFIG_HOME/blot/stable.key, or "
                         "~/.config/blot/stable.key). Created 0600 on first use; a file that already "
                         "exists is refused if group- or world-readable, or if it is under 16 bytes, "
                         "unless --force")
    ap.add_argument("--map", dest="mapfile", metavar="FILE",
                    help="write the reverse table here, mode 0600 — this file holds every secret")
    ap.add_argument("--force", action="store_true",
                    help="let --map replace an existing file or land inside a git work tree, and let "
                         "a group- or world-readable --stable key be read anyway")
    ap.add_argument("--keep", action="append", default=[], metavar="TYPE",
                    help="do not blot this type (repeatable)")
    ap.add_argument("--pii", action="store_true", help="also blot emails, IPv4 addresses, phone numbers")
    ap.add_argument("--paranoid", action="store_true",
                    help="also blot high-entropy values sitting at a key, quote or --flag= site")
    ap.add_argument("--quiet", action="store_true", help="suppress the stderr report")
    ap.add_argument("--rules", metavar="FILE",
                    help="extra detectors from a JSON file ({name, regex, screen}), applied before "
                         "the built-ins")
    ap.add_argument("--dump-rules", metavar="FILE",
                    help="write the built-in rule set here to edit, then feed it back with --rules")
    ap.add_argument("--candidates", action="store_true",
                    help="report what survived, described rather than quoted, for a reviewer or an "
                         "agent to adjudicate")
    ap.add_argument("--strict", action="store_true",
                    help="with --verify: exit 4 unless the candidate sweep is empty too, so an "
                         "unnamed secret-shaped survivor cannot be certified clean")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable findings on stdout; the redacted text then needs --out")
    ap.add_argument("--list-types", action="store_true",
                    help="print every type blot can blot, honouring --pii/--paranoid/--rules")
    ap.add_argument("--version", action="store_true", help="print the version and exit")
    a = ap.parse_args(argv)
    if a.strict:
        a.verify = True   # --strict is the safe single command; verifying is part of what it means

    if a.version:
        print("%s %s" % (PROG, VERSION))
        return 0

    custom = None
    if a.rules:
        custom, err = load_rules(a.rules)
        if err:
            sys.stderr.write("%s: %s\n" % (PROG, err))
            return 2

    if a.dump_rules:
        err = dump_rules(a.dump_rules)
        if err:
            sys.stderr.write("%s: %s\n" % (PROG, err))
            return 2
        sys.stderr.write("%s: %d built-in rules -> %s\n" % (PROG, len(RULES), a.dump_rules))
        return 0

    if a.list_types:
        types = [t for t, _, _ in (custom or []) + RULES] + ["PRIVKEY", "SEEDPHRASE"]
        if a.pii:
            types += [t for t, _, _ in PII]
        if a.paranoid:
            types.append("ENTROPY")
        print("\n".join(sorted(set(types))))
        return 0

    known = ALL_TYPES | {t for t, _, _ in (custom or [])}
    unknown = [k for k in a.keep if k.upper() not in known]
    if unknown:
        # A typo in --keep would otherwise be silently ignored, and the type the user meant to
        # spare gets blotted anyway — or worse, they believe something was spared that was not.
        sys.stderr.write("%s: unknown --keep type(s): %s (see --list-types)\n"
                         % (PROG, ", ".join(unknown)))
        return 2

    if not a.files and sys.stdin.isatty():
        sys.stderr.write("%s: no files and nothing on stdin — pipe text in, name a file, or use "
                         "--help\n" % PROG)
        return 2

    stable_key = None
    if a.stable:
        stable_key, created, err = load_stable_key(stable_key_path(a.stable_key), a.force)
        if err:
            sys.stderr.write("%s: %s\n" % (PROG, err))
            return 2
        if created and not a.quiet:
            sys.stderr.write("%s: created a new --stable key at %s (0600). Publish that file and the "
                             "labels in this report are a lookup table; delete it and they all "
                             "change.\n" % (PROG, stable_key_path(a.stable_key)))

    b = Blotter(stable=a.stable, stable_key=stable_key, keep=[k.upper() for k in a.keep], pii=a.pii,
                paranoid=a.paranoid, rules=custom, candidates=a.candidates or a.json or a.strict)
    err = preflight(a.files)
    if err:
        sys.stderr.write("%s: %s\n" % (PROG, err))
        return 2

    # verify deliberately ignores --keep: auditing a redaction against the same exceptions that
    # produced it is how a leak gets certified clean. It does honour --rules, because a detector
    # someone added on purpose is part of what "recognisable" now means. It runs as each line is
    # produced, so nothing is held in memory to be re-scanned later.
    check = Blotter(pii=a.pii, paranoid=a.paranoid, rules=custom) if a.verify else None
    live, err = redact_stream(b, a.files, a.out, check, discard=a.json and not a.out)
    if err:
        sys.stderr.write("%s: %s\n" % (PROG, err))
        return 2

    if not a.quiet:
        kinds = " ".join("%s=%d" % (k, v) for k, v in sorted(b.counts.items()))
        total = sum(b.counts.values())
        sys.stderr.write(
            "%s: %d secret(s) blotted (%d distinct) across %d line(s)%s\n%s\n"
            % (PROG, total, len(b.labels), b.lines,
               "" if total else "  — nothing matched, which is NOT evidence the text was clean",
               "  " + kinds if kinds else "  (none)"))

    rows = b.candidate_report() if (a.candidates or a.json or a.strict) else []
    if a.candidates and not a.json:
        for c in rows[:40]:
            sys.stderr.write("%s: %-7s %-20s %-9s %-16s x%-4d line %d\n"
                             % (PROG, c["kind"], (c["site"] or "-")[:20], c["charset"],
                                c["shape"], c["count"], c["line"]))
            sys.stderr.write("%s:         %s\n" % (PROG, c["context"]))
        if len(rows) > 40:
            sys.stderr.write("%s: ... %d more distinct shapes (--json for all)\n"
                             % (PROG, len(rows) - 40))
        elif not rows:
            sys.stderr.write("%s: no candidates — nothing that survived is secret-shaped, which is "
                             "still not proof that nothing is\n" % PROG)

    if a.mapfile:
        root = in_git_worktree(a.mapfile)
        if root and not a.force:
            sys.stderr.write(
                "%s: refusing to write the reverse map inside the git work tree at %s. That file "
                "holds every secret from this run and is one `git add -A` from being public — write "
                "it outside the tree, or pass --force if you have ignored it.\n" % (PROG, root))
            return 2
        # Created exclusive at 0600 instead of written then chmod'ed: in the window between those two
        # calls, every secret from this run sat in a file the rest of the machine could read. An
        # existing path is refused rather than overwritten — this file is usually the only copy.
        flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if a.force else os.O_EXCL)
        try:
            fd = os.open(a.mapfile, flags, 0o600)
        except OSError as exc:
            sys.stderr.write("%s: cannot write the reverse map to %s: %s%s\n"
                             % (PROG, a.mapfile, getattr(exc, "strerror", None) or exc,
                                "" if a.force else " (pass --force to replace an existing map)"))
            return 2
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(b.labels, fh, indent=1, sort_keys=True)
        sys.stderr.write("%s: reverse map -> %s (0600). Publish that file and you have published "
                         "every secret in here.\n" % (PROG, a.mapfile))

    if a.json:
        print(json.dumps({"version": VERSION, "inputs": a.files or ["-"], "lines": b._lineno,
                          "blotted": sum(b.counts.values()), "distinct": len(b.labels),
                          "by_type": dict(sorted(b.counts.items())), "findings": b.findings,
                          "findings_truncated": b.findings_capped, "candidates": rows, "strict": a.strict,
                          "verify": {"clean": not live, "lines": live[:200]} if a.verify else None},
                         indent=1, sort_keys=True))

    if a.verify:
        if live:
            sys.stderr.write("%s: NOT CLEAN — something recognisable is still live on line(s) %s\n"
                             % (PROG, ", ".join(map(str, live[:20]))))
            return 3
        if a.strict and rows:
            names = ", ".join(sorted({c["site"] or c["kind"] for c in rows})[:6])
            sys.stderr.write("%s: UNNAMED — nothing recognised is live, but %d shape(s) still look "
                             "secret-shaped and no rule covers them: %s\n"
                             % (PROG, len(rows), names))
            return 4
        sys.stderr.write("%s: verify OK — no recognised secret remains in the output\n" % PROG)
    return 0


def cli():
    """Entry point for both `python blot.py` and an installed console script, which imports main()
    directly and so never reaches the __main__ guard below."""
    try:
        return main()
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(cli())
