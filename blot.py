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
  blot app.log --rules learned.json --verify            # ...and blot applies what it decided
"""
import argparse
import hashlib
import io
import json
import math
import os
import re
import string
import sys
import time

PROG = os.path.basename(sys.argv[0]).split(".")[0]
VERSION = "1.1.1"

# Named groups: `keep` is the context that stays visible (so a reader can still tell WHICH field was
# blotted), `sec` is the secret, `q`/`tail` preserve quoting. Order matters: specific prefixed forms
# first, generic key=value next, so a `token: ghp_...` line reports as GHTOKEN and not KV.
#
# The third field is a screen: literals such that ANY text the regex can match must contain at least
# one of them, case-insensitively. It is a necessary condition, never a heuristic — a screen that is
# wrong in that direction silently loses secrets, which is the one failure this tool cannot have. The
# regexes are long alternations and cost ~40x what a substring test costs on a line that cannot match
# (KV alone was 8.5s of an 18s run over a 12 MB log). An empty tuple means "always run it".
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
]

PII = (("EMAIL", re.compile(r"\b[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+\b"), ("@",)),
       ("IPV4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), (".",)),
       ("PHONE", re.compile(r"\b(?:\+?\d[\d\s\-()]{8,14}\d)\b"), ()))

PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")

# A wallet seed is a run of plain dictionary words. Counting words alone would blot half of poetry,
# so the run must also contain at least two words from a curated BIP39 subset.
SEED_HINT = {"abandon", "zombie", "oyster", "sushi", "jelly", "pigeon", "velvet", "crush", "brave",
             "coral", "lizard", "monkey", "peasant", "ridiculous", "tunnel", "wear", "yoga", "fossil",
             "hollow", "pudding", "sphere", "vocal", "impulse", "lonely", "cricket", "drip",
              "ability", "able", "about", "above", "absorb", "abstract", "absurd",
              "access", "accident", "account", "acid", "acoustic", "acrylic", "agent",
              "agree", "alarm", "album", "alpha", "amber", "angle", "animal", "answer"}
SEED_RUN = re.compile(r"\b(?:[a-z]{4,12}\s+){11,23}[a-z]{4,12}\b")
SEED_COUNTS = (12, 15, 18, 21, 24)

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
# A placeholder, tolerant of being cut off mid-label, because a later rule can match inside one.
# The type name has to allow what --rules allows: an earlier version matched only <[A-Z]+:, so the
# placeholder left by a rule named INTERNAL_KEY was not recognised as a placeholder and got blotted
# a second time, corrupting the one token that points back to the secret.
LABEL_INNER = re.compile(r"<[A-Z][A-Z0-9_]*(?::[^>\s]*)?>?", re.I)
# A label with 16+ credential-shaped characters still glued to it: `<JWT:1>eyJhbGciOiJI...` is what a
# half-redacted secret looks like, and verify must not be fooled by the label in front of it.
LABEL_TAIL = re.compile(r"<[A-Z][A-Z0-9_]*:[^>]*>[^\s<]*[A-Za-z0-9_/+\-]{16,}")


ALL_TYPES = {t for t, _, _ in RULES} | {t for t, _, _ in PII} | {"PRIVKEY", "SEEDPHRASE", "ENTROPY"}

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


class Blotter:
    """One Blotter per run: the label table lives here, which is what makes redaction consistent."""

    def __init__(self, stable=False, keep=(), pii=False, paranoid=False, screen=True, rules=None,
                 candidates=False):
        self.stable = stable
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
        # sound for it, so the shortcut is only built when every active rule screens for something.
        self._prefilter = SCREEN_ANY if all(sc for _t, _rx, sc in self.rules) else None
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
            tag = hashlib.sha1(secret.encode("utf-8", "replace")).hexdigest()[:6]
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
            if LABEL_INNER.search(m.group(0)):
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

    def blot_line(self, line):
        """Returns (blotted_line, hit_count). Interior PEM lines collapse to nothing: a key block is
        one secret, not thirty, and a report should say so once."""
        self._lineno += 1
        if self._in_pem:
            self._pem_lines += 1
            if PEM_END.search(line):
                self._in_pem = False
            return "", self._pem_lines
        m = PEM_BEGIN.search(line)
        if m:
            self._in_pem = True
            self._pem_lines = 1
            lab = self.label("PRIVKEY", "<pem-block>")
            self._note("PRIVKEY", lab)
            if not PEM_END.search(line):
                return lab, 1
            return lab + line[m.end():], 1

        out = line
        hits = 0
        sm = SEED_RUN.search(out)
        if sm:
            words = sm.group(0).split()
            if len(words) in SEED_COUNTS and len(SEED_HINT & set(words)) >= 2:
                lab = self.label("SEEDPHRASE", sm.group(0))
                self._note("SEEDPHRASE", lab)
                out = out[:sm.start()] + lab + out[sm.end():]
                hits += 1
        low = out.lower()
        if not self.screen or self._prefilter is None or self._prefilter.search(low):
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
            if LABEL_INNER.search(tok):
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
            if entropy(sec) >= PARANOID_MIN_BITS and not LABEL_INNER.search(sec):
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
                if ((check.blot_line(text)[1] and not LABEL_INNER.search(text))
                        or LABEL_TAIL.search(text)):
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
                    help="derive labels from the secret's hash so the same token gets the same label "
                         "across SEPARATE runs (default numbering is per-run)")
    ap.add_argument("--map", dest="mapfile", metavar="FILE",
                    help="write the reverse table here, mode 0600 — this file holds every secret")
    ap.add_argument("--force", action="store_true",
                    help="let --map replace an existing file, or land inside a git work tree")
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

    b = Blotter(stable=a.stable, keep=[k.upper() for k in a.keep], pii=a.pii,
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
