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
"""
import argparse
import hashlib
import json
import math
import os
import re
import sys

PROG = os.path.basename(sys.argv[0]).split(".")[0]
VERSION = "1.0.0"

# Named groups: `keep` is the context that stays visible (so a reader can still tell WHICH field was
# blotted), `sec` is the secret, `q`/`tail` preserve quoting. Order matters: specific prefixed forms
# first, generic key=value next, so a `token: ghp_...` line reports as GHTOKEN and not KV.
RULES = [
    ("AWS", re.compile(r"\b(?P<sec>(?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANVA|APINA)[0-9A-Z]{12,20})\b")),
    ("GHTOKEN", re.compile(r"\b(?P<sec>gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("GOOGLEKEY", re.compile(r"\b(?P<sec>AIza[0-9A-Za-z_\-]{30,40})\b")),
    ("SLACK", re.compile(r"\b(?P<sec>xox[baprs]-[0-9A-Za-z-]{10,})\b")),
    ("STRIPE", re.compile(r"\b(?P<sec>(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{10,})\b")),
    ("LLMTOKEN", re.compile(r"\b(?P<sec>sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,})\b")),
    # eyJ is `{"` in base64url; every real JWT starts with it, so this cannot hit ordinary prose.
    ("JWT", re.compile(r"\b(?P<sec>eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{8,})")),
    ("URLCREDS", re.compile(
        r"(?P<sec>[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@'\"]{1,64}:[^\s@/'\"]{1,128}@[^\s/'\"]*)")),
    ("BEARER", re.compile(
        r"(?i)(?P<keep>\b(?:authorization|proxy-authorization|x-api-token)\s*[:=]\s*)?"
        r"(?P<sec>bearer\s+[A-Za-z0-9._~+/=-]{12,})")),
    ("BASIC", re.compile(r"(?i)(?P<keep>\bbasic\s+)(?P<sec>[A-Za-z0-9+/]{12,}={0,2})")),
    ("COOKIE", re.compile(r"(?i)(?P<keep>\b(?:cookie|set-cookie)\s*[:=]\s*)(?P<sec>[^\r\n\"']{8,})")),
    # Curated on purpose, not `.*key.*=`: over-redacting a log is also a failure, and it is the one
    # that quietly destroys the report you were trying to publish. Long tail -> --paranoid.
    ("KV", re.compile(
        r"(?i)(?P<keep>[\"']?(?:password|passwd|pass|pwd|secret|secret[_-]?key(?:[_-]?base)?|"
        r"api[_-]?key|apikey|app[_-]?key|master[_-]?key|encryption[_-]?key|signing[_-]?key|"
        r"access[_-]?key(?:[_-]?id)?|access[_-]?token|private[_-]?key|auth[_-]?token|"
        r"refresh[_-]?token|session[_-]?token|bearer[_-]?token|id[_-]?token|token|seed|mnemonic|"
        r"recovery[_-]?phrase|otp|client[_-]?secret|webhook[_-]?secret)"
        r"[\"']?\s*[:=]\s*)(?P<q>[\"']?)(?P<sec>[^\"'\s,;}\]]{5,})(?P<tail>(?P=q))")),
]

PII = (("EMAIL", re.compile(r"\b[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+\b")),
       ("IPV4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
       ("PHONE", re.compile(r"\b(?:\+?\d[\d\s\-()]{8,14}\d)\b")))

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
LABEL_INNER = re.compile(r"<[A-Z]+:[^>]*>?", re.I)


ALL_TYPES = {t for t, _ in RULES} | {t for t, _ in PII} | {"PRIVKEY", "SEEDPHRASE", "ENTROPY"}


def near(text, lo, hi, window=CTX_WINDOW):
    return text[max(0, lo - window):hi + window]


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


class Blotter:
    """One Blotter per run: the label table lives here, which is what makes redaction consistent."""

    def __init__(self, stable=False, keep=(), pii=False, paranoid=False):
        self.stable = stable
        self.keep = {k.upper() for k in keep}
        self.pii = pii
        self.paranoid = paranoid
        self.labels = {}
        self.counts = {}
        self.lines = 0
        self._n = {}
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
                creds, _, host = rest.rpartition("@")
                return "%s%s://<URLCREDENTIALS>@%s" % (keep, scheme, host)
            return "%s%s%s%s" % (keep, q, self.label(typ, sec), q)

        new = rx.sub(sub, text)
        return new, hits[0]

    def blot_line(self, line):
        """Returns (blotted_line, hit_count). Interior PEM lines collapse to nothing: a key block is
        one secret, not thirty, and a report should say so once."""
        if self._in_pem:
            self._pem_lines += 1
            if PEM_END.search(line):
                self._in_pem = False
            return "", self._pem_lines
        m = PEM_BEGIN.search(line)
        if m:
            self._in_pem = True
            self._pem_lines = 1
            if not PEM_END.search(line):
                return self.label("PRIVKEY", "<pem-block>"), 1
            return self.label("PRIVKEY", "<pem-block>") + line[m.end():], 1

        out = line
        hits = 0
        sm = SEED_RUN.search(out)
        if sm:
            words = sm.group(0).split()
            if len(words) in SEED_COUNTS and len(SEED_HINT & set(words)) >= 2:
                out = out[:sm.start()] + self.label("SEEDPHRASE", sm.group(0)) + out[sm.end():]
                hits += 1
        for typ, rx in RULES:
            if typ in self.keep:
                continue
            new, n = self._apply(out, typ, rx)
            if n:
                out, hits = new, hits + n
        if self.pii:
            for typ, rx in PII:
                if typ in self.keep:
                    continue
                new, n = self._apply(out, typ, rx)
                if n:
                    out, hits = new, hits + n
        if self.paranoid:
            out, n = self._entropy_pass(out)
            hits += n
        if hits:
            self.lines += 1
        return out, hits

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
            if entropy(sec) >= PARANOID_MIN_BITS and not re.search(r"<[A-Z]+:", sec):
                out = out[:m.start("sec")] + self.label("ENTROPY", sec) + out[m.end("sec"):]
                n += 1
                pos = m.start("sec")
            else:
                pos = m.end("sec")

    def stream_lines(self, lines):
        for raw in lines:
            yield self.blot_line(raw.rstrip("\n"))[0]


def read_input(files):
    """Lines from the named files, or from stdin when none are given; `-` always means stdin.
    Returns (lines, error) — a missing file is a message, not a traceback."""
    lines = []
    for name in files or ["-"]:
        try:
            if name == "-":
                # Logs are routinely not valid UTF-8. Decoding strictly would raise halfway through a
                # pipe and lose the redaction that was already done, so bytes come in and undecodable
                # ones become U+FFFD, exactly as they do for a named file.
                raw = getattr(sys.stdin, "buffer", None)
                text = raw.read().decode("utf-8", "replace") if raw else sys.stdin.read()
            else:
                with open(name, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
        except OSError as exc:
            return None, "%s: %s" % (name, getattr(exc, "strerror", None) or exc)
        lines.extend(text.split("\n"))
    return lines, None


def emit(payload, dest):
    """Write the redacted text, reporting a write failure instead of dumping a stack on it.
    Returns None on success, or a message for the caller to print and exit non-zero on."""
    try:
        if dest:
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(payload)
        else:
            sys.stdout.write(payload)
            sys.stdout.flush()
    except BrokenPipeError:
        # `blot big.log | head -5` is a normal way to use this. Detach stdout so the interpreter's
        # shutdown flush doesn't turn a clean run into a stack trace.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError):
            pass
    except (OSError, ValueError) as exc:
        return "%s: %s" % (dest or "stdout", getattr(exc, "strerror", None) or exc)
    return None


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
    ap.add_argument("--keep", action="append", default=[], metavar="TYPE",
                    help="do not blot this type (repeatable)")
    ap.add_argument("--pii", action="store_true", help="also blot emails, IPv4 addresses, phone numbers")
    ap.add_argument("--paranoid", action="store_true",
                    help="also blot high-entropy values sitting at a key, quote or --flag= site")
    ap.add_argument("--quiet", action="store_true", help="suppress the stderr report")
    ap.add_argument("--list-types", action="store_true")
    ap.add_argument("--version", action="store_true")
    a = ap.parse_args(argv)

    if a.version:
        print("%s %s" % (PROG, VERSION))
        return 0
    if a.list_types:
        types = [t for t, _ in RULES] + ["PRIVKEY", "SEEDPHRASE"]
        if a.pii:
            types += [t for t, _ in PII]
        if a.paranoid:
            types.append("ENTROPY")
        print("\n".join(sorted(set(types))))
        return 0

    unknown = [k for k in a.keep if k.upper() not in ALL_TYPES]
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

    b = Blotter(stable=a.stable, keep=[k.upper() for k in a.keep], pii=a.pii, paranoid=a.paranoid)
    src, err = read_input(a.files)
    if err:
        sys.stderr.write("%s: %s\n" % (PROG, err))
        return 2

    out_lines = list(b.stream_lines(src))
    text = "\n".join(out_lines)
    payload = (text if text.endswith("\n") or not text else text + "\n")
    err = emit(payload, a.out)
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
    if a.mapfile:
        # Created exclusive at 0600 instead of written then chmod'ed: in the window between those two
        # calls, every secret from this run sat in a file the rest of the machine could read. An
        # existing path is refused rather than overwritten — this file is usually the only copy.
        try:
            fd = os.open(a.mapfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            sys.stderr.write("%s: cannot write the reverse map to %s: %s\n"
                             % (PROG, a.mapfile, getattr(exc, "strerror", None) or exc))
            return 2
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(b.labels, fh, indent=1, sort_keys=True)
        sys.stderr.write("%s: reverse map -> %s (0600). Publish that file and you have published "
                         "every secret in here.\n" % (PROG, a.mapfile))

    if a.verify:
        # verify deliberately ignores --keep: auditing a redaction against the same exceptions
        # that produced it is how a leak gets certified clean.
        check = Blotter(pii=a.pii, paranoid=a.paranoid)
        live = []
        for i, line in enumerate(out_lines, 1):
            if line and check.blot_line(line)[1] and not re.search(r"<[A-Z]+:", line):
                live.append(i)
            elif line and re.search(r"<[A-Z]+:[^>]*>[^\s<]*[A-Za-z0-9_/+\-]{16,}", line):
                live.append(i)
        if live:
            sys.stderr.write("%s: NOT CLEAN — something recognisable is still live on line(s) %s\n"
                             % (PROG, ", ".join(map(str, live[:20]))))
            return 3
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
