"""blot's own tests: every detector, and the four things that would make it dangerous to trust."""
import atexit
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import blot  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(os.path.dirname(HERE), "blot.py")
# Somewhere outside the repository: blot refuses to write a reverse map inside a git work tree, so
# the tests that exercise --map have to ask for a directory that is not one.
TMP = tempfile.mkdtemp(prefix="blot-tests-")
atexit.register(shutil.rmtree, TMP, True)
# --stable keeps a key under $XDG_CONFIG_HOME/blot/stable.key. Redirected before anything runs so no
# test can create, refuse on, or overwrite a file in the real home of whoever is running the suite —
# and so the subprocesses below, which inherit this environment, stay inside TMP too.
os.environ["XDG_CONFIG_HOME"] = TMP
DEFAULT_STABLE_KEY = os.path.join(TMP, "blot", "stable.key")


def scratch(name):
    return os.path.join(TMP, name)

AWS = "AKIAIOSFODNN7EXAMPLE"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5"
# A fixture that satisfies blot's shape-based detectors satisfies every other secret scanner too,
# including the one that gates pushes to this repo. These prefixes are assembled at runtime so the
# bytes in this file stay non-credential-looking to a reader and a scanner alike. What is asserted
# below is the shape blot reacts to, which is the thing that actually needs testing.
STRIPE = "sk_" + "live_" + "EXAMPLEKEY0123456789"
SLACK = "xox" + "b-" + "not-a-real-token-example"
PEM = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
       "b3BlbnNzaC1rZXktdjEAAAAABg5wa3QNCjEK\n"
       "cGFzc3dvcmQNCgAK\n"
       "-----END OPENSSH PRIVATE KEY-----")
SEED = ("abandon ability able about above absorb abstract absurd abuse access accident "
        "account")


def run(*args, stdin=None):
    p = subprocess.run([sys.executable, CLI] + list(args), input=stdin, capture_output=True,
                       text=True)
    return p.returncode, p.stdout, p.stderr


class TestDetectors(unittest.TestCase):
    def setUp(self):
        self.b = blot.Blotter(paranoid=True)

    def one(self, line):
        return self.b.blot_line(line)

    def test_every_named_shape_is_blotted(self):
        cases = [
            ("AWS", "key=" + AWS + " region=us-east-1", AWS),
            ("GHTOKEN", "Authorization: token " + GH, GH),
            ("JWT", "session=" + JWT, JWT),
            ("STRIPE", "const S = '" + STRIPE + "';", STRIPE),
            ("SLACK", "T=" + SLACK, SLACK),
            ("LLMTOKEN", "--api-key sk-ant-abcdefghij0123456789JKLMNOPQRST",
             "sk-ant-abcdefghij0123456789JKLMNOPQRST"),
            ("GOOGLEKEY", "key=AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY21",
             "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY21"),
            ("KV", '{"password": "hunter2secretvalue", "user": "bob"}', "hunter2secretvalue"),
        ]
        for typ, line, secret in cases:
            b = blot.Blotter()
            out, hits = b.blot_line(line)
            self.assertTrue(hits, "%s not blotted: %s" % (typ, line))
            self.assertIn("<%s" % typ, out, "%s mislabelled in %s" % (typ, out))
            self.assertNotIn(secret, out, "%s survived in %s" % (typ, out))

    def test_pem_block_becomes_one_label_not_twenty(self):
        b = blot.Blotter()
        outs = [b.blot_line(l) for l in PEM.split("\n")]
        labels = [o for o, _ in outs if o]
        self.assertEqual(len(labels), 1, outs)
        self.assertIn("<PRIVKEY:", labels[0])
        self.assertNotIn("b3BlbnNzaC", "\n".join(o for o, _ in outs))

    def test_url_keeps_the_host_and_loses_the_credentials(self):
        b = blot.Blotter()
        out, hits = b.blot_line("psql postgres://admin:Sup3rS3cret@db.internal:5432/app")
        self.assertTrue(hits)
        self.assertIn("db.internal:5432/app", out, "the host is what makes a log line useful")
        self.assertNotIn("Sup3rS3cret", out)
        self.assertNotIn("admin:", out)
        # And it has to be counted and in the label table: a URL credential that never reaches
        # --map makes that file a partial list while still claiming to be the inverse.
        self.assertEqual(b.counts.get("URLCREDENTIALS"), 1, b.counts)
        self.assertEqual(list(b.labels.values()), ["<URLCREDENTIALS:1>"])

    def test_key_name_survives_so_the_report_is_still_readable(self):
        b = blot.Blotter()
        out, _ = b.blot_line("JWT_SECRET=\"aValuethatislongenough\"")
        self.assertIn("JWT_SECRET", out)
        self.assertNotIn("aValuethatislongenough", out)

    def test_seed_phrase_needs_both_a_run_and_two_hint_words(self):
        b = blot.Blotter()
        out, hits = b.blot_line("wallet: " + SEED)
        self.assertTrue(hits, "a 12-word seed was missed")
        self.assertIn("<SEEDPHRASE:", out)
        prose = ("the quick brown fox jumps over the lazy dog while nobody watches the quiet "
                 "garden at sunset")
        _o2, h2 = blot.Blotter(paranoid=True).blot_line(prose)
        self.assertFalse(h2, "ordinary prose was blotted")


class TestConsistency(unittest.TestCase):
    def test_the_same_secret_gets_the_same_label_in_one_run(self):
        b = blot.Blotter()
        l1, _ = b.blot_line("token: %s" % JWT)
        l2, _ = b.blot_line("retried with %s" % JWT)
        self.assertEqual(l1.split(" ")[1], l2.split(" ")[2])

    def test_different_secrets_never_share_a_label(self):
        b = blot.Blotter()
        a, _ = b.blot_line("k1=" + AWS)
        c, _ = b.blot_line("k2=AKIAOTHEREXAMPLE123456")
        self.assertNotEqual(a, c)

    def test_stable_mode_agrees_across_separate_runs(self):
        one = blot.Blotter(stable=True).blot_line("t=" + GH)[0]
        two = blot.Blotter(stable=True).blot_line("Authorization: " + GH)[0]
        self.assertIn(one.split("=")[1], two, "--stable must not renumber the same secret")

    def test_map_is_the_exact_inverse(self):
        b = blot.Blotter()
        out, _ = b.blot_line("password=hunter2supersecret")
        self.assertEqual(b.labels["hunter2supersecret"], out.split("=")[1])


class TestStableKey(unittest.TestCase):
    """--stable exists so one incident spread over five logs reads consistently. That needs the label
    to be a function of the secret, which is also what let anyone holding the redacted text confirm a
    guess offline: hash a candidate, compare the six hex digits. Unsalted sha1[:6] made every weak
    secret in the report recoverable by dictionary. The fix is a key only the operator has."""

    def keyfile(self, name, body=b"k" * 32, mode=0o600):
        path = scratch(name)
        with open(path, "wb") as fh:
            fh.write(body)
        os.chmod(path, mode)
        return path

    def read_bytes(self, path):
        with open(path, "rb") as fh:
            return fh.read()

    def tag(self, out):
        m = re.search(r"<[A-Z]+:([0-9a-f]+)>", out)
        self.assertIsNotNone(m, "no stable label in: " + out)
        return m.group(1)

    def test_a_stable_tag_is_not_a_plain_hash_of_the_secret(self):
        path = self.keyfile("_k_hash")
        rc, out, err = run("--quiet", "--stable", "--stable-key", path, stdin="token " + GH + "\n")
        self.assertEqual(rc, 0, out + err)
        tag = self.tag(out)
        self.assertEqual(len(tag), 8, "the tag is %r, not 8 hex characters" % tag)
        for h in (hashlib.sha1, hashlib.sha256, hashlib.md5):
            self.assertNotEqual(tag, h(GH.encode()).hexdigest()[:8],
                                "the tag is a bare digest of the secret: a dictionary confirms it")

    def test_the_key_is_what_makes_the_tag(self):
        a = self.keyfile("_k_a", b"A" * 32)
        b = self.keyfile("_k_b", b"B" * 32)
        _rc1, out1, _e1 = run("--quiet", "--stable", "--stable-key", a, stdin="token " + GH + "\n")
        _rc2, out2, _e2 = run("--quiet", "--stable", "--stable-key", b, stdin="token " + GH + "\n")
        self.assertNotEqual(self.tag(out1), self.tag(out2),
                            "two keys, same tag: the key is not being mixed in")

    def test_one_key_agrees_across_separate_processes(self):
        path = self.keyfile("_k_same")
        _r1, o1, _e1 = run("--quiet", "--stable", "--stable-key", path, stdin="token " + GH + "\n")
        _r2, o2, _e2 = run("--quiet", "--stable", "--stable-key", path,
                           stdin="retried with " + GH + "\n")
        self.assertEqual(self.tag(o1), self.tag(o2), "%s vs %s" % (o1, o2))

    def test_the_default_key_is_created_private_and_never_regenerated(self):
        if os.path.exists(DEFAULT_STABLE_KEY):
            os.remove(DEFAULT_STABLE_KEY)
        rc, out, err = run("--quiet", "--stable", stdin="token " + GH + "\n")
        self.assertEqual(rc, 0, out + err)
        self.assertTrue(os.path.exists(DEFAULT_STABLE_KEY), "no key at the documented path")
        self.assertEqual(oct(os.stat(DEFAULT_STABLE_KEY).st_mode)[-3:], "600")
        first = self.read_bytes(DEFAULT_STABLE_KEY)
        _r2, out2, _e2 = run("--quiet", "--stable", stdin="token " + GH + "\n")
        self.assertEqual(self.read_bytes(DEFAULT_STABLE_KEY), first, "the key was rewritten")
        self.assertEqual(self.tag(out), self.tag(out2), "the run after creation disagrees")

    def test_a_shared_key_is_refused_rather_than_trusted(self):
        path = self.keyfile("_k_open", mode=0o644)
        rc, out, err = run("--quiet", "--stable", "--stable-key", path, stdin="token " + GH + "\n")
        self.assertEqual(rc, 2, out + err)
        self.assertIn("600", err, err)
        rc2, _o2, err2 = run("--quiet", "--force", "--stable", "--stable-key", path,
                             stdin="token " + GH + "\n")
        self.assertEqual(rc2, 0, out + err2)

    def test_a_short_key_is_refused(self):
        path = self.keyfile("_k_short", body=b"abc")
        rc, out, err = run("--quiet", "--stable", "--stable-key", path, stdin="token " + GH + "\n")
        self.assertEqual(rc, 2, out + err)
        self.assertNotIn("<", out, "a weak key was used anyway: " + out)

    def test_a_named_key_is_created_with_its_parent_directories(self):
        path = os.path.join(TMP, "nested", "deeper", "stable.key")
        rc, out, err = run("--quiet", "--stable", "--stable-key", path, stdin="token " + GH + "\n")
        self.assertEqual(rc, 0, out + err)
        self.assertTrue(os.path.exists(path), err)
        self.assertEqual(oct(os.stat(path).st_mode)[-3:], "600")

    def test_stable_still_verifies(self):
        path = self.keyfile("_k_verify")
        rc, out, err = run("--stable", "--stable-key", path, "--verify",
                           stdin="token " + GH + "\npassword=hunter2supersecret\n")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("verify OK", err)

    def test_the_help_says_what_the_key_costs(self):
        rc, out, _err = run("--help")
        self.assertEqual(rc, 0)
        self.assertIn("--stable-key", out)
        for word in ("key", "hash"):
            self.assertIn(word, out.lower(), "--help must name the trade-off")

    def test_a_library_caller_gets_the_default_key_too(self):
        if os.path.exists(DEFAULT_STABLE_KEY):
            os.remove(DEFAULT_STABLE_KEY)
        one = blot.Blotter(stable=True).blot_line("t=" + GH)[0]
        two = blot.Blotter(stable=True).blot_line("Authorization: " + GH)[0]
        self.assertEqual(self.tag(one), self.tag(two))


class TestFalsePositives(unittest.TestCase):
    def test_a_git_sha_is_not_a_secret_even_when_paranoid(self):
        b = blot.Blotter(paranoid=True)
        line = "[detached 4f9a3cbe0a1d2b3c4d5e6f708192a3b4c5d6e7f8] commit 4f9a3cbe0a1d2b3c4d5e6f708192a3b4c5d6e7f8"
        out, hits = b.blot_line(line)
        self.assertNotIn("<ENTROPY", out, out)

    def test_ordinary_urls_and_paths_are_untouched(self):
        b = blot.Blotter(paranoid=True)
        for line in ["GET /api/v1/users?page=2 200 14ms",
                     "https://docs.example.com/en/reference/overview",
                     "npm install lodash@4.17.21"]:
            out, _ = b.blot_line(line)
            self.assertEqual(out, line, line)


class TestVerify(unittest.TestCase):
    def test_verify_passes_on_blotted_output(self):
        rc, out, err = run(stdin="token %s\naws %s\n" % (JWT, AWS))
        self.assertEqual(rc, 0, err)
        rc2, _o2, err2 = run("--verify", stdin="token %s\naws %s\n" % (JWT, AWS))
        self.assertEqual(rc2, 0, err2)
        self.assertIn("verify OK", err2)

    def test_verify_fails_loudly_when_a_type_was_kept(self):
        rc, out, err = run("--verify", "--keep", "AWS", stdin="aws key %s here\n" % AWS)
        self.assertEqual(rc, 3, out + err)
        self.assertIn("NOT CLEAN", err)

    def test_nothing_matched_is_not_reported_as_clean(self):
        rc, out, err = run(stdin="just a normal sentence\n")
        self.assertIn("NOT evidence", err, err)

    def test_a_large_line_does_not_hang(self):
        big = ("log noise " * 20000) + JWT
        t = time.time()
        b = blot.Blotter(paranoid=True)
        out, hits = b.blot_line(big)
        self.assertTrue(hits)
        self.assertLess(time.time() - t, 3.0, "one 240 KB log line took too long")


class TestVerifyLineGranularity(unittest.TestCase):
    """verify decides per line. A placeholder on a line is evidence that the line was *worked on*,
    not that it was finished — the exemption that read it the other way round certified a line
    carrying both `<KV:1>` and a live GitHub token as clean."""

    BOTH = "a=" + GH + " password=hunter22\n"

    def test_a_placeholder_does_not_exempt_the_live_secret_next_to_it(self):
        rc, out, err = run("--quiet", "--keep", "GHTOKEN", "--verify", stdin=self.BOTH)
        self.assertEqual(rc, 3, out + err)
        self.assertIn("NOT CLEAN", err)
        self.assertIn(GH, out, "the fixture stopped leaking, which would make the rc=3 vacuous")

    def test_a_fully_blotted_line_still_verifies_clean(self):
        rc, out, err = run("--verify", stdin=self.BOTH)
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn(GH, out)
        self.assertNotIn("hunter22", out)


class TestLabelGuard(unittest.TestCase):
    """The guard that stops a rule blotting inside a placeholder has to know what a placeholder is.
    Tolerant and case-insensitive, `<ss` in `pa<ss1word99` counted as one and shielded the secret."""

    def test_an_angle_bracket_that_is_not_a_label_does_not_shield_a_secret(self):
        out, hits = blot.Blotter().blot_line("password=pa<ss1word99")
        self.assertTrue(hits, "the guard read `<ss` as a placeholder and skipped the line")
        self.assertNotIn("pa<ss1word99", out, out)

    def test_a_secret_in_a_case_is_not_shielded_by_a_pseudo_label(self):
        for line in ["secret=<x><JWT-ish>hunter2secret", "token=<low>abcdefghij0123456789"]:
            out, hits = blot.Blotter().blot_line(line)
            self.assertTrue(hits, "not blotted: " + line)
            self.assertNotIn("hunter2secret", out, out)

    def test_a_real_label_still_shields_itself_from_later_rules(self):
        b = blot.Blotter()
        once, _ = b.blot_line("api_key=abcdefghijkl1234")
        self.assertIn("<", once)
        self.assertEqual(b.blot_line(once)[0], once, "a placeholder was blotted a second time")

    def test_the_repro_line_is_redacted_and_still_verifies_clean(self):
        rc, out, err = run("--quiet", "--verify", stdin="password=pa<ss1word99\n")
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("pa<ss1word99", out, out)

    def test_the_guard_accepts_truncated_labels_and_nothing_else(self):
        b = blot.Blotter()
        self.assertIsNotNone(b.label_re.search("<KV:1"), "a rule whose class stops at `>` can "
                             "match the label without its closing bracket")
        self.assertIsNone(b.label_re.search("pa<ss1word99"), "an ordinary `<` is not a label")
        self.assertIsNone(b.label_re.search("<jwt:1>"), "blot never emits a lowercase label")
        self.assertIsNotNone(b.label_re.search("<URLCREDENTIALS:12>"),
                             "the one label whose type is not a rule name")

    def test_every_label_blot_emits_is_matched_by_blots_own_guard(self):
        # URLCREDS emits <URLCREDENTIALS:n>, which is not the name of any rule: a guard built from
        # rule names alone would re-blot inside it and corrupt the one token pointing at the secret.
        samples = TestScreens.corpus() + [
            PEM, "wallet: " + SEED, "cipher=" + "0a1b2c3d4e5f60718293a4b5c6d7e8f90123a4b5",
            "postgres://deploy:Sup3rS3cret@db.internal:5432/app", "user@example.com",
            "x=4111 1111 1111 1111",
        ]
        b = blot.Blotter(pii=True, paranoid=True, rules=[("MY_INTERNAL_KEY",
                                                         re.compile(r"(?P<sec>none)"), ())])
        for line in samples:
            for sub in line.split("\n"):
                out = b.blot_line(sub)[0]
                for lab in re.findall(r"<[A-Za-z_][A-Za-z0-9_]*:[^>\s]*>", out):
                    self.assertIsNotNone(b.label_re.fullmatch(lab),
                                         "%s emitted in %r but the guard does not know it"
                                         % (lab, out))


class TestPII(unittest.TestCase):
    """`--pii` was advertised, listed in --list-types, and unreachable: none of the three PII patterns
    named a `sec` group, so the first email on a line raised IndexError out of main(). load_rules has
    refused a --rules regex without one all along; the built-ins are held to the same contract here."""

    def test_every_built_in_pattern_names_the_group_it_replaces(self):
        for name, rx, _screen in list(blot.RULES) + list(blot.PII):
            self.assertIn("sec", rx.groupindex, "%s cannot be replaced: no (?P<sec>...) group" % name)

    def test_pii_blots_instead_of_raising(self):
        for line, secret in [("contact user@example.com for details", "user@example.com"),
                             ("client 203.0.113.77 connected", "203.0.113.77"),
                             ("call +1 555 987 6543 back", "555 987 6543")]:
            out, hits = blot.Blotter(pii=True).blot_line(line)
            self.assertTrue(hits, "not blotted: " + line)
            self.assertNotIn(secret, out, out)

    def test_pii_is_off_unless_asked_for(self):
        line = "contact user@example.com for details"
        self.assertEqual(blot.Blotter().blot_line(line)[0], line)

    def test_the_pii_flag_survives_the_cli(self):
        rc, out, err = run("--pii", "--quiet", stdin="contact user@example.com\n")
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("user@example.com", out, out)


class TestPemOneLine(unittest.TestCase):
    """A key block whose BEGIN and END share a line is what a private key looks like inside JSON, an
    env var or a tfvars file. The state machine was written for the multi-line case and got the
    single-line one wrong in three ways at once."""

    ONE = ('{"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkq\\n'
           '-----END PRIVATE KEY-----\\n"}')

    def test_a_one_line_block_loses_its_body_and_keeps_its_wrapping(self):
        out, hits = blot.Blotter().blot_line(self.ONE)
        self.assertTrue(hits)
        self.assertNotIn("MIIEvQIBADANBgkq", out, out)
        self.assertNotIn("-----END", out, out)
        self.assertIn("<PRIVKEY:", out)
        self.assertIn('{"private_key": "', out, "the JSON around the key is not the secret")

    def test_a_one_line_block_does_not_swallow_the_next_line(self):
        # Returning from the BEGIN branch without clearing the state left the run inside a block that
        # had already closed, so every following line was deleted until the next -----END-----.
        b = blot.Blotter()
        first = b.blot_line(self.ONE)[0]
        second = b.blot_line("this line must survive intact")[0]
        self.assertNotIn("MIIE", first)
        self.assertEqual(second, "this line must survive intact")

    def test_two_blocks_on_one_line_are_both_gone(self):
        line = ('a="-----BEGIN RSA PRIVATE KEY-----\\nQVFBQVFB\\n-----END RSA PRIVATE KEY-----\\n" '
                'b="-----BEGIN EC PRIVATE KEY-----\\nU0VDUkVUCg==\\n-----END EC PRIVATE KEY-----\\n"')
        out, hits = blot.Blotter().blot_line(line)
        for body in ("QVFBQVFB", "U0VDUkVUCg=="):
            self.assertNotIn(body, out, "body %s survived: %s" % (body, out))
        self.assertGreaterEqual(hits, 2, out)

    def test_the_opening_line_of_a_multiline_block_keeps_its_context(self):
        out, _ = blot.Blotter().blot_line('key = "-----BEGIN PRIVATE KEY-----"')
        self.assertTrue(out.startswith("key = "), out)
        self.assertIn("<PRIVKEY:", out)

    def test_a_closed_pem_reaches_the_cli(self):
        rc, out, err = run("--quiet", "--verify", stdin=self.ONE + "\nafter the block\n")
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("MIIEvQIBADANBgkq", out, out)
        self.assertIn("after the block", out, "the run swallowed the line after a closed block")


class TestPgpBlocks(unittest.TestCase):
    """PGP's ASCII armor writes `-----BEGIN PGP PRIVATE KEY BLOCK-----`. The `[A-Z ]*PRIVATE KEY`
    in the markers could not reach past the space before BLOCK, so a private key in the most common
    export format on the planet was passed through untouched."""

    PGP = ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
           "Version: GnuPG v2\n"
           "Comment: AARgBV0DCADg9o0HkPu0M8oGBACMRm9jYW6lCgYEAo0=\n"
           "mQINBGVk7XgB/adRgK8pn0fqbGFr3V9u4TQ1Ck4w1jZ0Fg0Kk7w=\n"
           "=Xk3L\n"
           "-----END PGP PRIVATE KEY BLOCK-----")

    def test_a_pgp_private_key_block_becomes_one_label(self):
        b = blot.Blotter()
        outs = [b.blot_line(l) for l in self.PGP.split("\n")]
        labels = [o for o, _ in outs if o]
        self.assertEqual(len(labels), 1, outs)
        self.assertIn("<PRIVKEY:", labels[0])
        joined = "\n".join(o for o, _ in outs)
        for body in ("mQINBGVk7XgB", "adRgK8pn0fqbGFr3V9u4TQ1Ck4w", "=Xk3L"):
            self.assertNotIn(body, joined, "%s survived: %s" % (body, joined))

    def test_a_pgp_block_that_shares_one_line_is_blotted_too(self):
        line = ('{"secret": "-----BEGIN PGP PRIVATE KEY BLOCK-----\\nVersion: h\\nmQINBGVk7XgB\\n'
                '-----END PGP PRIVATE KEY BLOCK-----\\n"}')
        out, hits = blot.Blotter().blot_line(line)
        self.assertTrue(hits)
        self.assertNotIn("mQINBGVk7XgB", out, out)
        self.assertNotIn("-----END", out, out)

    def test_the_line_after_a_pgp_block_survives(self):
        b = blot.Blotter()
        for l in self.PGP.split("\n"):
            b.blot_line(l)
        self.assertEqual(b.blot_line("the next log line")[0], "the next log line")

    def test_a_public_key_block_is_not_a_secret(self):
        # Over-redaction is a failure too: a PUBLIC KEY BLOCK is public by name, and blotting it
        # would take the fingerprint a reader needs out of the report.
        line = ("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                "mQINBGVk7XgB/QFx0hv3kZ1sCgYEAo8uI1n3Q4tLpZ7w=\n"
                "-----END PGP PUBLIC KEY BLOCK-----")
        b = blot.Blotter()
        outs = [b.blot_line(l) for l in line.split("\n")]
        self.assertEqual([o for o, _ in outs], line.split("\n"), outs)


class TestSeedPhrase(unittest.TestCase):
    """A wallet seed is 12/15/18/21/24 words from one fixed 2048-word list. The detector had a ~50
    word guess at that list, so a real mnemonic made of other words passed, and `mnemonic=<12 words>`
    blotted exactly one word of it."""

    SEED12 = ("abandon ability able about above absent absorb abstract absurd abuse access accident")
    SEED24 = ("abandon ability able about above absent absorb abstract absurd abuse access accident "
              "account accuse achieve acid acoustic acquire across act action actor actress actual")
    # 10 of 12 from the list: the bar is "at least 80%", not "all of them", because a transcription
    # with two words misread from a photo of a seed sheet is still a seed sheet.
    MIX10 = ("abandon ability able about above absent absorb abstract absurd abuse witch least")
    PROSE12 = "our vendor shipped a broken widget nobody could debug before the weekly release"

    def test_the_wordlist_is_the_real_bip39_list(self):
        self.assertEqual(len(blot.BIP39), 2048, "the list is not the BIP39 English list")
        self.assertEqual(len(set(blot.BIP39)), 2048, "the list has duplicates")
        self.assertEqual(blot.BIP39[0], "abandon")
        self.assertEqual(blot.BIP39[-1], "zoo")

    def test_a_bare_twelve_word_seed_is_one_secret(self):
        out, hits = blot.Blotter().blot_line("backup " + self.SEED12 + " restored")
        self.assertTrue(hits, "a 12-word run from the list was passed through")
        self.assertIn("<SEEDPHRASE:", out)
        for w in self.SEED12.split():
            self.assertNotIn(w, out, "%s survived in %s" % (w, out))

    def test_every_valid_phrase_length_is_recognised(self):
        words = self.SEED24.split()
        for n in (12, 15, 18, 21, 24):
            out, hits = blot.Blotter().blot_line(" ".join(words[:n]))
            self.assertTrue(hits, "%d-word phrase missed" % n)
            self.assertIn("<SEEDPHRASE:", out)

    def test_a_phrase_with_two_words_off_the_list_still_blots(self):
        out, hits = blot.Blotter().blot_line(self.MIX10)
        self.assertTrue(hits, "10/12 on the list is 83%, which is over the bar")
        self.assertNotIn("witch", out, out)

    def test_a_three_letter_list_word_does_not_break_the_run(self):
        # BIP39 words run to three characters (`act`, `add`, `air`); the old {4,12} class cut a seed
        # in half at the first one.
        line = ("abandon ability able about above absent absorb abstract absurd abuse access act")
        out, hits = blot.Blotter().blot_line(line)
        self.assertTrue(hits, out)
        self.assertNotIn("abandon", out, out)

    def test_a_twelve_word_english_sentence_is_not_redacted(self):
        out, hits = blot.Blotter(paranoid=True).blot_line(self.PROSE12)
        self.assertEqual(out, self.PROSE12, "over-redacted ordinary prose")
        self.assertFalse(hits, out)

    def test_a_seed_site_consumes_the_whole_value_not_its_first_word(self):
        # This is the shape from the report: `mnemonic=` followed by words that are mostly not on the
        # list. The name says the field holds a phrase, so everything after it is the secret.
        line = "mnemonic=witch collapse practice feed shame open despair creek road again ice least"
        out, hits = blot.Blotter().blot_line(line)
        self.assertTrue(hits)
        for w in line.split("=")[1].split():
            self.assertNotIn(w, out.split("=", 1)[1], "`%s` survived: %s" % (w, out))

    def test_seed_mnemonic_and_recovery_names_all_take_the_phrase(self):
        for name in ("seed", "mnemonic", "recovery_phrase", "recovery phrase", "seed_words",
                     "SEED-PHRASE"):
            line = '%s="correct horse battery staple purple giraffe"' % name
            out, _ = blot.Blotter().blot_line(line)
            self.assertNotIn("giraffe", out, "%s left the tail of the phrase: %s" % (name, out))
            self.assertNotIn("staple", out, "%s left the tail of the phrase: %s" % (name, out))

    def test_a_single_word_value_at_a_seed_site_still_blots(self):
        out, hits = blot.Blotter().blot_line("mnemonic=witch")
        self.assertTrue(hits, out)
        self.assertNotIn("witch", out, out)

    def test_the_repro_line_verifies_clean_after_redaction(self):
        rc, out, err = run("--quiet", "--verify",
                           stdin="mnemonic=" + " witch collapse practice feed shame open despair "
                           "creek road again ice least\n")
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("despair", out, out)


class TestWeb3(unittest.TestCase):
    """Chain keys are the reason a lot of these logs exist. They are also the hardest shape to catch
    honestly: `0x` + 64 hex is equally a transaction hash, and a base58 string is equally a public key,
    so the site name is what decides and the name has to be a *whole* word — `monkey` ends in `key`."""

    EVM = "0x" + "ab" * 32                       # 32 bytes, hex, 0x-prefixed
    EVM_NO0X = "ab" * 32
    SOL = "4p2M" + "n7Kd" * 21                   # 88 chars of base58, no 0/O/I/l
    SOL_PUB = "4p2M" + "n7Kd" * 5 + "7"          # 32-44 chars: a public key, not a secret
    SUI = "sui" + "privkey1" + "qprz" * 20 + "yd"
    ARR = "[" + ", ".join(str(i * 4 % 256) for i in range(64)) + "]"
    ALK = "Ab3d" + "Ef6gHi8jK0Lm2No4Pq6Rs8T"     # 28 chars, assembled like the rest
    INF = "1p2q" + "3r4s5t6u7v8w9x0y1z2a3b4c"
    QKN = "9f8e" + "7d6c5b4a39281706f5e4d3c2b1a0"
    ANK = "0123" + "456789abcdef0123456789abcdef"
    HEL = "a1b2" + "c3d4e5f60718293a4b5c6d7e8f90"

    def blotted(self, line):
        out, hits = blot.Blotter().blot_line(line)
        self.assertTrue(hits, "not blotted: " + line)
        return out

    def test_a_hex_key_at_a_signer_name_is_blotted_by_default(self):
        for name in ("deployer_key", "SIGNER_KEY", "pk", "user_pk", "sui_private", "eth-key",
                     "my_signer", "validator_private", "WALLET_PK", "SIGNER_PK"):
            out = self.blotted("%s=%s" % (name, self.EVM))
            self.assertNotIn(self.EVM, out, "%s survived: %s" % (name, out))
            self.assertIn("<EVMPRIVKEY:", out, "%s mislabelled: %s" % (name, out))

    def test_a_name_kv_already_knows_keeps_the_generic_label(self):
        # KV runs first on purpose. `API_KEY=0x…` is a named secret, and stamping it EVMPRIVKEY would
        # claim which chain was leaked from a line that does not say. Vague beats wrong.
        for name in ("PRIVATE_KEY", "private_key", "api_key", "API_KEY", "MNEMONIC", "secretKey"):
            out = self.blotted("%s=%s" % (name, self.EVM))
            self.assertNotIn(self.EVM, out, name + " survived")
            self.assertNotIn("EVMPRIVKEY", out, "%s over-claimed: %s" % (name, out))

    def test_a_name_that_merely_ends_in_the_letters_key_is_not_a_key_site(self):
        for name in ("monkey", "donkey", "hockey", "turkey"):
            line = "%s=%s" % (name, self.EVM)
            self.assertEqual(blot.Blotter().blot_line(line)[0], line,
                             "over-redacted %s=: a word is not a field name" % name)

    def test_quoted_and_json_forms_of_the_same_site_blot(self):
        for line in ['"private_key": "%s",' % self.EVM, "private_key: '%s'" % self.EVM,
                    '{"PRIVATE_KEY":"%s"}' % self.EVM]:
            out = self.blotted(line)
            self.assertNotIn(self.EVM, out, out)

    def test_a_suiprivkey_is_blotted(self):
        out = self.blotted("sui key: " + self.SUI)
        self.assertIn("<SUIPRIVKEY:", out, out)
        self.assertNotIn(self.SUI, out, out)

    def test_a_solana_base58_secret_key_is_blotted(self):
        out = self.blotted("keypair " + self.SOL + " loaded")
        self.assertIn("<SOLPRIVKEY:", out, out)
        self.assertNotIn(self.SOL, out, out)

    def test_a_solana_public_key_is_left_alone(self):
        # 32-44 base58 characters is an address, and addresses are the thing a log is *about*.
        line = "transfer to " + self.SOL_PUB + " confirmed"
        self.assertEqual(blot.Blotter().blot_line(line)[0], line, "over-redacted an address")

    def test_a_json_byte_array_keypair_at_a_key_site_is_blotted(self):
        for name in ("secretKey", "private_key", "keypair", "wallet", "keystore"):
            out = self.blotted('%s": %s' % (name, self.ARR))
            self.assertNotIn("252, 44", out, "%s survived: %s" % (name, out))
            self.assertIn("<SOLKEYJSON:", out, "%s mislabelled: %s" % (name, out))

    def test_an_array_at_a_non_key_site_is_not_a_keypair(self):
        for line in ["samples=" + self.ARR, "frame [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] dumped",
                     "rgb=[240, 128, 64]"]:
            self.assertEqual(blot.Blotter().blot_line(line)[0], line,
                             "over-redacted an ordinary array: " + line)

    def test_rpc_urls_lose_their_key_and_keep_their_host(self):
        cases = [("https://eth-mainnet.g.alchemy.com/v2/" + self.ALK, "alchemy.com/v2/"),
                 ("https://mainnet.infura.io/v3/" + self.INF, "infura.io/v3/"),
                 ("https://solo.quiknode.pro/" + self.QKN, "quiknode.pro/"),
                 ("https://rpc.ankr.com/solana/" + self.ANK, "ankr.com/solana/"),
                 ("https://mainnet.helius-rpc.com/?api-key=" + self.HEL, "api-key=")]
        for line, host in cases:
            out = self.blotted(line)
            key = line.rsplit("/", 1)[-1].split("=", 1)[-1]
            self.assertNotIn(key, out, "%s survived: %s" % (host, out))
            self.assertIn(host, out, "the host is what makes the line readable: " + out)

    def test_a_keyless_rpc_url_is_untouched(self):
        for line in ["https://eth-mainnet.g.alchemy.com/v2/",
                     "https://rpc.ankr.com/solana",
                     "https://api.mainnet-beta.solana.com",
                     "https://mainnet.infura.io/v3/" + "e" * 12]:
            out, _ = blot.Blotter().blot_line(line)
            self.assertEqual(out, line, "over-redacted: " + out)

    def test_etherscan_family_keys_at_an_apikey_site(self):
        key = "aB3dE5fG7hJ9kL1mN3oP5qR7sT9uV1w"      # 31 chars, assembled like the rest
        for line, name in [("https://api.etherscan.io/api?module=account&action=balance&apikey=" + key,
                            "api.etherscan.io"),
                           ("https://api.bscscan.com/api?apikey=" + key, "api.bscscan.com"),
                           ("ETHERSCAN_API_KEY=" + key, "ETHERSCAN_API_KEY"),
                           ("polygonscan_apikey: " + key, "polygonscan_apikey")]:
            out = self.blotted(line)
            self.assertNotIn(key, out, "%s survived: %s" % (name, out))
            self.assertIn("<ETHERSCAN:", out, "%s mislabelled: %s" % (name, out))
            self.assertIn(name.split("/")[0] if "http" in line else name, out,
                            "the site must stay readable: " + out)

    def test_a_short_apikey_value_is_not_claimed_by_the_family_rule(self):
        # KV has long blotted `apikey=<5+ chars>` as a named secret, and that stays: this asserts the
        # ETHERSCAN floor is not so low that a placeholder token gets reported as an Etherscan key.
        line = "curl 'https://api.etherscan.io/api?apikey=short-token'"
        out, hits = blot.Blotter().blot_line(line)
        self.assertTrue(hits, "the name says apikey, so KV should still reach it")
        self.assertNotIn("<ETHERSCAN:", out, "a 10-character value is not a 31-character key: " + out)

    def test_these_reach_the_cli_without_extra_flags(self):
        text = ("PRIVATE_KEY=%s\nsui=%s\n%s\nhttps://eth-mainnet.g.alchemy.com/v2/%s\n"
                % (self.EVM, self.SUI, self.SOL, self.ALK))
        rc, out, err = run("--quiet", "--verify", stdin=text)
        self.assertEqual(rc, 0, out + err)
        for secret in (self.EVM, self.SUI, self.SOL, self.ALK):
            self.assertNotIn(secret, out, "%s survived to stdout" % secret[:12])


class TestKeyNames(unittest.TestCase):
    """KV is a curated list of names, so the list has to cover the names people actually leak.
    Over-matching is a failure too, so both directions get asserted."""

    def test_framework_secret_names_are_caught_by_name(self):
        for line in ["APP_KEY=base64:VGhpcyBpc250YV9yZWFsX2tleQ==",
                     "SECRET_KEY_BASE=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                     "MASTER_KEY=0123456789abcdef0123456789abcdef",
                     "encryption_key = f9e8d7c6b5a4938271625f4e3d2c1b0a"]:
            out, hits = blot.Blotter().blot_line(line)
            self.assertTrue(hits, "missed by name: " + line)
            self.assertNotIn(line.split("=", 1)[1].strip(), out, "survived: " + out)

    def test_an_ordinary_key_name_is_not_treated_as_a_secret(self):
        for line in ["sort_key=created_at", "cache_key=user:42", "monkey_key=banana",
                     "primary_key=id"]:
            out, _ = blot.Blotter().blot_line(line)
            self.assertEqual(out, line, "over-redacted: " + line)

    def test_paranoid_reaches_the_vendor_names_the_list_cannot_hold(self):
        line = "MYVENDOR_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
        self.assertEqual(blot.Blotter().blot_line(line)[0], line, "the default stays quiet")
        out, hits = blot.Blotter(paranoid=True).blot_line(line)
        self.assertTrue(hits, "--paranoid should reach the long tail of *key= sites")
        self.assertIn("<ENTROPY", out)


    def test_the_vendor_wave_is_labelled_by_vendor(self):
        for typ, line in [
            ("GITLAB", "x=glpat-" + "a" * 20),
            ("NPM", "x=npm_" + "b" * 36),
            ("PYPI", "x=pypi-AgEIcHlwaS5vcmc" + "c" * 40),
            ("HUGGINGFACE", "x=hf_" + "d" * 34),
            ("CLOUDFLARE", "x=cfut_" + "e" * 40),
            ("GRAFANA", "x=glsa_" + "f" * 30),
            ("GRAFANA", "x=gldc_" + "f" * 30),
            ("SENTRY", "x=sntrys_" + "g" * 48),
            ("SENDGRID", "x=SG." + "h" * 20 + "." + "i" * 40),
            ("STRIPEWH", "x=whsec_" + "j" * 24),
            ("GOOAUTH", "x=ya29." + "k" * 40),
            ("TWILIOSID", "account_sid=AC" + "0123456789abcdef" * 2),
            ("SLACKWEBHOOK", "https://hooks.slack.com/services/T000/B000/" + "Z" * 24),
            ("DISCORDHOOK", "https://discord.com/api/webhooks/123456789012345678/" + "Y" * 30),
            ("DIGITALOCEAN", "x=dop_v1_" + "0" * 64),
            ("VAULT", "x=hvs_" + "a" * 24),
            ("DOCKERHUB", "x=dckr_pat_" + "b" * 27),
            ("NEWRELIC", "x=NRAK-" + "C" * 24),
            ("B64PEM", "TF_VAR_key=LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t"),
            ("AZURE", "Endpoint=sb://x.servicebus.windows.net/;SharedAccessKeyName=ro;"
                      "AccountKey=" + "dGhpcyBpc250YSByZWFsIGtleSBidXQgaXQgaXMgbG9uZw==" * 2),
            ("JWK", '{"kty":"RSA","e":"AQAB","d":"RbTj9xV3zQnZqQmW3kK7pQj4dZ3cR7pQj4dZ3cR7pQj4dZ"}'),
            ("HDR", "x-api-key: abcdefghijklmnop1234"),
            ("AUTHSCHEME", "Authorization: ssws abcdefghijklmnop1234"),
            ("AUTHHEADER", "Authorization: 03af9d2b1c5e7f8a9b0c1d2e3f4a5b6c"),
        ]:
            out, hits = blot.Blotter().blot_line(line)
            self.assertTrue(hits, "%s not blotted: %s" % (typ, line))
            self.assertIn("<%s:" % typ, out, "%s mislabelled: %s" % (typ, out))

    def test_the_name_stays_visible_when_only_the_value_is_a_credential(self):
        b = blot.Blotter()
        out, _ = b.blot_line("account_sid=AC" + "0123456789abcdef" * 2)
        self.assertIn("account_sid=", out, "a reader must still know which field this was")


class TestScreens(unittest.TestCase):
    """Each rule carries a screen: literals that ANY match must contain. That is a claim about the
    regex, and getting it backwards silently loses secrets. So: run the whole corpus with screens on
    and off and demand identical output, and enumerate every alternation branch because that is
    where a screen breaks."""

    @staticmethod
    def corpus():
        cases = []
        for pre in ("AKIA", "ASIA", "AIDA", "AROA", "AGPA", "AIPA", "ANVA", "APINA"):
            cases.append("x=%s%s" % (pre, "B" * 16))
        for p in ("ghp", "gho", "ghu", "ghs", "ghr"):
            cases.append("x=%s_%s" % (p, "a" * 24))
        cases.append("x=github_pat_" + "a" * 24 + "_" + "b" * 24)
        for t in ("xoxb", "xoxa", "xoxp", "xoxr", "xoxs"):
            cases.append("x=%s-%s" % (t, "c" * 12))
        for a in ("sk", "pk", "rk"):
            for e in ("live", "test"):
                cases.append("x=%s_%s_%s" % (a, e, "d" * 12))
        for s in ("sk-", "sk-ant-", "sk-proj-"):
            cases.append("x=" + s + "e" * 24)
        cases.append("x=AIza" + "F" * 35)
        cases.append("x=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.aaaaaaaaaaaaaaaaaaaaa")
        cases.append("postgres://deploy:Sup3rS3cret@db.internal:5432/app")
        cases.append("Authorization: Bearer abcdefghijklmnop")
        cases.append("basic U2VjcmV0VmFsdWU=")
        cases.append("Cookie: session=abcdefghijklmnop")
        for v in ("glpat-" + "a" * 20, "npm_" + "b" * 36, "pypi-AgEIcHlwaS5vcmc" + "c" * 40,
                  "hf_" + "d" * 34, "cfut_" + "e" * 40, "glsa_" + "f" * 30, "gldc_" + "f" * 30,
                  "sntrys_" + "g" * 48, "SG." + "h" * 20 + "." + "i" * 40, "whsec_" + "j" * 24,
                  "ya29." + "k" * 40, "AC" + "0123456789abcdef" * 2,
                  "https://hooks.slack.com/services/T000/B000/" + "Z" * 24,
                  "https://discord.com/api/webhooks/123456789012345678/" + "Y" * 30):
            cases.append("account_sid=" + v)
            cases.append("x=" + v)
        cases += [
            "x=dop_v1_" + "0" * 64, "x=hvs_" + "a" * 24, "x=dckr_pat_" + "b" * 27,
            "x=NRAK-" + "C" * 24,
            "TF_VAR_key=LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t",
            "AccountKey=" + "dGhpcyBpc250YSByZWFsIGtleSBidXQgaXQgaXMgbG9uZw==" * 2,
            '{"kty":"RSA","e":"AQAB","d":"RbTj9xV3zQnZqQmW3kK7pQj4dZ3cR7pQj4dZ3cR7pQj4dZ"}',
            "x-api-key: abcdefghijklmnop1234",
            "Authorization: ssws abcdefghijklmnop1234",
            "Authorization: 03af9d2b1c5e7f8a9b0c1d2e3f4a5b6c",
        ]
        for n in ("password", "passwd", "pass", "pwd", "secret", "secret_key", "secret_key_base",
                  "api_key", "apikey", "app_key", "master_key", "encryption_key", "signing_key",
                  "access_key", "access_key_id", "access_token", "private_key", "auth_token",
                  "refresh_token", "session_token", "bearer_token", "id_token", "token", "seed",
                  "mnemonic", "recovery_phrase", "otp", "client_secret", "webhook_secret"):
            cases.append('%s="Sup3rS3cretValue"' % n)
            cases.append("%s: Sup3rS3cretValue" % n.upper())
        # KVPHRASE's branches, each with a multi-word value: the screens claim for this rule is about
        # the names, and every name in the alternation has to be exercised with a value that reaches
        # the `sec` group.
        for n in ("seed", "mnemonic", "recovery_phrase", "recovery phrase", "seed_words",
                  "SEED-PHRASE", "mnemonic_backup", "recovery-key"):
            cases.append('%s="witch collapse practice feed shame open despair"' % n)
            cases.append("%s: abandon, ability, able, above, absent, absorb" % n.upper())
        # Chain keys: every branch of every name alternation, both ways a name can be written, and the
        # two shapes that carry no name at all. A screen that is wrong in the loose direction loses a
        # detector silently, and these are the rules whose screens are easiest to get wrong.
        hexkey = "0x" + "cd" * 32
        for n in ("DEPLOYER_KEY", "signer_key", "pk", "user_pk", "sui_private", "eth-key",
                  "my_signer", "MNEMONIC", "validator_private", "WALLET_PK", "private_key",
                  "API_KEY", "secretKey", "SIGNER_PK"):
            cases.append("%s=%s" % (n, hexkey))
        cases.append("sui key: " + "sui" + "privkey1" + "qprz" * 20)
        cases.append("keypair " + "4p2M" + "n7Kd" * 21 + " loaded")
        cases.append('secretKey": [' + ", ".join(str(i * 4 % 256) for i in range(64)) + "]")
        cases += [
            "https://eth-mainnet.g.alchemy.com/v2/" + "Ab3d" + "Ef6gHi8jK0Lm2No4Pq6Rs8T",
            "https://mainnet.infura.io/v3/" + "1p2q" + "3r4s5t6u7v8w9x0y1z2a3b4c",
            "https://solo.quiknode.pro/" + "9f8e" + "7d6c5b4a39281706f5e4d3c2b1a0",
            "https://x.y.solana.mainnet.quiknode.pro/aaa/" + "9f8e" + "7d6c5b4a39281706f",
            "https://rpc.ankr.com/solana/" + "0123" + "456789abcdef0123456789abcdef",
            "https://mainnet.helius-rpc.com/?api-key=" + "a1b2" + "c3d4e5f60718293a4b5c6d7e8f90",
            "https://api.etherscan.io/api?apikey=" + "aB3dE5fG7hJ9kL1mN3oP5qR7sT9uV1w",
            "ETHERSCAN_API_KEY=" + "aB3dE5fG7hJ9kL1mN3oP5qR7sT9uV1w",
            "polygonscan_apikey: " + "aB3dE5fG7hJ9kL1mN3oP5qR7sT9uV1w",
            "https://api.bscscan.com/api?apikey=" + "aB3dE5fG7hJ9kL1mN3oP5qR7sT9uV1w",
            "https://api.arbiscan.io/api?apikey=" + "aB3dE5fG7hJ9kL1mN3oP5qR7sT9uV1w",
            "https://api.basescan.org/api?apikey=" + "aB3dE5fG7hJ9kL1mN3oP5qR7sT9uV1w",
            "https://api.ftmscan.com/api?apikey=" + "aB3dE5fG7hJ9kL1mN3oP5qR7sT9uV1w",
            "https://api.hecoinfo.com/api?apikey=" + "aB3dE5fG7hJ9kL1mN3oP5qR7sT9uV1w",
            "https://api.snowtrace.io/api?apikey=" + "aB3dE5fG7hJ9kL1mN3oP5qR7sT9uV1w",
        ]
        cases += ["nothing to see here, just a log line",
                  "commit 4f9a3cbe0a1d2b3c4d5e6f708192a3b4c5d6e7f8",
                  "GET /api/v1/users?page=2 200 14ms"]
        return cases

    def setUp(self):
        self.cases = self.corpus()

    def test_screens_change_speed_and_nothing_else(self):
        for line in self.cases:
            for flags in ({}, {"pii": True}, {"paranoid": True}, {"pii": True, "paranoid": True}):
                on = blot.Blotter(screen=True, **flags).blot_line(line)
                off = blot.Blotter(screen=False, **flags).blot_line(line)
                self.assertEqual(on, off, "screens changed %r with %r" % (line, flags))

    def test_the_corpus_still_matches_so_the_comparison_is_not_vacuous(self):
        hit = sum(1 for l in self.cases if blot.Blotter().blot_line(l)[1])
        self.assertGreater(hit, int(len(self.cases) * 0.9),
                           "only %d of %d lines matched; the corpus stopped exercising the rules"
                           % (hit, len(self.cases)))

    def test_a_screen_literal_that_only_appears_in_a_placeholder_cannot_hide_a_real_secret(self):
        # Labels are uppercase words like <LLMTOKEN:1>, which lowercase to text containing "token"
        # and "key". A later rule must not be skipped because the literal arrived via a label.
        line = "token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa and password=Sup3rS3cretValue"
        self.assertEqual(blot.Blotter().blot_line(line), blot.Blotter(screen=False).blot_line(line))


class TestInputAndErrors(unittest.TestCase):
    """The failure modes that make a redactor unsafe to trust: silently doing nothing."""

    def test_stdin_is_read_when_no_file_is_named(self):
        rc, out, err = run(stdin="token %s\n" % GH)
        self.assertEqual(rc, 0, err)
        self.assertIn("<GHTOKEN:1>", out)

    def test_dash_reads_stdin_even_next_to_a_file(self):
        path = scratch("_in.txt")
        with open(path, "w") as fh:
            fh.write("a " + AWS + "\n")
        try:
            rc, out, err = run(path, "-", stdin="b " + GH + "\n")
            self.assertEqual(rc, 0, err)
            self.assertIn("<AWS:1>", out)
            self.assertIn("<GHTOKEN:1>", out)
        finally:
            os.remove(path)

    def test_empty_input_is_empty_output(self):
        rc, out, err = run(stdin="")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "")

    def test_a_missing_file_is_a_message_not_a_traceback(self):
        rc, out, err = run("this-file-does-not-exist.txt")
        self.assertEqual(rc, 2, err)
        self.assertNotIn("Traceback", err)
        self.assertIn("this-file-does-not-exist.txt", err)

    def test_an_unwritable_out_file_does_not_report_success(self):
        rc, out, err = run("--out", "/nonexistent-dir/out.txt", stdin="token %s\n" % GH)
        self.assertEqual(rc, 2, err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("verify OK", err)

    def test_a_typo_in_keep_is_refused_rather_than_ignored(self):
        rc, out, err = run("--keep", "AWSKEY", stdin="aws " + AWS + "\n")
        self.assertEqual(rc, 2, err)
        self.assertIn("unknown --keep", err)

    def test_keep_is_case_insensitive(self):
        rc, out, err = run("--keep", "aws", stdin="aws " + AWS + "\n")
        self.assertEqual(rc, 0, err)
        self.assertIn(AWS, out)

    def test_a_closed_consumer_is_not_reported_as_a_failure(self):
        # A file for stdin, not a pipe: blot streams now, so a parent that writes all of a 1 MB
        # input before reading any of it deadlocks on pipe buffers — the same way `cat` does. The
        # usage under test is `blot big.log | head -1`, which is exactly this shape.
        path = scratch("_closed.txt")
        with open(path, "w") as fh:
            fh.write("".join("line %d token %s\n" % (i, GH) for i in range(20000)))
        try:
            p = subprocess.Popen([sys.executable, CLI, path], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
            p.stdout.readline()
            p.stdout.close()  # the consumer went away mid-stream, the way `| head -1` does
            err = p.stderr.read()
            rc = p.wait(timeout=60)
            p.stderr.close()
            self.assertNotIn("Traceback", err)
            self.assertEqual(rc, 0, err)
        finally:
            os.remove(path)


    def test_the_map_refuses_to_overwrite_an_existing_file(self):
        path = scratch("_map.json")
        with open(path, "w") as fh:
            fh.write("the only copy of something important\n")
        try:
            rc, out, err = run("--map", path, stdin="password=hunter2supersecret\n")
            self.assertEqual(rc, 2, err)
            self.assertIn("cannot write the reverse map", err)
            with open(path) as fh:
                self.assertIn("only copy", fh.read(), "--map clobbered an existing map")
        finally:
            os.remove(path)

    def test_undecodable_bytes_do_not_abort_a_redaction(self):
        raw = b"blob \xff\xfe on a binary-ish line\npassword=hunter2secretvalue\n"
        p = subprocess.run([sys.executable, CLI], input=raw, capture_output=True)
        self.assertNotIn(b"Traceback", p.stderr)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(b"<KV:1>", p.stdout)
        self.assertNotIn(b"hunter2secretvalue", p.stdout)


    def test_ctrl_c_is_an_exit_code_not_a_traceback(self):
        p = subprocess.Popen([sys.executable, CLI], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(0.5)  # blocked on a stdin that never sends anything, the way Ctrl-C finds it
        p.send_signal(signal.SIGINT)
        rc = p.wait(timeout=30)
        err = p.stderr.read()
        for fh in (p.stdout, p.stderr, p.stdin):
            fh.close()
        self.assertNotIn("Traceback", err)
        self.assertEqual(rc, 130, err)


    def test_crlf_line_endings_survive_the_round_trip(self):
        path = scratch("_crlf.txt")
        with open(path, "w", newline="") as fh:
            fh.write("password=hunter2secretvalue\r\ntoken=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5\r\n")
        try:
            p = subprocess.run([sys.executable, CLI, path], capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            # bytes, not text=True: universal newlines in the *parent* would translate \r\n away and
            # the assertion would pass or fail on the harness rather than on blot.
            self.assertIn(b"\r\n", p.stdout, "blot rewrote the file's line endings")
            self.assertNotIn(b"hunter2secretvalue", p.stdout)
        finally:
            os.remove(path)

    def test_a_binary_is_refused_rather_than_written_out(self):
        path = scratch("_bin.dat")
        with open(path, "wb") as fh:
            fh.write(b"\x7fELF\x00\x00password=hunter2secretvalue\x00")
        try:
            rc, out, err = run(path)
            self.assertEqual(rc, 2, err)
            self.assertIn("NUL", err)
            self.assertEqual(out, "", "binary content reached stdout")
        finally:
            os.remove(path)


class TestMapGuard(unittest.TestCase):
    """The reverse map is the one file whose leak is total. blot refuses the two ways that happens:
    a world-readable moment while writing, and landing in a repository."""

    SECRET_LINE = "password=hunter2supersecret\n"

    def test_a_map_is_refused_inside_a_git_work_tree(self):
        path = os.path.join(HERE, "_map.json")
        self.assertTrue(blot.in_git_worktree(HERE), "this test file should be inside a repo")
        rc, out, err = run("--map", path, stdin=self.SECRET_LINE)
        self.assertEqual(rc, 2, err)
        self.assertIn("work tree", err)
        self.assertFalse(os.path.exists(path), "refused it, then wrote it anyway")

    def test_a_map_outside_a_work_tree_needs_no_force(self):
        rc, out, err = run("--map", scratch("_map.json"), stdin=self.SECRET_LINE)
        self.assertEqual(rc, 0, err)

    def test_force_lets_a_map_land_in_a_work_tree_and_replace_itself(self):
        path = os.path.join(HERE, "_map.json")
        try:
            rc, out, err = run("--map", path, "--force", stdin=self.SECRET_LINE)
            self.assertEqual(rc, 0, err)
            self.assertEqual(oct(os.stat(path).st_mode)[-3:], "600")
            rc2, _o, err2 = run("--map", path, "--force", stdin="password=anothersecretvalue\n")
            self.assertEqual(rc2, 0, err2)
        finally:
            os.remove(path)


    def test_a_word_that_merely_contains_a_secret_name_is_not_one(self):
        # `pass` and `otp` are substrings of ordinary words; without boundaries bypass, compass and
        # footprint all look like fields holding a credential and get blotted.
        for line in ["bypass=123456789", "compass: 123456789", "footprint=1234567890",
                     "surpass: 123456789", "tokenizer=created_at"]:
            out, _ = blot.Blotter().blot_line(line)
            self.assertEqual(out, line, "over-redacted: " + out)

    def test_the_compound_and_uppercase_forms_still_blot(self):
        for line in ["password=abcdefgh12345", "passwd: abcdefgh12345", "pass=abcdefgh12345",
                     "passphrase=abcdefgh12345", "totp=JBSWY3DPEHPK3PXP", "OTP: JBSWY3DPEHPK3PXP"]:
            out, hits = blot.Blotter().blot_line(line)
            self.assertTrue(hits, "missed: " + line)
            self.assertNotIn("abcdefgh12345", out)
            self.assertNotIn("JBSWY3DPEHPK3PXP", out)


class TestCandidateClasses(unittest.TestCase):
    """The half of a leak that wears no key name — a bare seed, a UUID, a hex private key, a base64
    blob — is invisible to the rules by design. The sweep is what makes it visible to a reviewer."""

    def test_the_sweep_reports_secrets_that_wore_no_key_name(self):
        for line, kind in [
            ("trace 6fa45ea5-4cf0-4c4b-9f42-c0e0f0e0d1c2 accepted", "uuid"),
            ("session 4f9a3cbe0a1d2b3c4d5e6f708192a3b4c5d6e7f8 ok", "hex"),
            ("provision JBSWY3DPEHPK3PXPAAB for user 42", "base32"),
            ("blob dGhpcyBpc250YSBzZWNyZXQgYnV0IG5vbmUgaGFzIG1lCg dumped", "bare"),
        ]:
            b = blot.Blotter(candidates=True)
            b.blot_line(line)
            kinds = {c["kind"] for c in b.candidate_report()}
            self.assertIn(kind, kinds, "%s not reported as %s: %s" % (line, kind, sorted(kinds)))

    def test_a_shape_is_reported_once_under_its_most_specific_class(self):
        line = "session 4f9a3cbe0a1d2b3c4d5e6f708192a3b4c5d6e7f8 ok"
        b = blot.Blotter(candidates=True)
        b.blot_line(line)
        rows = b.candidate_report()
        self.assertEqual([r["kind"] for r in rows], ["hex"], rows)

    def test_a_card_is_not_also_reported_as_a_bare_digit_run(self):
        b = blot.Blotter(candidates=True)
        b.blot_line("acct=4111 1111 1111 1111")
        self.assertEqual([r["kind"] for r in b.candidate_report()], ["card"])

    def test_the_sweep_still_quotes_nothing(self):
        b = blot.Blotter(candidates=True)
        for line in ["provision JBSWY3DPEHPK3PXPAAB", "trace 6fa45ea5-4cf0-4c4b-9f42-c0e0f0e0d1c2",
                     "session 4f9a3cbe0a1d2b3c4d5e6f708192a3b4c5d6e7f8"]:
            b.blot_line(line)
        blob = json.dumps(b.candidate_report())
        for secret in ("JBSWY3DPEHPK3PXPAAB", "6fa45ea5-4cf0-4c4b-9f42-c0e0f0e0d1c2",
                       "4f9a3cbe0a1d2b3c4d5e6f708192a3b4c5d6e7f8"):
            self.assertNotIn(secret, blob, "a candidate context leaked the value it describes")

    def test_the_candidate_prefilter_changes_nothing(self):
        lines = TestScreens.corpus() + [
            "acct=4111 1111 1111 1111", "trace 6fa45ea5-4cf0-4c4b-9f42-c0e0f0e0d1c2",
            "provision JBSWY3DPEHPK3PXPAAB",
            "blob dGhpcyBpc250YSBzZWNyZXQgYnV0IG5vbmUgaGFzIG1lCg",
            "session 4f9a3cbe0a1d2b3c4d5e6f708192a3b4c5d6e7f8", "MY_INTERNAL_KEY=zzzQQQQqqqzz",
            "just a sentence about nothing", "GET /api/v1/users?page=2 200 14ms",
        ]
        for line in lines:
            on = blot.Blotter(candidates=True)
            off = blot.Blotter(candidates=True, screen=False)
            self.assertEqual(on.blot_line(line), off.blot_line(line), line)
            self.assertEqual(on.candidate_report(), off.candidate_report(),
                             "the prefilter hid a candidate on: %s" % line)


class TestEntropyGate(unittest.TestCase):
    SHA = "4f9a3cbe0a1d2b3c4d5e6f708192a3b4c5d6e7f8"
    OTHER = "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567"

    def test_a_hex_key_is_blotted_once_the_measure_is_in_bits(self):
        # ln(16)=2.77 nats: under a nats threshold no hex secret could ever reach 3.0, so --paranoid
        # silently spared every 40-hex key. Name a site KV does not know, so this proves the measure
        # and not the keyword list.
        out, hits = blot.Blotter(paranoid=True).blot_line("cipher=" + self.OTHER)
        self.assertTrue(hits, "a 40-hex value at a key site was spared")
        self.assertIn("<ENTROPY", out)

    def test_the_git_sha_exception_is_local_not_whole_line(self):
        line = "commit " + self.SHA + " " + ("filler " * 60) + "k=" + self.OTHER
        out, _ = blot.Blotter(paranoid=True).blot_line(line)
        self.assertIn(self.SHA, out, "the sha beside `commit` must survive")
        self.assertIn("<ENTROPY", out, "a hex value 400 chars from `commit` is not a git sha")


class TestStrict(unittest.TestCase):
    """--verify can only see what has a rule. --strict is the refusal to call that clean, and the
    point of the pair is the difference between their exit codes."""

    UNKNOWN = "MY_VENDOR_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6\n"

    def test_strict_refuses_to_certify_a_shape_no_rule_covers(self):
        rc, out, err = run("--strict", stdin=self.UNKNOWN)
        self.assertEqual(rc, 4, out + err)
        self.assertIn("UNNAMED", err)

    def test_verify_alone_still_passes_where_strict_refuses(self):
        rc, out, err = run("--verify", stdin=self.UNKNOWN)
        self.assertEqual(rc, 0, err)
        self.assertIn("verify OK", err)

    def test_a_learned_rule_turns_the_refusal_into_a_pass(self):
        path = scratch("_rules.json")
        with open(path, "w") as fh:
            json.dump([{"name": "MY_VENDOR_KEY",
                        "regex": r"(?i)(?P<keep>\bmy_vendor_key\s*[:=]\s*)(?P<sec>\S{8,})"}], fh)
        try:
            rc, out, err = run("--strict", "--rules", path, stdin=self.UNKNOWN)
            self.assertEqual(rc, 0, out + err)
            self.assertNotIn("UNNAMED", err)
            self.assertNotIn("a1b2c3d4", out)
        finally:
            os.remove(path)

    def test_a_recognised_leak_outranks_an_unnamed_shape(self):
        rc, out, err = run("--strict", "--keep", "AWS", stdin="aws %s %s" % (AWS, self.UNKNOWN))
        self.assertEqual(rc, 3, out + err)
        self.assertIn("NOT CLEAN", err)


class TestAgentSurface(unittest.TestCase):
    """--rules, --candidates and --json are how an agent drives blot. The property that matters:
    the report describes what survived without ever quoting it, so reading the report is not a
    second leak."""

    STRIPE_VALUE = "sk_" + "live_" + "a" * 24   # assembled, as above: a shape this valid is valid
    LEAKY = ("stripe_key=%s\n" % STRIPE_VALUE
             + "MY_INTERNAL_KEY=zzzQQQQqqqzzzQQQQqqqqzzzz\n"
               "acct=4111 1111 1111 1111\n")
    SECRETS = (STRIPE_VALUE, "zzzQQQQqqqzzzQQQQqqqqzzzz", "4111 1111 1111 1111",
               "4111111111111111")

    def _rules(self, doc):
        path = scratch("_rules.json")
        with open(path, "w") as fh:
            json.dump(doc, fh)
        return path

    def test_a_custom_rule_blots_and_verify_still_passes(self):
        path = self._rules({"rules": [{
            "name": "INTERNAL_KEY", "screen": ["internal"],
            "regex": r"(?i)(?P<keep>\b[\w.\-]*internal[\w.\-]*\s*[:=]\s*)(?P<sec>\S{6,})"}]})
        try:
            rc, out, err = run("--rules", path, "--verify", stdin=self.LEAKY)
            self.assertEqual(rc, 0, out + err)
            self.assertIn("<INTERNAL_KEY:1>", out)
            self.assertNotIn("zzzQQQQ", out)
        finally:
            os.remove(path)

    def test_a_bad_custom_rule_is_refused_rather_than_skipped(self):
        path = self._rules([{"name": "X", "regex": "(?P<nope>a)"}])
        try:
            rc, out, err = run("--rules", path, stdin="x\n")
            self.assertEqual(rc, 2, err)
            self.assertIn("(?P<sec>", err)
        finally:
            os.remove(path)

    def test_a_placeholder_from_a_rule_named_with_an_underscore_survives_later_rules(self):
        rules = [("MY_KEY", re.compile(r"(?i)(?P<keep>my_secret\s*[:=]\s*)(?P<sec>\S{6,})"), ())]
        b = blot.Blotter(rules=rules)
        out, _ = b.blot_line("my_secret=hunter2secretvalue")
        self.assertEqual(out, "my_secret=<MY_KEY:1>")
        self.assertEqual(b.blot_line(out)[0], out, "a placeholder was blotted a second time")

    def test_candidates_describe_survivors_without_quoting_them(self):
        rc, out, err = run("--candidates", "--json", "--out", os.devnull, stdin=self.LEAKY)
        self.assertEqual(rc, 0, err)
        doc = json.loads(out)
        kinds = {c["kind"] for c in doc["candidates"]}
        self.assertIn("named", kinds, "a *_KEY= site nobody recognised went unreported")
        self.assertIn("card", kinds, "a Luhn-valid PAN went unreported")
        blob = json.dumps(doc)
        for secret in self.SECRETS:
            self.assertNotIn(secret, blob, "the report quoted a live secret")

    def test_the_json_report_counts_and_locates_without_leaving_the_map_behind(self):
        rc, out, err = run("--json", "--out", os.devnull, stdin=self.LEAKY)
        self.assertEqual(rc, 0, err)
        doc = json.loads(out)
        self.assertEqual(doc["by_type"], {"STRIPE": 1})
        self.assertEqual(doc["findings"], [{"line": 1, "type": "STRIPE", "label": "<STRIPE:1>"}])
        self.assertNotIn("sk_live", json.dumps(doc))

    def test_every_blot_path_is_locatable_not_merely_counted(self):
        """PEM, seed runs and entropy strays reach label() directly rather than through a rule, so
        they were counted by type and absent from findings — a report that says how many and not
        where. by_type totals and findings length must agree."""
        text = (PEM + "\nwallet: " + SEED + "\ncipher=" + "0a1b2c3d4e5f60718293a4b5c6d7e8f90123a4b5"
                + "\n" + AWS + "\n")
        rc, out, err = run("--json", "--paranoid", "--out", os.devnull, stdin=text)
        self.assertEqual(rc, 0, err)
        doc = json.loads(out)
        found = {f["type"] for f in doc["findings"]}
        for typ in ("PRIVKEY", "SEEDPHRASE", "ENTROPY", "AWS"):
            self.assertIn(typ, found, "%s counted but never located: %s" % (typ, sorted(found)))
        self.assertEqual(sum(doc["by_type"].values()), len(doc["findings"]),
                         "%s vs %s" % (doc["by_type"], len(doc["findings"])))

    def test_a_catastrophic_custom_rule_is_refused_before_it_can_hang(self):
        path = self._rules([{"name": "BOOM", "regex": r"(?P<sec>(?:a+)+b)"}])
        try:
            started = time.monotonic()
            rc, out, err = run("--rules", path, stdin="x\n")
            self.assertEqual(rc, 2, err)
            self.assertIn("probe", err)
            self.assertLess(time.monotonic() - started, 10,
                            "a rule that will hang must be refused early, not eventually")
        finally:
            os.remove(path)

    def test_an_ordinary_rule_still_loads_and_blots(self):
        path = self._rules([{"name": "OK", "regex": r"(?i)(?P<keep>foo\s*[:=]\s*)(?P<sec>\S{8,})"}])
        try:
            rc, out, err = run("--rules", path, stdin="foo=abcdefgh\n")
            self.assertEqual(rc, 0, err)
            self.assertIn("<OK:1>", out)
        finally:
            os.remove(path)

    def test_no_built_in_rule_is_catastrophic(self):
        for name, rx, _screen in blot.RULES:
            self.assertIsNone(blot.probe_rule(name, rx), "built-in %s fails its own probe" % name)

    def test_dump_rules_round_trips_back_through_rules(self):
        path = scratch("_dump.json")
        rc, _o, err = run("--dump-rules", path)
        try:
            self.assertEqual(rc, 0, err)
            with open(path) as fh:
                doc = json.load(fh)
            self.assertTrue(any(r["name"] == "KV" for r in doc["rules"]))
            rc2, out2, err2 = run("--rules", path, stdin=self.LEAKY)
            self.assertEqual(rc2, 0, err2)
            self.assertIn("<STRIPE:1>", out2)
        finally:
            os.remove(path)


class TestCli(unittest.TestCase):
    def test_types_are_listed(self):
        rc, out, err = run("--list-types", "--pii", "--paranoid")
        self.assertEqual(rc, 0)
        self.assertIn("PRIVKEY", out)
        self.assertIn("EMAIL", out)
        self.assertIn("ENTROPY", out)

    def test_map_file_is_written_private_and_warned(self):
        path = scratch("_map.json")
        rc, out, err = run("--map", path, stdin="password=hunter2supersecret\n")
        try:
            self.assertEqual(rc, 0, err)
            self.assertEqual(oct(os.stat(path).st_mode)[-3:], "600")
            self.assertIn("every secret", err)
            with open(path) as fh:
                self.assertIn("hunter2supersecret", fh.read())
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_out_file_matches_stdout(self):
        path = scratch("_out.txt")
        rc1, so, _ = run(stdin="token %s\n" % GH)
        rc2, _o, err = run("--out", path, stdin="token %s\n" % GH)
        try:
            self.assertEqual(rc2, 0, err)
            with open(path) as fh:
                self.assertEqual(fh.read().strip(), so.strip())
        finally:
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    unittest.main()
