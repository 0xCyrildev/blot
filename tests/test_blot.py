"""blot's own tests: every detector, and the four things that would make it dangerous to trust."""
import atexit
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
        big = "".join("line %d token %s\n" % (i, GH) for i in range(20000))
        p = subprocess.Popen([sys.executable, CLI], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        p.stdin.write(big)
        p.stdin.close()
        p.stdout.readline()
        p.stdout.close()  # the consumer went away mid-stream, the way `| head -1` does
        err = p.stderr.read()
        rc = p.wait(timeout=60)
        p.stderr.close()
        self.assertNotIn("Traceback", err)
        self.assertEqual(rc, 0, err)


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
