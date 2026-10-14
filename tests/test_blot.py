"""blot's own tests: every detector, and the four things that would make it dangerous to trust."""
import io
import re
import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import blot  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(os.path.dirname(HERE), "blot.py")

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


class TestInputAndErrors(unittest.TestCase):
    """The failure modes that make a redactor unsafe to trust: silently doing nothing."""

    def test_stdin_is_read_when_no_file_is_named(self):
        rc, out, err = run(stdin="token %s\n" % GH)
        self.assertEqual(rc, 0, err)
        self.assertIn("<GHTOKEN:1>", out)

    def test_dash_reads_stdin_even_next_to_a_file(self):
        path = os.path.join(HERE, "_in.txt")
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


class TestEntropyGate(unittest.TestCase):
    SHA = "4f9a3cbe0a1d2b3c4d5e6f708192a3b4c5d6e7f8"
    OTHER = "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567"

    def test_a_hex_key_is_blotted_once_the_measure_is_in_bits(self):
        # ln(16)=2.77 nats: under a nats threshold no hex secret could ever reach 3.0, so --paranoid
        # silently spared every 40-hex key.
        out, hits = blot.Blotter(paranoid=True).blot_line("encryption_key=" + self.OTHER)
        self.assertTrue(hits, "a 40-hex value at a key site was spared")
        self.assertIn("<ENTROPY", out)

    def test_the_git_sha_exception_is_local_not_whole_line(self):
        line = "commit " + self.SHA + " " + ("filler " * 60) + "k=" + self.OTHER
        out, _ = blot.Blotter(paranoid=True).blot_line(line)
        self.assertIn(self.SHA, out, "the sha beside `commit` must survive")
        self.assertIn("<ENTROPY", out, "a hex value 400 chars from `commit` is not a git sha")


class TestCli(unittest.TestCase):
    def test_types_are_listed(self):
        rc, out, err = run("--list-types", "--pii", "--paranoid")
        self.assertEqual(rc, 0)
        self.assertIn("PRIVKEY", out)
        self.assertIn("EMAIL", out)
        self.assertIn("ENTROPY", out)

    def test_map_file_is_written_private_and_warned(self):
        path = os.path.join(HERE, "_map.json")
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
        path = os.path.join(HERE, "_out.txt")
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
