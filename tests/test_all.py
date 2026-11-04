import sys, os, json, tempfile, itertools, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import wad18 as W
from transaction import Transaction, AccountProfile, CHANNELS
import fraud_engine as F
from fraud_engine import screen, ALLOW, REVIEW, BLOCK, DECISIONS
from csl import CSL, IntegrityError
import pipeline

BASE = 1730000000

def T(amount=10000, ts=BASE, country="US", cp="CP", dev="D", acct="A", tid="T", ch="ONLINE"):
    return Transaction(tid, acct, amount, cp, ts, country, dev, ch)

def P(age=400, home=("US",), hist=()):
    return AccountProfile("A", age, home, list(hist))

def H(amount, ts): return T(amount=amount, ts=ts)

def rules(txn, prof, dev=None, bl=frozenset()):
    return screen(txn, prof, dev, bl)["rules_triggered"]


class TestTransaction(unittest.TestCase):
    def test_valid(self):
        t = T(); self.assertEqual(t.amount_cents, 10000)
    def test_zero_amount_rejected(self):
        with self.assertRaises(ValueError): T(amount=0)
    def test_one_cent_ok(self): self.assertEqual(T(amount=1).amount_cents, 1)
    def test_negative_amount_rejected(self):
        with self.assertRaises(ValueError): T(amount=-5)
    def test_float_amount_rejected(self):
        with self.assertRaises(ValueError): T(amount=1.5)
    def test_bool_amount_rejected(self):
        with self.assertRaises(ValueError): T(amount=True)
    def test_negative_timestamp_rejected(self):
        with self.assertRaises(ValueError): T(ts=-1)
    def test_zero_timestamp_ok(self): self.assertEqual(T(ts=0).timestamp_s, 0)
    def test_float_timestamp_rejected(self):
        with self.assertRaises(ValueError): T(ts=1.0)
    def test_bool_timestamp_rejected(self):
        with self.assertRaises(ValueError): T(ts=True)
    def test_bad_channel_rejected(self):
        with self.assertRaises(ValueError): T(ch="FAX")
    def test_all_channels_ok(self):
        for c in CHANNELS: self.assertEqual(T(ch=c).channel, c)
    def test_country_must_be_two_upper(self):
        for bad in ("usa", "us", "U", "U1", 5):
            with self.assertRaises(ValueError): T(country=bad)
    def test_country_ok(self): self.assertEqual(T(country="GB").country, "GB")
    def test_profile_age_validation(self):
        for bad in (-1, 1.5, True):
            with self.assertRaises(ValueError): AccountProfile("A", bad, ["US"])
        self.assertEqual(AccountProfile("A", 0, ["US"]).age_days, 0)
    def test_profile_history_copied(self):
        h = [H(1, BASE)]
        p = AccountProfile("A", 5, ["US"], h); h.append(H(2, BASE))
        self.assertEqual(len(p.history), 1)
    def test_profile_defaults_empty_history(self):
        self.assertEqual(AccountProfile("A", 5, ["US"]).history, [])


class TestVelocity(unittest.TestCase):
    def hist(self, n, dt=10): return [H(1000, BASE - dt * (i + 1)) for i in range(n)]
    def test_four_prior_not_flagged(self):
        self.assertNotIn("VELOCITY", rules(T(), P(hist=self.hist(4))))
    def test_five_prior_flagged(self):
        self.assertIn("VELOCITY", rules(T(), P(hist=self.hist(5))))
    def test_window_inner_edge_counts(self):
        h = [H(1000, BASE - 3599)] * 5
        self.assertIn("VELOCITY", rules(T(), P(hist=h)))
    def test_window_outer_edge_excluded(self):
        h = [H(1000, BASE - 3600)] * 5
        self.assertNotIn("VELOCITY", rules(T(), P(hist=h)))
    def test_same_timestamp_counts(self):
        h = [H(1000, BASE)] * 5
        self.assertIn("VELOCITY", rules(T(), P(hist=h)))
    def test_future_history_excluded(self):
        h = [H(1000, BASE + 1)] * 5
        self.assertNotIn("VELOCITY", rules(T(), P(hist=h)))


class TestOutlier(unittest.TestCase):
    def hist(self, n=4, amt=10000): return [H(amt, BASE - 86400 * (i + 1)) for i in range(n)]
    def test_exact_5x_not_flagged(self):
        self.assertNotIn("OUTLIER", rules(T(amount=50000), P(hist=self.hist())))
    def test_one_cent_over_flagged(self):
        self.assertIn("OUTLIER", rules(T(amount=50001), P(hist=self.hist())))
    def test_needs_three_history(self):
        self.assertNotIn("OUTLIER", rules(T(amount=900000), P(hist=self.hist(2))))
        self.assertIn("OUTLIER", rules(T(amount=900000), P(hist=self.hist(3))))
    def test_mean_not_total(self):
        # 3 history txns of 10000; mean 10000; 5x = 50000
        self.assertNotIn("OUTLIER", rules(T(amount=50000), P(hist=self.hist(3))))
        self.assertIn("OUTLIER", rules(T(amount=50001), P(hist=self.hist(3))))
    def test_ratio_exact_wad18(self):
        r = screen(T(amount=25000), P(hist=self.hist()))
        self.assertEqual(r["outlier_ratio_wad18"], W.from_str("2.5"))
    def test_ratio_zero_when_thin(self):
        r = screen(T(amount=25000), P(hist=self.hist(2)))
        self.assertEqual(r["outlier_ratio_wad18"], W.ZERO)
    def test_ratio_formula_nonuniform(self):
        h = [H(10000, BASE-1), H(20000, BASE-2), H(30000, BASE-3)]  # mean 20000
        r = screen(T(amount=30000), P(hist=h))
        self.assertEqual(r["outlier_ratio_wad18"], W.from_str("1.5"))


class TestOtherRules(unittest.TestCase):
    def test_geo(self):
        self.assertNotIn("GEO", rules(T(country="US"), P()))
        self.assertIn("GEO", rules(T(country="FR"), P()))
        self.assertNotIn("GEO", rules(T(country="FR"), P(home=("US", "FR"))))
    def test_new_account_age_boundary(self):
        self.assertIn("NEW_ACCOUNT", rules(T(amount=500000), P(age=29)))
        self.assertNotIn("NEW_ACCOUNT", rules(T(amount=500000), P(age=30)))
    def test_new_account_amount_boundary(self):
        self.assertNotIn("NEW_ACCOUNT", rules(T(amount=499999), P(age=1)))
        self.assertIn("NEW_ACCOUNT", rules(T(amount=500000), P(age=1)))
    def test_structuring_boundaries(self):
        for amt, exp in ((899999, False), (900000, True), (999999, True), (1000000, False)):
            self.assertEqual("STRUCTURING" in rules(T(amount=amt), P()), exp, amt)
    def test_blocklist(self):
        self.assertIn("BLOCKLIST", rules(T(cp="X"), P(), bl=frozenset(["X"])))
        self.assertNotIn("BLOCKLIST", rules(T(cp="Y"), P(), bl=frozenset(["X"])))
    def test_device_boundary(self):
        d3 = {"D": ["B", "C"]}          # + A = 3 accounts
        d4 = {"D": ["B", "C", "E"]}     # + A = 4 accounts
        self.assertNotIn("DEVICE", rules(T(), P(), dev=d3))
        self.assertIn("DEVICE", rules(T(), P(), dev=d4))
    def test_device_own_account_not_double_counted(self):
        d = {"D": ["A", "B", "C"]}      # A already present -> 3 accounts
        self.assertNotIn("DEVICE", rules(T(), P(), dev=d))
    def test_device_unknown_device(self):
        self.assertNotIn("DEVICE", rules(T(dev="ZZ"), P(), dev={"D": ["B","C","E","F"]}))


class TestScoreAndDecision(unittest.TestCase):
    def test_weights_exact(self):
        exp = {"VELOCITY":"0.25","OUTLIER":"0.25","GEO":"0.20","NEW_ACCOUNT":"0.15",
               "STRUCTURING":"0.30","BLOCKLIST":"1.00","DEVICE":"0.20"}
        for k, v in exp.items(): self.assertEqual(F.RULE_WEIGHTS[k], W.from_str(v))
        self.assertEqual(F.REVIEW_THRESHOLD, W.from_str("0.30"))
        self.assertEqual(F.BLOCK_THRESHOLD, W.from_str("0.70"))
    def test_constants(self):
        self.assertEqual(F.VELOCITY_WINDOW_S, 3600); self.assertEqual(F.VELOCITY_MAX, 5)
        self.assertEqual(F.OUTLIER_MULT, 5); self.assertEqual(F.MIN_HISTORY_FOR_OUTLIER, 3)
        self.assertEqual(F.NEW_ACCOUNT_DAYS, 30); self.assertEqual(F.NEW_ACCOUNT_AMOUNT_CENTS, 500000)
        self.assertEqual(F.STRUCT_LOW_CENTS, 900000); self.assertEqual(F.STRUCT_HIGH_CENTS, 1000000)
        self.assertEqual(F.DEVICE_ACCOUNT_MAX, 3)
    def test_no_rules_allow_zero(self):
        r = screen(T(), P())
        self.assertEqual((r["decision"], r["score_wad18"], r["score_str"]), (ALLOW, 0, "0.000000"))
    def test_review_threshold_inclusive(self):
        r = screen(T(amount=950000), P(age=400))     # structuring alone = 0.30
        self.assertEqual(r["rules_triggered"], ["STRUCTURING"])
        self.assertEqual(r["decision"], REVIEW)
    def test_just_below_review_allows(self):
        r = screen(T(country="FR"), P())             # geo alone = 0.20
        self.assertEqual(r["decision"], ALLOW)
    def test_block_threshold_inclusive(self):
        h = [H(10000, BASE - 86400 * (i+1)) for i in range(4)]
        r = screen(T(amount=950000), P(age=10, hist=h))   # 0.30+0.25+0.15 = 0.70
        self.assertEqual(r["rules_triggered"], ["NEW_ACCOUNT", "OUTLIER", "STRUCTURING"])
        self.assertEqual(r["score_wad18"], W.from_str("0.70"))
        self.assertEqual(r["decision"], BLOCK)
    def test_just_below_block_reviews(self):
        r = screen(T(amount=950000, country="FR"), P(age=10))  # 0.30+0.15+0.20 = 0.65
        self.assertEqual(r["score_wad18"], W.from_str("0.65"))
        self.assertEqual(r["decision"], REVIEW)
    def test_blocklist_alone_blocks(self):
        self.assertEqual(screen(T(cp="X"), P(), None, frozenset(["X"]))["decision"], BLOCK)
    def test_score_clamped_to_one(self):
        h = [H(100, BASE - i) for i in range(5)]
        t = T(amount=950000, country="FR", cp="X")
        r = screen(t, P(age=1, hist=h), {"D": ["B","C","E"]}, frozenset(["X"]))
        self.assertEqual(len(r["rules_triggered"]), 7)
        self.assertEqual(r["score_wad18"], W.ONE)
        self.assertEqual(r["score_str"], "1.000000")
    def test_score_str_six_places(self):
        r = screen(T(country="FR"), P())
        self.assertEqual(r["score_str"], "0.200000")
    def test_rules_sorted(self):
        r = screen(T(amount=950000, country="FR"), P())
        self.assertEqual(r["rules_triggered"], sorted(r["rules_triggered"]))
    def test_decision_in_set_and_fields(self):
        r = screen(T(), P())
        self.assertIn(r["decision"], DECISIONS)
        self.assertEqual(r["txn_id"], "T"); self.assertEqual(r["account_id"], "A")
        self.assertEqual(r["arithmetic"], "WAD-18 exact integer throughout")
        self.assertIsInstance(r["score_wad18"], int)

    def test_monotone_over_all_rule_subsets(self):
        names = sorted(F.RULE_WEIGHTS)
        def score(sub):
            s = sum((F.RULE_WEIGHTS[n] for n in sub), W.ZERO)
            return W.clamp(s, W.ZERO, W.ONE)
        rank = {ALLOW: 0, REVIEW: 1, BLOCK: 2}
        def dec(s):
            return BLOCK if s >= F.BLOCK_THRESHOLD else REVIEW if s >= F.REVIEW_THRESHOLD else ALLOW
        for k in range(len(names) + 1):
            for sub in itertools.combinations(names, k):
                for extra in names:
                    if extra in sub: continue
                    self.assertGreaterEqual(rank[dec(score(sub + (extra,)))], rank[dec(score(sub))])

    def test_screen_pure_and_reproducible(self):
        h = [H(1000, BASE - i) for i in range(5)]
        p = P(hist=h); d = {"D": ["B"]}
        before = (len(p.history), dict((k, list(v)) for k, v in d.items()))
        r1 = screen(T(), p, d); r2 = screen(T(), p, d)
        self.assertEqual(r1, r2)
        self.assertEqual(before, (len(p.history), d))

    def test_device_map_not_mutated(self):
        d = {"D": ["B"]}; screen(T(), P(), d)
        self.assertEqual(d, {"D": ["B"]})


class TestPipelineAndAudit(unittest.TestCase):
    def test_reference_cases(self):
        raw, profiles = pipeline.load()
        for t in raw["transactions"]:
            txn = Transaction(t["txn_id"], t["account_id"], t["amount_cents"], t["counterparty_id"],
                              t["timestamp_s"], t["country"], t["device_id"])
            r = screen(txn, profiles[txn.account_id], raw["device_accounts"], frozenset(raw["blocklist"]))
            self.assertEqual(r["decision"], t["expected_decision"], t["label"])
            self.assertEqual(r["rules_triggered"], t["expected_rules"], t["label"])
    def test_csl_chain_and_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "l.json")
            c = CSL(path); c.append({"decision": "ALLOW"}); c.append({"decision": "BLOCK"})
            self.assertTrue(c.verify())
            blocks = json.load(open(path)); blocks[0]["S_i"]["decision"] = "BLOCK"
            json.dump(blocks, open(path, "w"))
            with self.assertRaises(IntegrityError): CSL(path)

if __name__ == "__main__":
    unittest.main()
