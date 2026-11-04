"""Fraud Capsule Pipeline: screen reference transactions, commit each decision to the CSL."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from transaction import Transaction, AccountProfile
from fraud_engine import screen
from csl import CSL

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data", "reference_transactions.json")
LEDGER = os.path.join(ROOT, "audit", "csl_ledger.json")
LOGS = os.path.join(ROOT, "logs")


def load(path=DATA):
    raw = json.load(open(path))
    profiles = {}
    for a in raw["accounts"]:
        hist = [Transaction("H", a["account_id"], h["amount_cents"], "CP-H",
                            h["timestamp_s"], "US", "DEV-H") for h in a["history"]]
        profiles[a["account_id"]] = AccountProfile(
            a["account_id"], a["age_days"], a["home_countries"], hist)
    return raw, profiles


def run():
    os.makedirs(LOGS, exist_ok=True)
    csl = CSL(LEDGER)
    raw, profiles = load()
    blocklist = frozenset(raw["blocklist"])
    csl.append({"capsule": "fraud-capsule", "version": "1.0.0",
                "arithmetic": "WAD-18 exact integer", "n_accounts": len(profiles)},
               label="GENESIS")
    results = []
    for t in raw["transactions"]:
        txn = Transaction(t["txn_id"], t["account_id"], t["amount_cents"],
                          t["counterparty_id"], t["timestamp_s"], t["country"], t["device_id"])
        r = screen(txn, profiles[txn.account_id], raw["device_accounts"], blocklist)
        ok = (r["decision"] == t["expected_decision"]
              and r["rules_triggered"] == t["expected_rules"])
        csl.append({"txn_id": r["txn_id"], "decision": r["decision"],
                    "rules": r["rules_triggered"], "score": r["score_str"], "pass": ok},
                   label=t["label"])
        r["pass"] = ok
        results.append(r)
        print("  %s [%s] %-6s score=%s rules=%s" % ("✓" if ok else "✗", t["txn_id"],
              r["decision"], r["score_str"], ",".join(r["rules_triggered"]) or "-"))
    all_pass = all(r["pass"] for r in results)
    csl.append({"all_pass": all_pass, "H_final": csl.root_hash()}, label="FINALIZATION")
    json.dump({"results": results, "all_pass": all_pass},
              open(os.path.join(LOGS, "screenings.json"), "w"), indent=2, sort_keys=True)
    print("\n  All pass: %s | H_final: %s..." % (all_pass, csl.root_hash()[:24]))
    return results


if __name__ == "__main__":
    run()
