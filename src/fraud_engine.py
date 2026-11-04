"""
Fraud screening engine. Deterministic rule set; risk score is an exact WAD-18
sum of fixed rule weights, clamped to [0, 1]. No floats, no learned parameters.

Decision: score >= BLOCK_THRESHOLD -> BLOCK; score >= REVIEW_THRESHOLD -> REVIEW;
otherwise ALLOW. Triggering an additional rule can never lower the score.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wad18 as W
from transaction import Transaction, AccountProfile

ALLOW, REVIEW, BLOCK = "ALLOW", "REVIEW", "BLOCK"
DECISIONS = frozenset([ALLOW, REVIEW, BLOCK])

VELOCITY_WINDOW_S = 3600
VELOCITY_MAX = 5
OUTLIER_MULT = 5
MIN_HISTORY_FOR_OUTLIER = 3
NEW_ACCOUNT_DAYS = 30
NEW_ACCOUNT_AMOUNT_CENTS = 500000
STRUCT_LOW_CENTS = 900000
STRUCT_HIGH_CENTS = 1000000
DEVICE_ACCOUNT_MAX = 3

RULE_WEIGHTS = {
    "VELOCITY":    W.from_str("0.25"),
    "OUTLIER":     W.from_str("0.25"),
    "GEO":         W.from_str("0.20"),
    "NEW_ACCOUNT": W.from_str("0.15"),
    "STRUCTURING": W.from_str("0.30"),
    "BLOCKLIST":   W.from_str("1.00"),
    "DEVICE":      W.from_str("0.20"),
}
REVIEW_THRESHOLD = W.from_str("0.30")
BLOCK_THRESHOLD = W.from_str("0.70")


def rule_velocity(txn, profile):
    n = 0
    for h in profile.history:
        d = txn.timestamp_s - h.timestamp_s
        if 0 <= d < VELOCITY_WINDOW_S:
            n += 1
    return n + 1 > VELOCITY_MAX


def rule_outlier(txn, profile):
    n = len(profile.history)
    if n < MIN_HISTORY_FOR_OUTLIER:
        return False
    total = sum(h.amount_cents for h in profile.history)
    return txn.amount_cents * n > OUTLIER_MULT * total


def rule_geo(txn, profile):
    return txn.country not in profile.home_countries


def rule_new_account(txn, profile):
    return (profile.age_days < NEW_ACCOUNT_DAYS
            and txn.amount_cents >= NEW_ACCOUNT_AMOUNT_CENTS)


def rule_structuring(txn, profile):
    return STRUCT_LOW_CENTS <= txn.amount_cents < STRUCT_HIGH_CENTS


def rule_blocklist(txn, blocklist):
    return txn.counterparty_id in blocklist


def rule_device(txn, device_accounts):
    accounts = set(device_accounts.get(txn.device_id, ()))
    accounts.add(txn.account_id)
    return len(accounts) > DEVICE_ACCOUNT_MAX


def outlier_ratio(txn, profile):
    n = len(profile.history)
    total = sum(h.amount_cents for h in profile.history)
    if n < MIN_HISTORY_FOR_OUTLIER or total == 0:
        return W.ZERO
    return W.div(W.from_cents(txn.amount_cents * n), W.from_cents(total))


def screen(txn, profile, device_accounts=None, blocklist=frozenset()):
    device_accounts = device_accounts or {}
    fired = []
    if rule_velocity(txn, profile):              fired.append("VELOCITY")
    if rule_outlier(txn, profile):               fired.append("OUTLIER")
    if rule_geo(txn, profile):                   fired.append("GEO")
    if rule_new_account(txn, profile):           fired.append("NEW_ACCOUNT")
    if rule_structuring(txn, profile):           fired.append("STRUCTURING")
    if rule_blocklist(txn, blocklist):           fired.append("BLOCKLIST")
    if rule_device(txn, device_accounts):        fired.append("DEVICE")

    score = W.ZERO
    for name in fired:
        score += RULE_WEIGHTS[name]
    score = W.clamp(score, W.ZERO, W.ONE)

    if score >= BLOCK_THRESHOLD:
        decision = BLOCK
    elif score >= REVIEW_THRESHOLD:
        decision = REVIEW
    else:
        decision = ALLOW

    return {
        "txn_id": txn.txn_id,
        "account_id": txn.account_id,
        "rules_triggered": sorted(fired),
        "score_wad18": score,
        "score_str": W.to_str(score, 6),
        "outlier_ratio_wad18": outlier_ratio(txn, profile),
        "decision": decision,
        "arithmetic": "WAD-18 exact integer throughout",
    }
