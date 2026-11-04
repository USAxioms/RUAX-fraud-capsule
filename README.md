# Fraud Capsule v1.0

Deterministic transaction pre-screen. Seven rules, fixed WAD-18 weights, exact integer comparisons, SHA-256 CSL audit chain. It is a rule engine, not a learned model: it will not catch fraud its rules do not describe.

## Rules and weights
VELOCITY 0.25 (>5 txns incl. this one in 3600s) · OUTLIER 0.25 (amount > 5x account mean, history >= 3, tested as `amount*n > 5*total`, no division) · GEO 0.20 · NEW_ACCOUNT 0.15 (age < 30d and >= $5,000) · STRUCTURING 0.30 ($9,000.00 to $9,999.99) · BLOCKLIST 1.00 · DEVICE 0.20 (> 3 accounts on one device).

Score = clamp(sum of fired weights, 0, 1). `>= 0.70` BLOCK, `>= 0.30` REVIEW, else ALLOW. Adding a fired rule never lowers the decision.

## Use
```python
from fraud_engine import screen
r = screen(txn, profile, device_accounts, blocklist)  # r["decision"], r["rules_triggered"], r["score_wad18"]
```
Run: `PYTHONHASHSEED=0 python3 src/pipeline.py` · Tests: `python3 -m unittest discover -s tests` (55) · Mutation: `python3 src/mutation.py` (66 mutants: 63 killed, 3 equivalent, 0 unexplained; scope = transaction.py and fraud_engine.py only).

## Limits
Thresholds and weights are illustrative, not calibrated on real fraud data. No external benchmark. Rules are static and gameable by anyone who knows them. `wad18.py`/`csl.py` are shared and not mutated here. CVI is self-assessed; AXM requires external ratification.
