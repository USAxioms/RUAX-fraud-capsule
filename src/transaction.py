"""Transaction model. Amounts are integer cents; timestamps are integer epoch seconds."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CHANNELS = frozenset(["ONLINE", "POS", "ATM", "WIRE"])


def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


class Transaction:
    def __init__(self, txn_id, account_id, amount_cents, counterparty_id,
                 timestamp_s, country, device_id, channel="ONLINE"):
        if not _is_int(amount_cents) or amount_cents <= 0:
            raise ValueError("amount_cents must be a positive int: %r" % (amount_cents,))
        if not _is_int(timestamp_s) or timestamp_s < 0:
            raise ValueError("timestamp_s must be a non-negative int: %r" % (timestamp_s,))
        if channel not in CHANNELS:
            raise ValueError("unknown channel: %r" % (channel,))
        if not (isinstance(country, str) and len(country) == 2 and country.isalpha() and country.isupper()):
            raise ValueError("country must be 2 uppercase letters: %r" % (country,))
        self.txn_id = str(txn_id)
        self.account_id = str(account_id)
        self.amount_cents = amount_cents
        self.counterparty_id = str(counterparty_id)
        self.timestamp_s = timestamp_s
        self.country = country
        self.device_id = str(device_id)
        self.channel = channel


class AccountProfile:
    def __init__(self, account_id, age_days, home_countries, history=None):
        if not _is_int(age_days) or age_days < 0:
            raise ValueError("age_days must be a non-negative int")
        self.account_id = str(account_id)
        self.age_days = age_days
        self.home_countries = frozenset(home_countries)
        self.history = list(history or [])
