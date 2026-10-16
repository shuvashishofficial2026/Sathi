"""Scam shield: deterministic checks on a payment request someone sent the user.

The score comes from code, not from the AI, so a cleverly worded message can't
talk its way to a low score. The biggest signal is an account number that
doesn't match the verified account of the institution the message names.
"""

from __future__ import annotations

import re

from .audit import mask_account
from .payees import Payees, digits

# (id, pattern, weight, why it matters)
RED_FLAGS: list[tuple[str, str, int, str]] = [
    ("discount_offer", r"\b(discount|\d{1,2}\s?% off|cash ?back|special (rate|offer))\b|ছাড়|ডিসকাউন্ট", 25,
     "Offers a discount for paying through a third party. Universities don't sell tuition discounts via agents."),
    ("urgency", r"\b(urgent(ly)?|immediately|today only|within \d+ hours?|last chance|act now|expires? today)\b"
                r"|জরুরি|আজকেই", 15,
     "Pressure to pay fast, so you don't stop to check."),
    ("personal_account", r"\b(personal account|my (own )?account|agent'?s? account|individual account|"
                         r"private account)\b", 25,
     "Asks you to pay a personal account instead of the institution."),
    ("changed_details", r"\b(new (bank )?account|(bank|account|payment) details (have )?(been )?(changed|updated)|"
                        r"changed (our|the|its) (bank|account)|updated (bank|account) details|"
                        r"account has (been )?changed)\b|নতুন অ্যাকাউন্ট|অ্যাকাউন্ট (পরিবর্তন|বদল)", 30,
     "Claims the bank details changed: the classic invoice-fraud pattern."),
    ("off_channel", r"\b(whats ?app|telegram|imo|signal|dm me|message me)\b", 10,
     "Moves the conversation to a private messaging app."),
    ("unusual_method", r"\b(gift ?cards?|crypto|bitcoin|usdt|binance)\b", 25,
     "Asks for an unusual payment method."),
    ("secrecy", r"\b(don'?t tell|keep (this|it) (confidential|secret|private)|do not contact|don'?t contact)\b", 25,
     "Asks you to keep it secret or not to contact the university."),
    ("credentials", r"\b(otp|password|passcode|cvv|verification code|pin)\b|পিন|ওটিপি|পাসওয়ার্ড", 30,
     "Asks for a code or password. Never share these."),
]

ACCOUNT_RE = re.compile(r"(?<!\d)(?:\d[ -]?){8,30}\d(?!\d)")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")


class ScamShield:
    def __init__(self, payees: Payees):
        self.payees = payees

    def analyze(self, text: str) -> dict:
        text = text or ""
        flags, score = [], 0
        for flag_id, pattern, weight, why in RED_FLAGS:
            if re.search(pattern, text, re.IGNORECASE):
                flags.append({"id": flag_id, "weight": weight, "why": why})
                score += weight

        accounts = {digits(m) for m in ACCOUNT_RE.findall(text)} | {m for m in IBAN_RE.findall(text)}
        accounts = {a for a in accounts if len(a) >= 9}
        institutions = self.payees.registry_mentions(text)
        checks = []
        for inst in institutions:
            official = digits(inst["account_number"])
            if not accounts:
                checks.append({"institution": inst["name"], "result": "no_account_in_message"})
            elif official in accounts and len(accounts) == 1:
                checks.append({"institution": inst["name"], "result": "matches_verified_account"})
                score -= 20
            else:
                checks.append({"institution": inst["name"], "result": "does_not_match_verified_account",
                               "verified_account_ends": official[-4:]})
                flags.append({"id": "account_mismatch", "weight": 45,
                              "why": f"The account in this message doesn't match {inst['name']}'s verified "
                                     f"account (ends {official[-4:]})."})
                score += 45

        score = max(0, min(100, score))
        level = "high" if score >= 60 else "medium" if score >= 30 else "low"
        if level == "high":
            advice = ("Don't pay. Contact the institution through the official website or office, not the "
                      "contact details in this message.")
        elif level == "medium":
            advice = "Be careful. Check the details with the institution through its official channel first."
        else:
            advice = "No strong warning signs, but only pay accounts that Sathi shows as verified."
        return {
            "risk_score": score,
            "risk_level": level,
            "flags": flags,
            "accounts_found": [mask_account(a) for a in sorted(accounts)],
            "institutions_mentioned": [i["name"] for i in institutions],
            "registry_checks": checks,
            "advice": advice,
        }
