"""
taxonomy.py - the one shared vocabulary of address categories (platform types, risk flags, other).

Every tool uses the same words, so a label written by one tool is understood by all the others.
PLATFORM categories mean "a service or protocol, not an individual" (clusters containing them are never
attributed to a person). RISK categories are warnings, not identities. The names are in English for the
data files; Arabic names are for display.
"""
PLATFORM = {"exchange": "بورصة", "custodian": "خدمة حفظ", "bridge": "جسر بين الشبكات", "service": "خدمة",
            "gambling": "مقامرة", "mining-pool": "مجمّع تعدين", "payment-processor": "معالج دفع", "defi": "بروتوكول لامركزي"}
RISK = {"sanctioned": "عقوبات", "scam": "احتيال", "theft": "سرقة", "mixer": "خلط", "darknet": "شبكة مظلمة", "ransomware": "فدية"}
OTHER = {"contract": "عقد ذكي", "suspicious-site": "مرتبط بموقع مشبوه", "reported": "بُلّغ عنه علنًا", "other": "أخرى"}
ALL = {**PLATFORM, **RISK, **OTHER}
ALIASES = {"custodial": "custodian", "cex": "exchange", "bridging": "bridge", "miner": "mining-pool", "mining": "mining-pool",
           "dex": "defi", "processor": "payment-processor", "payment": "payment-processor", "unknown": "other", "coinjoin": "mixer"}


def canon(category):
    c = (category or "").strip().lower()
    return ALIASES.get(c, c) or None


def ar(category):
    return ALL.get(canon(category), category or "غير محدد")


def is_platform(category):
    return canon(category) in PLATFORM


def is_risk(category):
    return canon(category) in RISK
