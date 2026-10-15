"""
chains.py - the one place that knows which networks the tools support. Python 3.8+.

Families:  utxo (Bitcoin-like: btc, ltc, doge, bch) | evm (eth, bsc, polygon, arbitrum, base) | tron | sol.
Every tool asks this module instead of hard-coding "btc"/"eth"/"tron".

HONESTY: only btc, eth and tron were designed against provider documentation I could check. The other networks use provider
addresses and token contracts written from memory ("tested": False). Run `python live_check.py` (or record it with --record)
to see which of them really answer; the site marks them "تجريبية / experimental".
"""
import re

CHAINS = {
    "btc": dict(fam="utxo", name_en="Bitcoin", name_ar="بيتكوين", native="BTC", tested=True,
                api="https://blockstream.info/api", addr_url="https://blockstream.info/address/%s", tx_url="https://blockstream.info/tx/%s",
                addr_re=r"^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{11,87})$", lower_prefix="bc1"),
    "ltc": dict(fam="utxo", name_en="Litecoin", name_ar="لايتكوين", native="LTC", tested=False,
                api="https://litecoinspace.org/api", addr_url="https://litecoinspace.org/address/%s", tx_url="https://litecoinspace.org/tx/%s",
                addr_re=r"^(?:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-z0-9]{11,87})$", lower_prefix="ltc1"),
    "doge": dict(fam="utxo", name_en="Dogecoin", name_ar="دوجكوين", native="DOGE", tested=False, shim="blockchair", shim_name="dogecoin",
                 addr_url="https://blockchair.com/dogecoin/address/%s", tx_url="https://blockchair.com/dogecoin/transaction/%s",
                 addr_re=r"^[DA9][a-km-zA-HJ-NP-Z1-9]{25,34}$"),
    "bch": dict(fam="utxo", name_en="Bitcoin Cash", name_ar="بيتكوين كاش", native="BCH", tested=False, shim="blockchair", shim_name="bitcoin-cash",
                addr_url="https://blockchair.com/bitcoin-cash/address/%s", tx_url="https://blockchair.com/bitcoin-cash/transaction/%s",
                addr_re=r"^(?:(?:bitcoincash:)?[qp][a-z0-9]{41}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$"),
    "eth": dict(fam="evm", name_en="Ethereum", name_ar="إيثريوم", native="ETH", tested=True, chain_id=1,
                providers=[("blockscout", "https://eth.blockscout.com/api/v2")], rpc="https://ethereum-rpc.publicnode.com",
                addr_url="https://etherscan.io/address/%s", tx_url="https://etherscan.io/tx/%s",
                stables={"0xdac17f958d2ee523a2206206994597c13d831ec7": ("USDT", 6), "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USDC", 6),
                         "0x6b175474e89094c44da98b954eedeac495271d0f": ("DAI", 18)}),
    "bsc": dict(fam="evm", name_en="BNB Chain", name_ar="بي إن بي (BNB Chain)", native="BNB", tested=False, chain_id=56,
                providers=[("blockscout", "https://bsc.blockscout.com/api/v2"), ("etherscan2", "https://api.etherscan.io/v2/api")],
                rpc="https://bsc-rpc.publicnode.com", addr_url="https://bscscan.com/address/%s", tx_url="https://bscscan.com/tx/%s",
                stables={"0x55d398326f99059ff775485246999027b3197955": ("USDT", 18), "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": ("USDC", 18)}),
    "polygon": dict(fam="evm", name_en="Polygon", name_ar="بوليغون", native="POL", tested=False, chain_id=137,
                    providers=[("blockscout", "https://polygon.blockscout.com/api/v2"), ("etherscan2", "https://api.etherscan.io/v2/api")],
                    rpc="https://polygon-bor-rpc.publicnode.com", addr_url="https://polygonscan.com/address/%s", tx_url="https://polygonscan.com/tx/%s",
                    stables={"0xc2132d05d31c914a87c6611c10748aeb04b58e8f": ("USDT", 6), "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359": ("USDC", 6),
                             "0x2791bca1f2de4661ed88a30c99a7a9449aa84174": ("USDC", 6)}),
    "arbitrum": dict(fam="evm", name_en="Arbitrum", name_ar="أربيتروم", native="ETH", tested=False, chain_id=42161,
                     providers=[("blockscout", "https://arbitrum.blockscout.com/api/v2"), ("etherscan2", "https://api.etherscan.io/v2/api")],
                     rpc="https://arbitrum-one-rpc.publicnode.com", addr_url="https://arbiscan.io/address/%s", tx_url="https://arbiscan.io/tx/%s",
                     stables={"0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": ("USDT", 6), "0xaf88d065e77c8cc2239327c5edb3a432268e5831": ("USDC", 6),
                              "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8": ("USDC", 6)}),
    "base": dict(fam="evm", name_en="Base", name_ar="بيس (Base)", native="ETH", tested=False, chain_id=8453,
                 providers=[("blockscout", "https://base.blockscout.com/api/v2"), ("etherscan2", "https://api.etherscan.io/v2/api")],
                 rpc="https://base-rpc.publicnode.com", addr_url="https://basescan.org/address/%s", tx_url="https://basescan.org/tx/%s",
                 stables={"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": ("USDC", 6), "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2": ("USDT", 6)}),
    "tron": dict(fam="tron", name_en="TRON", name_ar="ترون (TRON)", native="TRX", tested=True, node="https://api.trongrid.io",
                 addr_url="https://tronscan.org/#/address/%s", tx_url="https://tronscan.org/#/transaction/%s",
                 addr_re=r"^T[1-9A-HJ-NP-Za-km-z]{33}$", stables={"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": ("USDT", 6)}),
    "sol": dict(fam="sol", name_en="Solana", name_ar="سولانا (Solana)", native="SOL", tested=False,
                rpc="https://solana-rpc.publicnode.com", rpc_fallback="https://api.mainnet-beta.solana.com",
                addr_url="https://solscan.io/account/%s", tx_url="https://solscan.io/tx/%s",
                addr_re=r"^[1-9A-HJ-NP-Za-km-z]{32,44}$",
                stables={"Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": ("USDT", 6), "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": ("USDC", 6)}),
}
EVM_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
ORDER = ["btc", "eth", "tron", "bsc", "polygon", "arbitrum", "base", "sol", "ltc", "doge", "bch"]
DEFAULT_MIN_NATIVE = {"BTC": 0.001, "LTC": 0.01, "DOGE": 10, "BCH": 0.001, "ETH": 0.01, "BNB": 0.01, "POL": 10, "TRX": 100, "SOL": 0.1}


def get(chain):
    if chain not in CHAINS:
        raise ValueError("شبكة غير معروفة: %s" % chain)
    return CHAINS[chain]


def fam(chain):
    return get(chain)["fam"]


def is_utxo(chain):
    return chain in CHAINS and CHAINS[chain]["fam"] == "utxo"


def is_evm(chain):
    return chain in CHAINS and CHAINS[chain]["fam"] == "evm"


def is_account(chain):
    """Networks traced by transfers between accounts (not by outputs)."""
    return chain in CHAINS and CHAINS[chain]["fam"] in ("evm", "tron", "sol")


def native(chain):
    return get(chain)["native"]


def tested(chain):
    return bool(get(chain).get("tested"))


def stables(chain):
    """{contract/mint: symbol}"""
    return {k: v[0] for k, v in (get(chain).get("stables") or {}).items()}


def stable_decimals(chain, contract, default=6):
    v = (get(chain).get("stables") or {}).get(contract if fam(chain) != "evm" else (contract or "").lower())
    return v[1] if v else default


def explorer_addr(chain, a):
    return get(chain)["addr_url"] % a


def explorer_tx(chain, t):
    return get(chain)["tx_url"] % t


def normalize(chain, addr):
    """Canonical form or ValueError. EVM -> lowercase, bech32 -> lowercase, others unchanged."""
    c, addr = get(chain), (addr or "").strip()
    if c["fam"] == "evm":
        if not EVM_RE.match(addr):
            raise ValueError("العنوان لا يطابق شبكة %s (يبدأ بـ 0x ويتكوّن من 40 خانة)." % c["name_ar"])
        return addr.lower()
    if c.get("lower_prefix") and addr.lower().startswith(c["lower_prefix"]):
        addr = addr.lower()
    if c["fam"] == "utxo" and chain == "bch" and addr.lower().startswith("bitcoincash:"):
        addr = addr.split(":", 1)[1]
    if not re.match(c["addr_re"], addr):
        raise ValueError("العنوان غير صالح لشبكة %s." % c["name_ar"])
    return addr


def choices():
    return [{"id": k, "name_ar": CHAINS[k]["name_ar"], "name_en": CHAINS[k]["name_en"], "native": CHAINS[k]["native"],
             "tested": bool(CHAINS[k].get("tested"))} for k in ORDER]


def guess(addr):
    """Networks an address could belong to (several are possible: EVM addresses are shared by all EVM chains)."""
    a = (addr or "").strip()
    out = []
    if EVM_RE.match(a):
        return [k for k in ORDER if is_evm(k)]
    for k in ORDER:
        c = CHAINS[k]
        if c["fam"] != "evm" and re.match(c["addr_re"], a.lower() if c.get("lower_prefix") and a.lower().startswith(c["lower_prefix"]) else a):
            out.append(k)
    if "sol" in out and len(out) > 1 and len(a) < 43:
        pass
    return out
