import os
import sys
import re
import time
import requests

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ─────────────────────────────────────────────
# CORS
# ─────────────────────────────────────────────

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST')
    return response

# ─────────────────────────────────────────────
# THREAT DATABASE  (risk 0–100)
# ─────────────────────────────────────────────

KNOWN_BLACKLIST = {
    # BTC
    "1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF": {"risk": 100, "label": "Mt. Gox Stolen Funds"},
    "1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY": {"risk": 95,  "label": "Known Suspicious BTC Wallet"},
    "1P5ZEDWTKTFGxQjZphgWPQUpe554WKDfHQ": {"risk": 90,  "label": "High-Risk Whale Wallet"},
    "12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr":  {"risk": 85,  "label": "Reported Ransomware Address"},
    "1dice8EMZmqKvrGE4Qc9bUFngAiT1Xfacing": {"risk": 80, "label": "Reported Scam Address"},
    "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94": {"risk": 75,  "label": "Mixing Service / Tumbler"},
    "1LuckyR1fFHEsXYyx5QK4UFzv3PEAepPMK": {"risk": 72,  "label": "Lucky Bitcoin Gambling/Faucet – High-volume micro-payout service with fraud reports"},

    # ETH
    "0xaA923Cd02364Bb8A4c3d6F894178d2e12231655C": {"risk": 100, "label": "Cryptopia Hacker Wallet"},
    "0x9007A0421145B06a0345d55a8C0f0327f62A2224": {"risk": 100, "label": "Cryptopia Hacker Wallet"},
    "0xD882cFc20F52f2599D84b8e8D58C7FB62cfE344b": {"risk": 95,  "label": "Reported Phishing Address"},
    "0x7F367cC41522cE07553e823bf3be79A889DEbe1B": {"risk": 98,  "label": "Lazarus Group – Sanctioned by OFAC"},
    "0x098B716b8Aaf21512996dC57EB0615e2383E2f96": {"risk": 100, "label": "Tornado Cash – OFAC Sanctioned Mixer"},
}

# ─────────────────────────────────────────────
# WHITELIST  (legitimate, well-known wallets)
# ─────────────────────────────────────────────

KNOWN_WHITELIST = {
    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq": "Blockstream Test Wallet",
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa":         "Satoshi Nakamoto Genesis Wallet",
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh": "Binance Cold Wallet",
    "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5":  "Sample Test Wallet",
    "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo":          "Binance Exchange Hot Wallet",
    "3LYJfcfHcvBHWeight6i6THe97emjoBkK2n":          "Kraken Exchange Wallet",
}

# ─────────────────────────────────────────────
# GAMBLING / HIGH-VOLUME SERVICE PATTERNS
# Known gambling/faucet/lottery prefixes and addresses
# ─────────────────────────────────────────────

GAMBLING_PATTERNS = [
    r"^1Lucky",
    r"^1Dice",
    r"^1Satoshi",
    r"^3FupHM",
    r"^1Casino",
    r"^1Gambl",
]

def is_gambling_address(address: str) -> bool:
    for pattern in GAMBLING_PATTERNS:
        if re.match(pattern, address, re.IGNORECASE):
            return True
    return False

# ─────────────────────────────────────────────
# VALIDATORS
# ─────────────────────────────────────────────

def validate_ethereum_address(address: str) -> bool:
    return bool(re.match(r"^0x[a-fA-F0-9]{40}$", address))

def validate_bitcoin_address(address: str) -> bool:
    patterns = [
        r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$',
        r'^(bc1)[a-zA-HJ-NP-Z0-9]{39,59}$',
    ]
    return any(re.match(p, address) for p in patterns)

def detect_network(address: str) -> str | None:
    if validate_ethereum_address(address):
        return "ethereum"
    if validate_bitcoin_address(address):
        return "bitcoin"
    return None

# ─────────────────────────────────────────────
# EXTERNAL THREAT INTEL
# ─────────────────────────────────────────────

def check_bitcoinabuse(address: str) -> dict:
    """
    Query BitcoinAbuse public report count via their API.
    Returns {'reports': N, 'error': None} or {'reports': 0, 'error': 'reason'}.
    Set BITCOINABUSE_API_KEY in .env to enable (free tier available).
    """
    api_key = os.environ.get("BITCOINABUSE_API_KEY", "").strip()
    if not api_key:
        return {"reports": 0, "error": "no_key"}
    try:
        url = f"https://www.bitcoinabuse.com/api/reports/check?address={address}&api_token={api_key}"
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            data = r.json()
            return {"reports": data.get("count", 0), "error": None}
    except Exception as e:
        return {"reports": 0, "error": str(e)}
    return {"reports": 0, "error": "api_error"}


def check_chainalysis_sanctions(address: str) -> bool:
    """
    Query Chainalysis sanctions API if key is set.
    Returns True if address is sanctioned.
    """
    api_key = os.environ.get("CHAINALYSIS_API_KEY", "").strip()
    if not api_key:
        return False
    try:
        headers = {"Token": api_key}
        url = f"https://public.chainalysis.com/api/v1/address/{address}"
        r = requests.get(url, headers=headers, timeout=8)
        if r.status_code == 200:
            data = r.json()
            identifications = data.get("identifications", [])
            return any(
                i.get("category") in ("sanctions", "darkweb", "stolen funds", "ransomware")
                for i in identifications
            )
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────
# ETHEREUM ANALYSIS
# ─────────────────────────────────────────────

def get_ethereum_wallet_data(wallet: str) -> dict:
    api_key = os.environ.get("ETHERSCAN_API_KEY", "").strip()
    if not api_key:
        return {"error": "Missing Etherscan API key"}

    try:
        # Paginated TX fetch (up to 2000 most recent)
        txs = []
        for page in range(1, 5):          # 4 pages × 500 = 2,000 txs max
            url = (
                "https://api.etherscan.io/v2/api"
                f"?chainid=1&module=account&action=txlist"
                f"&address={wallet}&startblock=0&endblock=99999999"
                f"&page={page}&offset=500&sort=desc&apikey={api_key}"
            )
            r = requests.get(url, timeout=20)
            data = r.json()
            if data.get("status") != "1":
                if page == 1:
                    return {"error": data.get("result", "Failed fetching ETH data")}
                break
            batch = data.get("result", [])
            txs.extend(batch)
            if len(batch) < 500:
                break
            time.sleep(0.25)              # respect rate limits

        # Current balance
        balance = 0.0
        try:
            bal_url = (
                "https://api.etherscan.io/v2/api"
                f"?chainid=1&module=account&action=balance"
                f"&address={wallet}&tag=latest&apikey={api_key}"
            )
            br = requests.get(bal_url, timeout=10)
            bd = br.json()
            if bd.get("status") == "1":
                balance = int(bd["result"]) / 1e18
        except Exception:
            pass

        # ERC-20 token transfer count (mixer / DeFi heuristic)
        token_tx_count = 0
        try:
            token_url = (
                "https://api.etherscan.io/v2/api"
                f"?chainid=1&module=account&action=tokentx"
                f"&address={wallet}&startblock=0&endblock=99999999"
                f"&page=1&offset=100&sort=desc&apikey={api_key}"
            )
            tr = requests.get(token_url, timeout=10)
            td = tr.json()
            if td.get("status") == "1":
                token_tx_count = len(td.get("result", []))
        except Exception:
            pass

        result = analyze_ethereum_transactions(wallet, txs, balance)
        result["token_tx_count"] = token_tx_count
        return result

    except Exception as e:
        return {"error": str(e)}


def analyze_ethereum_transactions(wallet: str, txs: list, balance: float = 0.0) -> dict:
    total_tx = len(txs)
    total_volume = 0.0
    max_tx = 0.0
    dust = small = large = 0
    outgoing = 0
    unique_outgoing = set()
    unique_incoming = set()
    timestamps = []
    contract_interactions = 0
    failed_tx = 0
    tx_values = []

    for tx in txs[:2000]:
        try:
            value = int(tx["value"]) / 1e18
            abs_val = abs(value)
            total_volume += abs_val
            max_tx = max(max_tx, abs_val)
            timestamps.append(int(tx["timeStamp"]))
            tx_values.append(abs_val)

            if tx.get("isError") == "1":
                failed_tx += 1

            if tx.get("input", "0x") not in ("0x", ""):
                contract_interactions += 1

            if abs_val < 0.0001:
                dust += 1
            if abs_val < 0.01:
                small += 1
            if abs_val > 50:
                large += 1

            if tx["from"].lower() == wallet.lower():
                outgoing += 1
                if tx.get("to"):
                    unique_outgoing.add(tx["to"].lower())
            else:
                if tx.get("from"):
                    unique_incoming.add(tx["from"].lower())

        except Exception:
            pass

    latest = max(timestamps) if timestamps else 0
    days = int((time.time() - latest) / 86400) if latest else 999
    dust_pct = (dust / total_tx * 100) if total_tx > 0 else 0.0

    # Velocity: transactions per day (over the wallet's lifetime)
    if len(timestamps) >= 2:
        oldest = min(timestamps)
        lifetime_days = max((time.time() - oldest) / 86400, 1)
        tx_per_day = total_tx / lifetime_days
    else:
        tx_per_day = 0.0

    # Value uniformity score (mixer heuristic) – high if most txs are same value
    uniformity_score = 0.0
    if tx_values:
        avg = sum(tx_values) / len(tx_values)
        if avg > 0:
            near_avg = sum(1 for v in tx_values if abs(v - avg) / avg < 0.05)
            uniformity_score = near_avg / len(tx_values)

    return {
        "network": "ethereum",
        "currency": "ETH",
        "total_tx": total_tx,
        "total_volume": total_volume,
        "max_tx_amount": max_tx,
        "dust_tx_count": dust,
        "small_tx_count": small,
        "large_tx_count": large,
        "dust_percentage": dust_pct,
        "outgoing_tx_count": outgoing,
        "unique_outgoing_addresses": len(unique_outgoing),
        "unique_incoming_addresses": len(unique_incoming),
        "contract_interactions": contract_interactions,
        "failed_tx_count": failed_tx,
        "tx_per_day": tx_per_day,
        "value_uniformity": uniformity_score,
        "recent_activity": days <= 1,
        "last_active_days": days,
        "balance": balance,
        "is_real_data": True,
    }

# ─────────────────────────────────────────────
# BITCOIN ANALYSIS
# ─────────────────────────────────────────────

def get_bitcoin_wallet_data(wallet: str) -> dict:
    try:
        # Address summary
        info_url = f"https://blockstream.info/api/address/{wallet}"
        r = requests.get(info_url, timeout=20)
        if r.status_code != 200:
            return {"error": "BTC address not found"}
        info = r.json()

        # Paginated TX fetch (up to 500 most recent via after_txid)
        txs: list = []
        last_txid: str | None = None

        for _ in range(10):              # 10 pages × 25 = 250 txs
            tx_url = f"https://blockstream.info/api/address/{wallet}/txs"
            if last_txid:
                tx_url += f"/chain/{last_txid}"
            tr = requests.get(tx_url, timeout=20)
            if tr.status_code != 200:
                break
            page = tr.json()
            if not page:
                break
            txs.extend(page)
            if len(page) < 25:
                break
            last_txid = page[-1]["txid"]
            time.sleep(0.15)             # be polite to the free API

        return analyze_bitcoin_transactions(wallet, info, txs)

    except Exception as e:
        return {"error": str(e)}


def analyze_bitcoin_transactions(wallet: str, info: dict, txs: list) -> dict:
    total_tx = len(txs)
    total_volume = 0.0
    max_tx = 0.0
    dust = small = large = 0
    outgoing = 0
    unique_outgoing: set = set()
    unique_incoming: set = set()
    timestamps: list = []
    tx_values: list = []

    for tx in txs[:500]:
        tx_value = 0.0
        is_sending = False
        in_addrs: set = set()
        out_addrs: set = set()

        for vin in tx.get("vin", []):
            prev = vin.get("prevout")
            if prev and prev.get("scriptpubkey_address") == wallet:
                is_sending = True
                tx_value -= prev.get("value", 0) / 1e8
            elif prev and prev.get("scriptpubkey_address"):
                in_addrs.add(prev["scriptpubkey_address"])

        for vout in tx.get("vout", []):
            addr = vout.get("scriptpubkey_address")
            if addr == wallet:
                tx_value += vout.get("value", 0) / 1e8
            elif addr:
                out_addrs.add(addr)

        if is_sending:
            outgoing += 1
            unique_outgoing |= out_addrs
        else:
            unique_incoming |= in_addrs

        value = abs(tx_value)
        if value > 0:
            total_volume += value
            max_tx = max(max_tx, value)
            tx_values.append(value)

            if value < 0.00001:
                dust += 1
            if value < 0.001:
                small += 1
            if value > 2:
                large += 1

        block_time = tx.get("status", {}).get("block_time")
        if block_time:
            timestamps.append(block_time)

    latest = max(timestamps) if timestamps else 0
    days = int((time.time() - latest) / 86400) if latest else 999

    # Wallet lifetime velocity
    if len(timestamps) >= 2:
        oldest = min(timestamps)
        lifetime_days = max((time.time() - oldest) / 86400, 1)
        tx_per_day = total_tx / lifetime_days
    else:
        tx_per_day = 0.0

    # Uniformity (mixer / faucet heuristic)
    uniformity_score = 0.0
    if tx_values:
        avg = sum(tx_values) / len(tx_values)
        if avg > 0:
            near_avg = sum(1 for v in tx_values if abs(v - avg) / avg < 0.05)
            uniformity_score = near_avg / len(tx_values)

    funded = info.get("chain_stats", {}).get("funded_txo_sum", 0) / 1e8
    spent  = info.get("chain_stats", {}).get("spent_txo_sum",  0) / 1e8
    balance = funded - spent

    # Use on-chain total tx count (more reliable than len(txs) which is capped)
    onchain_tx_count = (
        info.get("chain_stats", {}).get("tx_count", 0) +
        info.get("mempool_stats", {}).get("tx_count", 0)
    )

    dust_pct = (dust / total_tx * 100) if total_tx > 0 else 0.0

    return {
        "network": "bitcoin",
        "currency": "BTC",
        "total_tx": onchain_tx_count,        # true count from chain_stats
        "sampled_tx": total_tx,              # how many we actually analyzed
        "total_volume": total_volume,
        "max_tx_amount": max_tx,
        "dust_tx_count": dust,
        "small_tx_count": small,
        "large_tx_count": large,
        "dust_percentage": dust_pct,
        "outgoing_tx_count": outgoing,
        "unique_outgoing_addresses": len(unique_outgoing),
        "unique_incoming_addresses": len(unique_incoming),
        "tx_per_day": tx_per_day,
        "value_uniformity": uniformity_score,
        "recent_activity": days <= 1,
        "last_active_days": days,
        "balance": balance,
        "funded_total": funded,
        "is_real_data": True,
    }

# ─────────────────────────────────────────────
# FRAUD / RISK ENGINE  (v2 – calibrated)
# ─────────────────────────────────────────────

def detect_fraud(wallet: str, data: dict) -> tuple[str, int, list[str]]:
    if data.get("error"):
        return "CANT_ANALYZE", 0, [data["error"]]

    score = 0
    reasons: list[str] = []
    currency = data.get("currency", "")

    # ── 1. HARD BLACKLIST ──────────────────────────────────────────────
    if wallet in KNOWN_BLACKLIST:
        threat = KNOWN_BLACKLIST[wallet]
        score = max(score, threat["risk"])
        reasons.append(f"🚨 BLACKLISTED: {threat['label']}")

    # ── 2. HARD WHITELIST ──────────────────────────────────────────────
    if wallet in KNOWN_WHITELIST:
        score = max(0, score - 20)
        reasons.append(f"✅ Verified legitimate wallet: {KNOWN_WHITELIST[wallet]}")

    # ── 3. EXTERNAL THREAT INTEL ──────────────────────────────────────
    # BitcoinAbuse (BTC only)
    if data.get("network") == "bitcoin":
        abuse = check_bitcoinabuse(wallet)
        if abuse["reports"] >= 10:
            score = min(100, score + 50)
            reasons.append(f"🚨 {abuse['reports']} abuse reports on BitcoinAbuse")
        elif abuse["reports"] >= 3:
            score = min(100, score + 25)
            reasons.append(f"⚠️ {abuse['reports']} abuse report(s) on BitcoinAbuse")
        elif abuse["reports"] >= 1:
            score = min(100, score + 10)
            reasons.append(f"📊 {abuse['reports']} report(s) on BitcoinAbuse")

    # Chainalysis (ETH/BTC)
    if check_chainalysis_sanctions(wallet):
        score = min(100, score + 60)
        reasons.append("🚨 Flagged by Chainalysis sanctions database")

    # ── 4. GAMBLING / FAUCET PATTERN ──────────────────────────────────
    gambling = is_gambling_address(wallet)
    if gambling:
        score = min(100, score + 30)
        reasons.append("🎰 Gambling/faucet address pattern detected")

    # ── 5. TRANSACTION METRICS ────────────────────────────────────────
    txs           = data.get("total_tx", 0)
    sampled       = data.get("sampled_tx", txs)      # BTC only
    dust_pct      = data.get("dust_percentage", 0.0)
    outgoing      = data.get("outgoing_tx_count", 0)
    uniq_out      = data.get("unique_outgoing_addresses", 0)
    uniq_in       = data.get("unique_incoming_addresses", 0)
    balance       = data.get("balance", 0.0)
    volume        = data.get("total_volume", 0.0)
    max_tx        = data.get("max_tx_amount", 0.0)
    tx_per_day    = data.get("tx_per_day", 0.0)
    uniformity    = data.get("value_uniformity", 0.0)
    funded_total  = data.get("funded_total", volume)  # BTC total received
    token_txs     = data.get("token_tx_count", 0)

    # ── 5a. DUST / ADDRESS POISONING ──────────────────────────────────
    if dust_pct > 70 and txs > 20:
        score += 45
        reasons.append(f"🔴 Severe dusting activity ({dust_pct:.0f}% dust transactions)")
    elif dust_pct > 40 and txs > 10:
        score += 28
        reasons.append(f"⚠️ High dust ratio ({dust_pct:.0f}%) – possible address poisoning")
    elif dust_pct > 20 and txs > 5:
        score += 14
        reasons.append(f"📊 Elevated dust rate ({dust_pct:.0f}%)")

    # ── 5b. MIXER / TUMBLER PATTERN ───────────────────────────────────
    # Many unique outgoing destinations relative to total outgoing
    out_diversity = (uniq_out / outgoing) if outgoing > 0 else 0
    if outgoing > 80 and out_diversity > 0.80:
        score += 50
        reasons.append("🔴 Strong mixer / tumbler pattern (high output diversity)")
    elif outgoing > 40 and out_diversity > 0.70:
        score += 30
        reasons.append("⚠️ Possible mixing / tumbling behavior")
    elif outgoing > 20 and out_diversity > 0.60:
        score += 15
        reasons.append("📊 Above-average outgoing address diversity")

    # ── 5c. VALUE UNIFORMITY (round-tripping, mixer churning) ─────────
    if uniformity > 0.80 and txs > 20:
        score += 25
        reasons.append("🔴 Near-identical transaction values (mixer / automated scheme)")
    elif uniformity > 0.60 and txs > 10:
        score += 12
        reasons.append("⚠️ Suspiciously uniform transaction amounts")

    # ── 5d. HIGH VELOCITY ─────────────────────────────────────────────
    if tx_per_day > 500:
        score += 35
        reasons.append(f"🔴 Extremely high velocity: {tx_per_day:.0f} txs/day")
    elif tx_per_day > 100:
        score += 20
        reasons.append(f"⚠️ Very high velocity: {tx_per_day:.0f} txs/day")
    elif tx_per_day > 20:
        score += 8
        reasons.append(f"📊 Elevated velocity: {tx_per_day:.1f} txs/day")

    # ── 5e. PASS-THROUGH / MONEY-MULE ─────────────────────────────────
    # Only flag if NOT a known gambling/service address
    if not gambling:
        if balance < 0.001 and txs > 100 and funded_total > 5:
            score += 28
            reasons.append("⚠️ Pass-through wallet: near-zero balance despite high activity & volume")
        elif balance < 0.0001 and txs > 30:
            score += 15
            reasons.append("📊 Possible money-mule pattern (swept balance, active wallet)")

    # ── 5f. LARGE TRANSACTIONS ────────────────────────────────────────
    btc_large_threshold = 100 if currency == "BTC" else 500
    eth_large_threshold = 50  if currency == "ETH" else 100
    large_threshold = btc_large_threshold if currency == "BTC" else eth_large_threshold

    if max_tx > large_threshold * 5:
        score += 22
        reasons.append(f"🔴 Extremely large single transaction: {max_tx:.4f} {currency}")
    elif max_tx > large_threshold:
        score += 12
        reasons.append(f"⚠️ Very large transaction detected: {max_tx:.4f} {currency}")

    # ── 5g. TOTAL VOLUME ──────────────────────────────────────────────
    vol_high = 50000 if currency == "BTC" else 10000
    vol_med  = 10000 if currency == "BTC" else 2000

    if volume > vol_high:
        score += 20
        reasons.append(f"📊 Extremely high total volume: {volume:.2f} {currency}")
    elif volume > vol_med:
        score += 10
        reasons.append(f"📊 High total volume: {volume:.2f} {currency}")

    # ── 5h. NEW WALLET ────────────────────────────────────────────────
    if txs == 0:
        score += 5
        reasons.append("🆕 Brand-new wallet – no transaction history")
    elif txs < 3:
        score += 8
        reasons.append("🆕 Very new wallet (fewer than 3 transactions)")

    # ── 5i. RECENT ACTIVITY ───────────────────────────────────────────
    if data.get("recent_activity"):
        score += 3
        reasons.append("📅 Active in the last 24 hours")

    # ── 5j. HIGH FAILED TX (ETH botnet / spam heuristic) ─────────────
    failed = data.get("failed_tx_count", 0)
    if txs > 0 and (failed / txs) > 0.30 and failed > 20:
        score += 18
        reasons.append(f"⚠️ High failed-transaction rate ({failed}/{txs}) – possible bot activity")

    # ── 5k. SUSPICIOUS ERC-20 ACTIVITY ───────────────────────────────
    if token_txs > 200:
        score += 12
        reasons.append("📊 Very high ERC-20 token transfer activity")

    # ── CAP & CLASSIFY ────────────────────────────────────────────────
    score = min(score, 100)

    if score >= 75:
        level = "HIGH RISK 🔴"
    elif score >= 45:
        level = "MEDIUM RISK ⚠️"
    elif score >= 20:
        level = "LOW RISK 📊"
    else:
        level = "VERY LOW RISK ✅"

    if not reasons:
        reasons.append("✅ No suspicious patterns detected")

    return level, score, reasons

# ─────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────

def get_wallet_data(wallet: str) -> dict:
    network = detect_network(wallet)
    if network == "ethereum":
        return get_ethereum_wallet_data(wallet)
    if network == "bitcoin":
        return get_bitcoin_wallet_data(wallet)
    return {"error": "Invalid wallet address"}

# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/check_wallet", methods=["POST"])
def check_wallet():
    try:
        body = request.get_json(silent=True) or {}
        wallet = body.get("wallet", "").strip()

        if not wallet:
            return jsonify({"error": "Wallet address required"}), 400

        network = detect_network(wallet)
        if not network:
            return jsonify({
                "error": "Invalid wallet format. Please enter a valid ETH or BTC address."
            }), 400

        result = get_wallet_data(wallet)
        if result.get("error"):
            return jsonify({"error": result["error"]}), 400

        risk_level, risk_score, reasons = detect_fraud(wallet, result)

        # Friendly last-active label
        days = result.get("last_active_days", 999)
        if days == 999:
            last_active = "No transactions"
        elif days == 0:
            last_active = "Today"
        elif days == 1:
            last_active = "1 day ago"
        else:
            last_active = f"{days} days ago"

        # Balance display
        currency = result.get("currency", "ETH")
        bal = result.get("balance", 0.0)
        if currency == "BTC":
            balance_display = f"{bal:.8f} BTC"
        else:
            balance_display = f"{bal:.4f} ETH" if bal > 0 else None

        return jsonify({
            "wallet":             wallet,
            "network":            result["network"],
            "currency":           currency,
            "risk_level":         risk_level,
            "risk_score":         risk_score,
            "reasons":            reasons,
            "transactions_found": result["total_tx"],
            "sampled_tx":         result.get("sampled_tx", result["total_tx"]),
            "total_volume":       f"{result['total_volume']:.8f} {currency}",
            "max_tx_amount":      f"{result['max_tx_amount']:.8f}",
            "last_active":        last_active,
            "last_active_days":   days,
            "small_tx_count":     result.get("small_tx_count", 0),
            "dust_tx_count":      result["dust_tx_count"],
            "large_tx_count":     result["large_tx_count"],
            "balance":            balance_display,
            "outgoing_tx_count":  result.get("outgoing_tx_count", 0),
            "unique_outgoing":    result.get("unique_outgoing_addresses", 0),
            "unique_incoming":    result.get("unique_incoming_addresses", 0),
            "tx_per_day":         round(result.get("tx_per_day", 0), 2),
            "is_real_data":       result.get("is_real_data", True),
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/test_api", methods=["GET"])
def test_api():
    eth_key        = bool(os.environ.get("ETHERSCAN_API_KEY", "").strip())
    groq_key       = bool(os.environ.get("GROQ_API_KEY", "").strip())
    abuse_key      = bool(os.environ.get("BITCOINABUSE_API_KEY", "").strip())
    chainalysis_key = bool(os.environ.get("CHAINALYSIS_API_KEY", "").strip())

    bitcoin_ok = False
    try:
        r = requests.get(
            "https://blockstream.info/api/address/bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            timeout=5
        )
        bitcoin_ok = r.status_code == 200
    except Exception:
        pass

    return jsonify({
        "etherscan_configured":    eth_key,
        "groq_configured":         groq_key,
        "bitcoinabuse_configured": abuse_key,
        "chainalysis_configured":  chainalysis_key,
        "bitcoin_api_working":     bitcoin_ok,
        "status": "operational",
    })

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    print("=" * 60)
    print("🔒 CryptoShield AI — Fraud Detection v2")
    print("=" * 60)
    print(f"  Etherscan API  : {'✅ Configured' if os.environ.get('ETHERSCAN_API_KEY') else '❌ Missing'}")
    print(f"  Bitcoin API    : ✅ Blockstream (free, no key needed)")
    print(f"  BitcoinAbuse   : {'✅ Configured' if os.environ.get('BITCOINABUSE_API_KEY') else '⚠️  Optional (add key for extra intel)'}")
    print(f"  Chainalysis    : {'✅ Configured' if os.environ.get('CHAINALYSIS_API_KEY') else '⚠️  Optional (sanctions DB)'}")
    print(f"  Groq AI        : {'✅ Configured' if os.environ.get('GROQ_API_KEY') else '⚠️  Optional'}")
    print(f"  Server         : http://localhost:{port}")
    print("=" * 60)

    app.run(host="0.0.0.0", port=port, debug=True)