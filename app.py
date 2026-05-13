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
# SPECIAL ADDRESSES
# ─────────────────────────────────────────────

SPECIAL_ADDRESSES = {
    "0x0000000000000000000000000000000000000000": {
        "risk": 5,
        "label": "Null/Burn Address (Ethereum)",
        "note": "This is the zero address, used for token burning and contract creation. It's not a user wallet."
    },
    "0x000000000000000000000000000000000000dead": {
        "risk": 5,
        "label": "Burn Address",
        "note": "Common burn address for tokens."
    }
}

# ─────────────────────────────────────────────
# THREAT DATABASE (risk 0–100)
# ─────────────────────────────────────────────

KNOWN_BLACKLIST = {
    # BTC
    "1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF": {"risk": 100, "label": "Mt. Gox Stolen Funds"},
    "1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY": {"risk": 95,  "label": "Known Suspicious BTC Wallet"},
    "1P5ZEDWTKTFGxQjZphgWPQUpe554WKDfHQ": {"risk": 90,  "label": "High-Risk Whale Wallet"},
    "12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr":  {"risk": 85,  "label": "Reported Ransomware Address"},
    "1dice8EMZmqKvrGE4Qc9bUFngAiT1Xfacing": {"risk": 80, "label": "Reported Scam Address"},
    "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94": {"risk": 75,  "label": "Mixing Service / Tumbler"},
    "1LuckyR1fFHEsXYyx5QK4UFzv3PEAepPMK": {"risk": 72,  "label": "Lucky Bitcoin Gambling/Faucet"},

    # ETH
    "0xaA923Cd02364Bb8A4c3d6F894178d2e12231655C": {"risk": 100, "label": "Cryptopia Hacker Wallet"},
    "0x9007A0421145B06a0345d55a8C0f0327f62A2224": {"risk": 100, "label": "Cryptopia Hacker Wallet"},
    "0xD882cFc20F52f2599D84b8e8D58C7FB62cfE344b": {"risk": 95,  "label": "Reported Phishing Address"},
    "0x7F367cC41522cE07553e823bf3be79A889DEbe1B": {"risk": 98,  "label": "Lazarus Group – Sanctioned by OFAC"},
    "0x098B716b8Aaf21512996dC57EB0615e2383E2f96": {"risk": 100, "label": "Tornado Cash – OFAC Sanctioned Mixer"},
}

# ─────────────────────────────────────────────
# WHITELIST (legitimate, well-known wallets)
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
    # Special case: null address is technically valid but not a real wallet
    if address == "0x0000000000000000000000000000000000000000":
        return True
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
    """Query BitcoinAbuse public report count via their API."""
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
    """Query Chainalysis sanctions API if key is set."""
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
    # Check special addresses first
    if wallet.lower() in SPECIAL_ADDRESSES:
        special = SPECIAL_ADDRESSES[wallet.lower()]
        return {
            "network": "ethereum",
            "currency": "ETH",
            "is_special": True,
            "special_label": special["label"],
            "special_note": special["note"],
            "total_tx": 0,
            "total_volume": 0.0,
            "max_tx_amount": 0.0,
            "dust_tx_count": 0,
            "small_tx_count": 0,
            "large_tx_count": 0,
            "dust_percentage": 0.0,
            "outgoing_tx_count": 0,
            "unique_outgoing_addresses": 0,
            "unique_incoming_addresses": 0,
            "contract_interactions": 0,
            "failed_tx_count": 0,
            "tx_per_day": 0.0,
            "value_uniformity": 0.0,
            "recent_activity": False,
            "last_active_days": 999,
            "balance": 0.0,
            "is_real_data": False,
        }
    
    api_key = os.environ.get("ETHERSCAN_API_KEY", "").strip()
    if not api_key:
        return {"error": "Missing Etherscan API key"}

    try:
        # Fetch transactions (up to 1000 for performance)
        txs = []
        url = (
            "https://api.etherscan.io/v2/api"
            f"?chainid=1&module=account&action=txlist"
            f"&address={wallet}&startblock=0&endblock=99999999"
            f"&page=1&offset=500&sort=desc&apikey={api_key}"
        )
        r = requests.get(url, timeout=20)
        data = r.json()
        
        if data.get("status") == "1":
            txs = data.get("result", [])[:1000]  # Limit to 1000 transactions
        
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

        # ERC-20 token transfer count
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
    total_received = 0.0
    total_sent = 0.0
    max_tx = 0.0
    
    # Non-overlapping categories
    dust_count = 0  # < 0.0001 ETH
    small_count = 0  # 0.0001 - 0.1 ETH
    medium_count = 0  # 0.1 - 10 ETH
    large_count = 0  # > 10 ETH
    
    outgoing = 0
    incoming = 0
    unique_outgoing = set()
    unique_incoming = set()
    timestamps = []
    contract_interactions = 0
    failed_tx = 0
    tx_values = []

    for tx in txs[:1000]:
        try:
            value = int(tx["value"]) / 1e18
            abs_val = abs(value)
            
            if tx["from"].lower() == wallet.lower():
                # Outgoing transaction
                total_sent += abs_val
                outgoing += 1
                if tx.get("to"):
                    unique_outgoing.add(tx["to"].lower())
            else:
                # Incoming transaction
                total_received += abs_val
                incoming += 1
                if tx.get("from"):
                    unique_incoming.add(tx["from"].lower())
            
            max_tx = max(max_tx, abs_val)
            timestamps.append(int(tx["timeStamp"]))
            
            if abs_val > 0:
                tx_values.append(abs_val)
                
                # Non-overlapping categories
                if abs_val < 0.0001:
                    dust_count += 1
                elif abs_val < 0.1:
                    small_count += 1
                elif abs_val < 10:
                    medium_count += 1
                else:
                    large_count += 1

            if tx.get("input", "0x") not in ("0x", ""):
                contract_interactions += 1

            if tx.get("isError") == "1":
                failed_tx += 1

        except Exception:
            pass

    total_volume = total_received + total_sent
    
    latest = max(timestamps) if timestamps else 0
    days = int((time.time() - latest) / 86400) if latest else 999
    
    dust_pct = (dust_count / total_tx * 100) if total_tx > 0 else 0.0

    # Velocity: transactions per day
    if len(timestamps) >= 2:
        oldest = min(timestamps)
        lifetime_days = max((time.time() - oldest) / 86400, 0.001)
        tx_per_day = total_tx / lifetime_days
    else:
        tx_per_day = 0.0

    # Value uniformity score
    uniformity_score = 0.0
    if len(tx_values) > 1:
        avg = sum(tx_values) / len(tx_values)
        if avg > 0:
            near_avg = sum(1 for v in tx_values if abs(v - avg) / avg < 0.05)
            uniformity_score = near_avg / len(tx_values)

    return {
        "network": "ethereum",
        "currency": "ETH",
        "total_tx": total_tx,
        "total_received": total_received,
        "total_sent": total_sent,
        "total_volume": total_volume,
        "max_tx_amount": max_tx,
        "dust_tx_count": dust_count,
        "small_tx_count": small_count,
        "medium_tx_count": medium_count,
        "large_tx_count": large_count,
        "dust_percentage": dust_pct,
        "incoming_tx_count": incoming,
        "outgoing_tx_count": outgoing,
        "unique_outgoing_addresses": len(unique_outgoing),
        "unique_incoming_addresses": len(unique_incoming),
        "contract_interactions": contract_interactions,
        "failed_tx_count": failed_tx,
        "tx_per_day": tx_per_day,
        "value_uniformity": uniformity_score,
        "recent_activity": days <= 7,
        "last_active_days": days,
        "balance": balance,
        "is_real_data": total_tx > 0,
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

        # Fetch transactions (limited to 200 for performance)
        txs = []
        tx_url = f"https://blockstream.info/api/address/{wallet}/txs"
        tr = requests.get(tx_url, timeout=20)
        if tr.status_code == 200:
            txs = tr.json()[:200]

        return analyze_bitcoin_transactions(wallet, info, txs)

    except Exception as e:
        return {"error": str(e)}

def analyze_bitcoin_transactions(wallet: str, info: dict, txs: list) -> dict:
    total_tx = len(txs)
    total_received = 0.0
    total_sent = 0.0
    max_tx = 0.0
    
    dust_count = 0  # < 0.00001 BTC
    small_count = 0  # 0.00001 - 0.001 BTC
    medium_count = 0  # 0.001 - 1 BTC
    large_count = 0  # > 1 BTC
    
    outgoing = 0
    incoming = 0
    unique_outgoing = set()
    unique_incoming = set()
    timestamps = []
    tx_values = []

    for tx in txs[:200]:
        tx_value = 0.0
        is_sending = False
        is_receiving = False
        in_addrs = set()
        out_addrs = set()

        for vin in tx.get("vin", []):
            prev = vin.get("prevout")
            if prev and prev.get("scriptpubkey_address") == wallet:
                is_sending = True
                value = prev.get("value", 0) / 1e8
                tx_value -= value
                total_sent += value
            elif prev and prev.get("scriptpubkey_address"):
                in_addrs.add(prev["scriptpubkey_address"])

        for vout in tx.get("vout", []):
            addr = vout.get("scriptpubkey_address")
            if addr == wallet:
                is_receiving = True
                value = vout.get("value", 0) / 1e8
                tx_value += value
                total_received += value
            elif addr:
                out_addrs.add(addr)

        if is_sending:
            outgoing += 1
            unique_outgoing |= out_addrs
        if is_receiving:
            incoming += 1
            unique_incoming |= in_addrs

        value = abs(tx_value)
        if value > 0:
            max_tx = max(max_tx, value)
            tx_values.append(value)
            
            # Non-overlapping categories
            if value < 0.00001:
                dust_count += 1
            elif value < 0.001:
                small_count += 1
            elif value < 1:
                medium_count += 1
            else:
                large_count += 1

        block_time = tx.get("status", {}).get("block_time")
        if block_time:
            timestamps.append(block_time)

    total_volume = total_received + total_sent
    
    latest = max(timestamps) if timestamps else 0
    days = int((time.time() - latest) / 86400) if latest else 999

    if len(timestamps) >= 2:
        oldest = min(timestamps)
        lifetime_days = max((time.time() - oldest) / 86400, 0.001)
        tx_per_day = total_tx / lifetime_days
    else:
        tx_per_day = 0.0

    uniformity_score = 0.0
    if len(tx_values) > 1:
        avg = sum(tx_values) / len(tx_values)
        if avg > 0:
            near_avg = sum(1 for v in tx_values if abs(v - avg) / avg < 0.05)
            uniformity_score = near_avg / len(tx_values)

    funded = info.get("chain_stats", {}).get("funded_txo_sum", 0) / 1e8
    spent = info.get("chain_stats", {}).get("spent_txo_sum", 0) / 1e8
    balance = funded - spent
    
    onchain_tx_count = (
        info.get("chain_stats", {}).get("tx_count", 0) +
        info.get("mempool_stats", {}).get("tx_count", 0)
    )

    dust_pct = (dust_count / total_tx * 100) if total_tx > 0 else 0.0

    return {
        "network": "bitcoin",
        "currency": "BTC",
        "total_tx": onchain_tx_count,
        "total_received": total_received,
        "total_sent": total_sent,
        "total_volume": total_volume,
        "max_tx_amount": max_tx,
        "dust_tx_count": dust_count,
        "small_tx_count": small_count,
        "medium_tx_count": medium_count,
        "large_tx_count": large_count,
        "dust_percentage": dust_pct,
        "incoming_tx_count": incoming,
        "outgoing_tx_count": outgoing,
        "unique_outgoing_addresses": len(unique_outgoing),
        "unique_incoming_addresses": len(unique_incoming),
        "tx_per_day": tx_per_day,
        "value_uniformity": uniformity_score,
        "recent_activity": days <= 7,
        "last_active_days": days,
        "balance": balance,
        "funded_total": funded,
        "is_real_data": total_tx > 0,
    }

# ─────────────────────────────────────────────
# FRAUD / RISK ENGINE
# ─────────────────────────────────────────────

def detect_fraud(wallet: str, data: dict) -> tuple[str, int, list[str]]:
    if data.get("error"):
        return "CANT_ANALYZE", 0, [data["error"]]
    
    # Handle special addresses
    if data.get("is_special"):
        return "VERY LOW RISK ✅", SPECIAL_ADDRESSES.get(wallet.lower(), {}).get("risk", 5), [f"ℹ️ {data.get('special_note', 'This is a special address')}"]

    score = 0
    reasons = []
    currency = data.get("currency", "")
    total_tx = data.get("total_tx", 0)
    
    # Don't analyze wallets with no transactions (except for special cases)
    if total_tx == 0 and not data.get("is_special"):
        return "VERY LOW RISK ✅", 5, ["🆕 No transaction history found. This address appears to be inactive or newly created."]

    # ── 1. HARD BLACKLIST ──
    if wallet in KNOWN_BLACKLIST:
        threat = KNOWN_BLACKLIST[wallet]
        score = max(score, threat["risk"])
        reasons.append(f"🚨 BLACKLISTED: {threat['label']}")

    # ── 2. HARD WHITELIST ──
    if wallet in KNOWN_WHITELIST:
        score = max(0, score - 30)
        reasons.append(f"✅ Verified legitimate wallet: {KNOWN_WHITELIST[wallet]}")

    # ── 3. EXTERNAL THREAT INTEL ──
    if data.get("network") == "bitcoin":
        abuse = check_bitcoinabuse(wallet)
        if abuse["reports"] >= 10:
            score = min(100, score + 50)
            reasons.append(f"🚨 {abuse['reports']} abuse reports on BitcoinAbuse")
        elif abuse["reports"] >= 3:
            score = min(100, score + 25)
            reasons.append(f"⚠️ {abuse['reports']} abuse reports on BitcoinAbuse")
        elif abuse["reports"] >= 1:
            score = min(100, score + 10)
            reasons.append(f"📊 {abuse['reports']} report(s) on BitcoinAbuse")

    if check_chainalysis_sanctions(wallet):
        score = min(100, score + 60)
        reasons.append("🚨 Flagged by Chainalysis sanctions database")

    # ── 4. GAMBLING PATTERN ──
    if is_gambling_address(wallet):
        score = min(100, score + 30)
        reasons.append("🎰 Gambling/faucet address pattern detected")

    # ── 5. TRANSACTION METRICS ──
    dust_count = data.get("dust_tx_count", 0)
    small_count = data.get("small_tx_count", 0)
    medium_count = data.get("medium_tx_count", 0)
    large_count = data.get("large_tx_count", 0)
    outgoing = data.get("outgoing_tx_count", 0)
    uniq_out = data.get("unique_outgoing_addresses", 0)
    balance = data.get("balance", 0.0)
    total_received = data.get("total_received", 0.0)
    total_sent = data.get("total_sent", 0.0)
    max_tx = data.get("max_tx_amount", 0.0)
    tx_per_day = data.get("tx_per_day", 0.0)
    uniformity = data.get("value_uniformity", 0.0)
    failed = data.get("failed_tx_count", 0)

    # Dust percentage (only meaningful for active wallets)
    if total_tx > 10:
        dust_pct = (dust_count / total_tx * 100)
        if dust_pct > 70:
            score += 45
            reasons.append(f"🔴 Severe dusting activity ({dust_pct:.0f}% dust transactions)")
        elif dust_pct > 40:
            score += 28
            reasons.append(f"⚠️ High dust ratio ({dust_pct:.0f}%) – possible address poisoning")

    # Mixer pattern
    if outgoing > 50:
        out_diversity = uniq_out / outgoing if outgoing > 0 else 0
        if out_diversity > 0.80:
            score += 50
            reasons.append("🔴 Strong mixer / tumbler pattern (high output diversity)")
        elif out_diversity > 0.60:
            score += 30
            reasons.append("⚠️ Possible mixing / tumbling behavior")

    # Value uniformity
    if uniformity > 0.80 and total_tx > 20:
        score += 25
        reasons.append("🔴 Near-identical transaction values (mixer / automated scheme)")

    # High velocity
    if tx_per_day > 500:
        score += 35
        reasons.append(f"🔴 Extremely high velocity: {tx_per_day:.0f} txs/day")
    elif tx_per_day > 100:
        score += 20
        reasons.append(f"⚠️ Very high velocity: {tx_per_day:.0f} txs/day")

    # Balance vs volume check (fixed logic)
    if total_received > 0 and balance < (total_received * 0.01) and total_tx > 100:
        score += 28
        reasons.append("⚠️ Pass-through wallet: very low balance relative to total received")

    # Large transactions
    large_threshold = 100 if currency == "BTC" else 500
    if max_tx > large_threshold * 5 and max_tx > 0:
        score += 22
        reasons.append(f"🔴 Extremely large single transaction: {max_tx:.4f} {currency}")
    elif max_tx > large_threshold:
        score += 12
        reasons.append(f"⚠️ Very large transaction detected: {max_tx:.4f} {currency}")

    # Total volume
    vol_high = 50000 if currency == "BTC" else 10000
    if total_received + total_sent > vol_high:
        score += 20
        reasons.append(f"📊 Extremely high total volume: {(total_received + total_sent):.2f} {currency}")

    # Failed transactions
    if total_tx > 0 and (failed / total_tx) > 0.30 and failed > 20:
        score += 18
        reasons.append(f"⚠️ High failed-transaction rate ({failed}/{total_tx}) – possible bot activity")

    # Normal wallet indicators (positive)
    if total_tx > 10 and dust_count < total_tx * 0.1 and large_count < 5:
        score = max(0, score - 15)
        if score < 30:
            reasons.insert(0, "✅ Wallet shows normal transaction patterns")

    # Cap score
    score = min(max(score, 0), 100)

    # Classify
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
# AI AGENT ENDPOINT
# ─────────────────────────────────────────────

@app.route("/agent", methods=["POST"])
def agent_chat():
    try:
        body = request.get_json(silent=True) or {}
        message = body.get("message", "").strip()
        context = body.get("context", "")

        if not message:
            return jsonify({"error": "No message provided"}), 400

        groq_key = os.environ.get("GROQ_API_KEY", "").strip()
        
        if not groq_key:
            return jsonify({"error": "NO_KEY"})
        
        # Simple mock response for now (since Groq API requires additional setup)
        # You can replace this with actual Groq API call
        return jsonify({
            "reply": f"🔍 **Blockchain Security Assistant**\n\nI understand you're asking about: \"{message[:100]}...\"\n\nFor full AI analysis, please configure your Groq API key in the .env file. The system is designed to provide real-time fraud detection and wallet risk assessment based on live blockchain data.\n\n**Current capabilities:**\n• Real-time ETH/BTC wallet scanning\n• Dust attack detection\n• Mixer/tumbler pattern recognition\n• Sanctions database checking\n\nWould you like me to explain any specific fraud pattern in detail?"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
            balance_display = f"{bal:.8f} BTC" if bal > 0 else "0 BTC"
        else:
            balance_display = f"{bal:.4f} ETH" if bal > 0 else "0 ETH"

        # Create transaction type breakdown
        tx_types = {
            "dust": result.get("dust_tx_count", 0),
            "small": result.get("small_tx_count", 0),
            "medium": result.get("medium_tx_count", 0),
            "large": result.get("large_tx_count", 0)
        }

        return jsonify({
            "wallet": wallet,
            "network": result["network"],
            "currency": currency,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "reasons": reasons,
            "transactions_found": result["total_tx"],
            "total_volume": f"{result['total_volume']:.8f} {currency}",
            "total_received": f"{result.get('total_received', 0):.8f}",
            "total_sent": f"{result.get('total_sent', 0):.8f}",
            "max_tx_amount": f"{result['max_tx_amount']:.8f}",
            "last_active": last_active,
            "last_active_days": days,
            "dust_tx_count": result["dust_tx_count"],
            "small_tx_count": result.get("small_tx_count", 0),
            "medium_tx_count": result.get("medium_tx_count", 0),
            "large_tx_count": result["large_tx_count"],
            "tx_types": tx_types,
            "balance": balance_display,
            "incoming_tx_count": result.get("incoming_tx_count", 0),
            "outgoing_tx_count": result.get("outgoing_tx_count", 0),
            "unique_outgoing": result.get("unique_outgoing_addresses", 0),
            "unique_incoming": result.get("unique_incoming_addresses", 0),
            "tx_per_day": round(result.get("tx_per_day", 0), 2),
            "is_real_data": result.get("is_real_data", True),
            "is_special": result.get("is_special", False),
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/test_api", methods=["GET"])
def test_api():
    eth_key = bool(os.environ.get("ETHERSCAN_API_KEY", "").strip())
    groq_key = bool(os.environ.get("GROQ_API_KEY", "").strip())
    abuse_key = bool(os.environ.get("BITCOINABUSE_API_KEY", "").strip())
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
        "etherscan_configured": eth_key,
        "groq_configured": groq_key,
        "bitcoinabuse_configured": abuse_key,
        "chainalysis_configured": chainalysis_key,
        "bitcoin_api_working": bitcoin_ok,
        "status": "operational",
    })

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    print("=" * 60)
    print("🔒 CryptoShield AI — Fraud Detection v3")
    print("=" * 60)
    print(f"  Etherscan API  : {'✅ Configured' if os.environ.get('ETHERSCAN_API_KEY') else '❌ Missing'}")
    print(f"  Bitcoin API    : ✅ Blockstream (free, no key needed)")
    print(f"  BitcoinAbuse   : {'✅ Configured' if os.environ.get('BITCOINABUSE_API_KEY') else '⚠️  Optional'}")
    print(f"  Chainalysis    : {'✅ Configured' if os.environ.get('CHAINALYSIS_API_KEY') else '⚠️  Optional'}")
    print(f"  Groq AI        : {'✅ Configured' if os.environ.get('GROQ_API_KEY') else '⚠️  Optional'}")
    print(f"  Server         : http://localhost:{port}")
    print("=" * 60)

    app.run(host="0.0.0.0", port=port, debug=True)