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

# ─────────────────────────────────────────────────────────────────────────────
# CORS
# ─────────────────────────────────────────────────────────────────────────────

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST')
    return response

# ─────────────────────────────────────────────────────────────────────────────
# KNOWN BLACKLIST / THREAT INTELLIGENCE
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_BLACKLIST = {

    # BTC
    "1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF": {
        "risk": 98,
        "label": "Mt. Gox Stolen Funds Wallet"
    },

    # ETH
    "0xaA923Cd02364Bb8A4c3d6F894178d2e12231655C": {
        "risk": 95,
        "label": "Cryptopia Hacker Wallet"
    },

    "0x9007A0421145B06a0345d55a8C0f0327f62A2224": {
        "risk": 95,
        "label": "Cryptopia Hacker Wallet"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# VALIDATORS
# ─────────────────────────────────────────────────────────────────────────────

def validate_ethereum_address(address):
    return (
        address.startswith('0x')
        and len(address) == 42
        and all(c in '0123456789abcdefABCDEF' for c in address[2:])
    )

def validate_bitcoin_address(address):

    address = address.strip()

    if re.match(r'^1[1-9A-HJ-NP-Za-km-z]{25,34}$', address):
        return True

    if re.match(r'^3[1-9A-HJ-NP-Za-km-z]{25,34}$', address):
        return True

    if re.match(r'^(bc1)[a-zA-HJ-NP-Z0-9]{39,59}$', address):
        return True

    return False

def detect_network(address):

    address = address.strip()

    if address.startswith('0x') and len(address) == 42:
        return 'ethereum'

    elif validate_bitcoin_address(address):
        return 'bitcoin'

    return None

# ─────────────────────────────────────────────────────────────────────────────
# ETHERSCAN TEST
# ─────────────────────────────────────────────────────────────────────────────

def test_etherscan_api_key(api_key):

    if not api_key:
        return False, "No API key provided"

    test_wallet = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5"

    url = (
        f"https://api.etherscan.io/v2/api?"
        f"chainid=1&module=account&action=balance"
        f"&address={test_wallet}&tag=latest&apikey={api_key}"
    )

    try:

        r = requests.get(url, timeout=10)
        d = r.json()

        if d.get('status') == '1':
            return True, "Valid"

        return False, d.get('result', 'Invalid')

    except Exception as e:
        return False, str(e)

# ─────────────────────────────────────────────────────────────────────────────
# ETHEREUM ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

def get_ethereum_wallet_data(wallet_address):

    api_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()

    if not api_key:
        return {'error': 'No Etherscan API key configured'}

    try:

        url = (
            f"https://api.etherscan.io/v2/api?"
            f"chainid=1&module=account&action=txlist"
            f"&address={wallet_address}"
            f"&startblock=0&endblock=99999999"
            f"&sort=desc&apikey={api_key}"
        )

        r = requests.get(url, timeout=15)
        d = r.json()

        if d.get('status') != '1':
            return {
                'error': d.get('result', 'Failed to fetch Ethereum data')
            }

        txs = d.get('result', [])

        total_tx = len(txs)

        small_tx_count = 0
        dust_tx_count = 0
        large_tx_count = 0

        max_amount = 0
        total_volume = 0

        latest_timestamp = 0

        for tx in txs[:500]:

            try:

                amt = int(tx['value']) / 1e18

                total_volume += abs(amt)

                if amt < 0.0001:
                    dust_tx_count += 1

                if amt < 0.01:
                    small_tx_count += 1

                if amt > 10:
                    large_tx_count += 1

                if amt > max_amount:
                    max_amount = amt

                ts = int(tx['timeStamp'])

                if ts > latest_timestamp:
                    latest_timestamp = ts

            except:
                pass

        days = 999
        recent_activity = False

        if latest_timestamp > 0:

            days = max(
                0,
                int((time.time() - latest_timestamp) / 86400)
            )

            if days == 0:
                recent_activity = True

        dust_percentage = (
            (dust_tx_count / total_tx) * 100
            if total_tx > 0 else 0
        )

        return {

            'network': 'ethereum',
            'currency': 'ETH',

            'total_tx': total_tx,

            'small_tx_count': small_tx_count,
            'dust_tx_count': dust_tx_count,
            'dust_percentage': dust_percentage,

            'large_tx_count': large_tx_count,

            'max_tx_amount': max_amount,
            'total_volume': total_volume,

            'last_active_days': days,
            'recent_activity': recent_activity,

            'outgoing_tx_count': 0,
            'unique_outgoing_addresses': 0,

            'balance': 0,

            'is_real_data': True
        }

    except Exception as e:

        return {
            'error': str(e)
        }

# ─────────────────────────────────────────────────────────────────────────────
# BITCOIN ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

def get_bitcoin_wallet_data(wallet_address):

    try:

        address_url = f"https://blockstream.info/api/address/{wallet_address}"

        r = requests.get(address_url, timeout=15)

        if r.status_code != 200:
            return {'error': 'Bitcoin address not found'}

        data = r.json()

        tx_url = f"https://blockstream.info/api/address/{wallet_address}/txs"

        tx_r = requests.get(tx_url, timeout=15)

        if tx_r.status_code != 200:
            return {'error': 'Failed to fetch BTC transactions'}

        txs = tx_r.json()

        total_tx = len(txs)

        small_tx_count = 0
        dust_tx_count = 0
        large_tx_count = 0

        max_amount = 0
        total_volume = 0

        latest_timestamp = 0

        outgoing_tx_count = 0
        unique_outgoing_addresses = set()

        for tx in txs[:500]:

            tx_value = 0
            is_sending = False

            for vin in tx.get('vin', []):

                prevout = vin.get('prevout')

                if prevout:

                    if prevout.get('scriptpubkey_address') == wallet_address:

                        is_sending = True

                        amt = prevout.get('value', 0) / 1e8

                        tx_value -= amt

            for vout in tx.get('vout', []):

                addr = vout.get('scriptpubkey_address')

                if addr == wallet_address:

                    tx_value += vout.get('value', 0) / 1e8

                elif is_sending and addr:
                    unique_outgoing_addresses.add(addr)

            if is_sending:
                outgoing_tx_count += 1

            abs_value = abs(tx_value)

            if abs_value > 0:

                total_volume += abs_value

                if abs_value < 0.00001:
                    dust_tx_count += 1

                if abs_value < 0.001:
                    small_tx_count += 1

                if abs_value > 1:
                    large_tx_count += 1

                if abs_value > max_amount:
                    max_amount = abs_value

            block_time = tx.get('status', {}).get('block_time', 0)

            if block_time > latest_timestamp:
                latest_timestamp = block_time

        days = 999
        recent_activity = False

        if latest_timestamp > 0:

            days = max(
                0,
                int((time.time() - latest_timestamp) / 86400)
            )

            if days == 0:
                recent_activity = True

        funded = data.get('chain_stats', {}).get('funded_txo_sum', 0) / 1e8
        spent = data.get('chain_stats', {}).get('spent_txo_sum', 0) / 1e8

        balance = funded - spent

        dust_percentage = (
            (dust_tx_count / total_tx) * 100
            if total_tx > 0 else 0
        )

        return {

            'network': 'bitcoin',
            'currency': 'BTC',

            'total_tx': total_tx,

            'small_tx_count': small_tx_count,
            'dust_tx_count': dust_tx_count,
            'dust_percentage': dust_percentage,

            'large_tx_count': large_tx_count,

            'max_tx_amount': max_amount,
            'total_volume': total_volume,

            'last_active_days': days,
            'recent_activity': recent_activity,

            'balance': balance,

            'outgoing_tx_count': outgoing_tx_count,
            'unique_outgoing_addresses': len(unique_outgoing_addresses),

            'is_real_data': True
        }

    except Exception as e:

        return {
            'error': str(e)
        }

# ─────────────────────────────────────────────────────────────────────────────
# FRAUD DETECTION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def detect_fraud(wallet_address, wallet_data):

    risk_score = 0
    reasons = []

    if wallet_data.get('error'):
        return "CANT_ANALYZE", 0, [wallet_data['error']]

    # BLACKLIST CHECK

    if wallet_address in KNOWN_BLACKLIST:

        threat = KNOWN_BLACKLIST[wallet_address]

        risk_score = max(risk_score, threat['risk'])

        reasons.append(
            f"🚨 BLACKLISTED: {threat['label']}"
        )

    network = wallet_data.get('network')
    total_tx = wallet_data.get('total_tx', 0)

    # DUST ANALYSIS

    dust_percentage = wallet_data.get('dust_percentage', 0)
    dust_count = wallet_data.get('dust_tx_count', 0)

    if dust_percentage > 50 and dust_count > 20:

        risk_score += 35

        reasons.append(
            f"Heavy dust activity ({dust_percentage:.0f}% dust txs)"
        )

    elif dust_percentage > 30:

        risk_score += 20

        reasons.append(
            "Suspicious dusting behavior"
        )

    # OUTGOING PATTERNS

    outgoing_tx = wallet_data.get('outgoing_tx_count', 0)
    unique_outgoing = wallet_data.get('unique_outgoing_addresses', 0)

    if outgoing_tx > 100 and unique_outgoing > 50:

        risk_score += 35

        reasons.append(
            "Potential laundering pattern"
        )

    elif outgoing_tx > 50:

        risk_score += 20

        reasons.append(
            "High outgoing transaction activity"
        )

    # LOW BALANCE + HIGH ACTIVITY

    balance = wallet_data.get('balance', 0)

    if balance < 0.001 and total_tx > 25:

        risk_score += 20

        reasons.append(
            "Possible pass-through/mixer wallet"
        )

    # LARGE TRANSACTIONS

    max_amt = wallet_data.get('max_tx_amount', 0)

    if network == 'bitcoin':

        if max_amt > 100:
            risk_score += 20

        elif max_amt > 10:
            risk_score += 10

    else:

        if max_amt > 10000:
            risk_score += 20

        elif max_amt > 1000:
            risk_score += 10

    # EXTREME VOLUME

    volume = wallet_data.get('total_volume', 0)

    if network == 'bitcoin':

        if volume > 10000:
            risk_score += 30

        elif volume > 1000:
            risk_score += 15

    else:

        if volume > 100000:
            risk_score += 30

        elif volume > 10000:
            risk_score += 15

    # RECENT ACTIVITY

    if wallet_data.get('recent_activity'):
        risk_score += 5

    # NEW WALLET

    if total_tx == 0:
        risk_score += 5

    elif total_tx < 5:
        risk_score += 3

    risk_score = min(100, risk_score)

    # FINAL CLASSIFICATION

    if risk_score >= 75:
        risk_level = "HIGH RISK ⚠️"

    elif risk_score >= 45:
        risk_level = "MEDIUM RISK ⚡"

    elif risk_score >= 20:
        risk_level = "LOW RISK 📊"

    else:
        risk_level = "VERY LOW RISK ✅"

    if not reasons:
        reasons.append("No suspicious patterns detected")

    return risk_level, risk_score, reasons

# ─────────────────────────────────────────────────────────────────────────────
# MAIN FETCHER
# ─────────────────────────────────────────────────────────────────────────────

def get_wallet_data(wallet_address):

    network = detect_network(wallet_address)

    if network == 'ethereum':
        return get_ethereum_wallet_data(wallet_address)

    elif network == 'bitcoin':
        return get_bitcoin_wallet_data(wallet_address)

    return {'error': 'Invalid wallet address'}

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check_wallet', methods=['POST'])
def check_wallet():

    try:

        data = request.get_json()

        wallet = data.get('wallet', '').strip()

        if not wallet:
            return jsonify({'error': 'Wallet required'})

        network = detect_network(wallet)

        if not network:
            return jsonify({'error': 'Invalid wallet format'})

        real_data = get_wallet_data(wallet)

        if real_data.get('error'):
            return jsonify({'error': real_data['error']})

        risk_level, risk_score, reasons = detect_fraud(
            wallet,
            real_data
        )

        currency = real_data.get('currency', 'ETH')

        decimals = 8 if currency == 'BTC' else 2

        volume_format = (
            f"{real_data['total_volume']:.{decimals}f} {currency}"
        )

        max_format = (
            f"{real_data['max_tx_amount']:.{decimals}f}"
        )

        days = real_data['last_active_days']

        if days == 999:
            last_active = "No transactions"

        elif days == 0:
            last_active = "Today"

        elif days == 1:
            last_active = "1 day ago"

        else:
            last_active = f"{days} days ago"

        return jsonify({

            'wallet': wallet,

            'network': network,
            'currency': currency,

            'risk_level': risk_level,
            'risk_score': risk_score,

            'reasons': reasons,

            'transactions_found': real_data['total_tx'],

            'total_volume': volume_format,

            'last_active': last_active,

            'small_tx_count': real_data['small_tx_count'],
            'dust_tx_count': real_data['dust_tx_count'],
            'large_tx_count': real_data['large_tx_count'],

            'max_tx_amount': max_format,

            'balance': (
                f"{real_data.get('balance', 0):.8f} BTC"
                if currency == 'BTC'
                else None
            ),

            'outgoing_tx_count': real_data.get(
                'outgoing_tx_count',
                0
            ),

            'unique_outgoing': real_data.get(
                'unique_outgoing_addresses',
                0
            ),

            'is_real_data': real_data['is_real_data']
        })

    except Exception as e:

        return jsonify({
            'error': str(e)
        })

# ─────────────────────────────────────────────────────────────────────────────
# API TEST
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/test_api')
def test_api():

    eth_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()

    valid, msg = test_etherscan_api_key(eth_key)

    return jsonify({

        'etherscan_valid': valid,
        'etherscan_message': msg,

        'groq_configured': bool(
            os.environ.get('GROQ_API_KEY')
        )
    })

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':

    port = int(os.environ.get('PORT', 5000))

    print("=" * 60)
    print("🔒 CryptoShield AI")
    print("=" * 60)

    app.run(
        host='0.0.0.0',
        port=port,
        debug=True
    )