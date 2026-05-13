import os
import sys

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

from flask import Flask, render_template, request, jsonify
import requests
import time
from dotenv import load_dotenv
import re

load_dotenv()
app = Flask(__name__)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST')
    return response

# ─── HELPER FUNCTIONS ────────────────────────────────────────────────────────

def validate_ethereum_address(address):
    return address.startswith('0x') and len(address) == 42 and all(c in '0123456789abcdefABCDEF' for c in address[2:])

def validate_bitcoin_address(address):
    address = address.strip()
    # P2PKH (starts with 1)
    if re.match(r'^1[1-9A-HJ-NP-Za-km-z]{25,34}$', address):
        return True
    # P2SH (starts with 3)
    if re.match(r'^3[1-9A-HJ-NP-Za-km-z]{25,34}$', address):
        return True
    # Bech32 (starts with bc1)
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

# ─── ETHERSCAN (ETHEREUM) ────────────────────────────────────────────────────

def test_etherscan_api_key(api_key):
    if not api_key or api_key == 'YOUR_API_KEY_HERE':
        return False, "No API key provided"
    test_wallet = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5"
    url = f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=balance&address={test_wallet}&tag=latest&apikey={api_key}"
    try:
        r = requests.get(url, timeout=10)
        d = r.json()
        if d.get('status') == '1':
            return True, "Valid"
        err = d.get('result', 'Unknown error')
        return False, "Invalid API key" if 'Invalid API Key' in err else err
    except Exception as e:
        return False, str(e)

def get_ethereum_wallet_data(wallet_address):
    api_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    if not api_key:
        return {'error': 'No Etherscan API key configured', 'is_real_data': False,
                'total_tx': 0, 'small_tx_count': 0, 'dust_tx_count': 0, 'large_tx_count': 0,
                'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999}

    url = (f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist"
           f"&address={wallet_address}&startblock=0&endblock=99999999&sort=desc&apikey={api_key}")
    try:
        print(f"Fetching Ethereum wallet: {wallet_address}")
        r = requests.get(url, timeout=15)
        d = r.json()

        if d.get('message') == 'NOTOK':
            err = d.get('result', 'Unknown error')
            if 'rate limit' in err.lower():
                err = 'Rate limit exceeded. Please wait and try again.'
            return {'error': err, 'is_real_data': False, 'total_tx': 0,
                    'small_tx_count': 0, 'dust_tx_count': 0, 'large_tx_count': 0,
                    'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999}

        if d.get('status') == '1' and d.get('result'):
            txs = d['result']
            total_tx = len(txs)
            small_tx_count = 0
            dust_tx_count = 0
            large_tx_count = 0
            max_amount = 0
            total_volume = 0
            recent_activity = False

            for tx in txs[:500]:
                try:
                    amt = int(tx['value']) / 1e18
                    if amt > 0:
                        total_volume += amt
                        if amt < 0.0001:  # ETH dust threshold
                            dust_tx_count += 1
                        if amt < 0.01:  # Small tx
                            small_tx_count += 1
                        if amt > 10:  # Large tx
                            large_tx_count += 1
                        if amt > max_amount:
                            max_amount = amt
                except:
                    continue

            days = 999
            if txs:
                try:
                    days = max(0, int((int(time.time()) - int(txs[0]['timeStamp'])) / 86400))
                    if days == 0:
                        recent_activity = True
                except:
                    pass

            print(f"Found {total_tx} ETH txs, {total_volume:.2f} ETH")
            return {'total_tx': total_tx, 'small_tx_count': small_tx_count,
                    'dust_tx_count': dust_tx_count, 'large_tx_count': large_tx_count,
                    'max_tx_amount': max_amount, 'total_volume': total_volume,
                    'last_active_days': days, 'recent_activity': recent_activity,
                    'is_real_data': True, 'network': 'ethereum', 'currency': 'ETH'}

        return {'total_tx': 0, 'small_tx_count': 0, 'dust_tx_count': 0, 'large_tx_count': 0,
                'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999,
                'recent_activity': False, 'is_real_data': True,
                'network': 'ethereum', 'currency': 'ETH'}

    except Exception as e:
        return {'error': str(e), 'is_real_data': False, 'total_tx': 0,
                'small_tx_count': 0, 'dust_tx_count': 0, 'large_tx_count': 0,
                'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999}

# ─── BLOCKSTREAM (BITCOIN) ────────────────────────────────────────────────────

def get_bitcoin_wallet_data(wallet_address):
    """Fetch Bitcoin wallet data using Blockstream API"""
    try:
        print(f"Fetching Bitcoin wallet: {wallet_address}")
        
        # Get address info
        url = f"https://blockstream.info/api/address/{wallet_address}"
        r = requests.get(url, timeout=15)
        
        if r.status_code == 404:
            return {'error': 'Bitcoin address not found or has no transactions', 'is_real_data': False,
                    'total_tx': 0, 'small_tx_count': 0, 'dust_tx_count': 0, 'large_tx_count': 0,
                    'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999}
        
        if r.status_code != 200:
            return {'error': f'Blockstream API error: {r.status_code}', 'is_real_data': False,
                    'total_tx': 0, 'small_tx_count': 0, 'dust_tx_count': 0, 'large_tx_count': 0,
                    'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999}
        
        data = r.json()
        
        # Get transactions
        tx_url = f"https://blockstream.info/api/address/{wallet_address}/txs"
        tx_r = requests.get(tx_url, timeout=15)
        
        if tx_r.status_code != 200:
            return {'error': 'Failed to fetch transactions', 'is_real_data': False,
                    'total_tx': 0, 'small_tx_count': 0, 'dust_tx_count': 0, 'large_tx_count': 0,
                    'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999}
        
        txs = tx_r.json()
        
        total_tx = len(txs) if isinstance(txs, list) else 0
        small_tx_count = 0
        dust_tx_count = 0
        large_tx_count = 0
        max_amount = 0
        total_volume = 0
        latest_timestamp = 0
        
        # Track outgoing transactions
        outgoing_tx_count = 0
        unique_outgoing_addresses = set()
        
        # Process transactions
        for tx in txs[:500]:
            # Determine if this wallet is sending or receiving
            is_sending = False
            tx_value = 0
            
            # Check inputs (sending)
            for vin in tx.get('vin', []):
                if 'prevout' in vin and vin['prevout'].get('scriptpubkey_address') == wallet_address:
                    is_sending = True
                    amount_sent = vin['prevout'].get('value', 0) / 1e8
                    if amount_sent > 0:
                        tx_value -= amount_sent
            
            # Check outputs (receiving)
            for vout in tx.get('vout', []):
                if 'scriptpubkey_address' in vout:
                    if vout['scriptpubkey_address'] == wallet_address:
                        amount_received = vout['value'] / 1e8
                        tx_value += amount_received
                    elif is_sending:
                        unique_outgoing_addresses.add(vout['scriptpubkey_address'])
            
            if is_sending:
                outgoing_tx_count += 1
            
            abs_value = abs(tx_value)
            if abs_value > 0:
                total_volume += abs_value
                
                # Dust threshold for Bitcoin (very small amounts)
                if abs_value < 0.00001:  # < 1,000 satoshis - suspicious dust
                    dust_tx_count += 1
                if abs_value < 0.001:  # Small tx (< 100,000 satoshis)
                    small_tx_count += 1
                if abs_value > 1.0:  # Large tx (>1 BTC)
                    large_tx_count += 1
                if abs_value > max_amount:
                    max_amount = abs_value
            
            # Track timestamp
            if tx.get('status', {}).get('block_time', 0) > latest_timestamp:
                latest_timestamp = tx['status']['block_time']
        
        # Calculate days since last activity
        days = 999
        recent_activity = False
        if latest_timestamp > 0:
            days = max(0, int((time.time() - latest_timestamp) / 86400))
            if days == 0:
                recent_activity = True
        
        # Get current balance
        funded_txo_sum = data.get('chain_stats', {}).get('funded_txo_sum', 0) / 1e8
        spent_txo_sum = data.get('chain_stats', {}).get('spent_txo_sum', 0) / 1e8
        balance = funded_txo_sum - spent_txo_sum
        
        # Calculate dust percentage (indicator of address poisoning)
        dust_percentage = (dust_tx_count / total_tx * 100) if total_tx > 0 else 0
        
        print(f"Found {total_tx} BTC txs, Volume: {total_volume:.8f} BTC, Dust: {dust_tx_count} ({dust_percentage:.1f}%)")
        
        return {
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
            'is_real_data': True,
            'network': 'bitcoin',
            'currency': 'BTC'
        }
        
    except Exception as e:
        print(f"Bitcoin API error: {e}")
        return {'error': f'Bitcoin API error: {str(e)}', 'is_real_data': False, 'total_tx': 0,
                'small_tx_count': 0, 'dust_tx_count': 0, 'large_tx_count': 0,
                'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999}

# ─── FRAUD DETECTION - BALANCED AND REALISTIC ────────────────────────────────

def detect_fraud(wallet_data):
    risk_score = 0
    reasons = []
    
    if wallet_data.get('error'):
        return "CANT_ANALYZE", 0, [wallet_data['error']]
    
    network = wallet_data.get('network', 'ethereum')
    currency = wallet_data.get('currency', 'ETH')
    
    total_tx = wallet_data.get('total_tx', 0)
    
    # ===== DUSTING / ADDRESS POISONING DETECTION =====
    # Only suspicious if there's a HIGH percentage of dust transactions
    dust_count = wallet_data.get('dust_tx_count', 0)
    dust_percentage = wallet_data.get('dust_percentage', 0)
    
    if total_tx > 0:
        if dust_percentage > 50 and dust_count > 20:
            risk_score += 45
            reasons.append(f"🔴 HIGH: {dust_count} dust transactions ({dust_percentage:.0f}% of total) — Strong address poisoning indicators")
        elif dust_percentage > 30 and dust_count > 15:
            risk_score += 30
            reasons.append(f"⚠️ WARNING: {dust_count} dust transactions ({dust_percentage:.0f}% of total) — Suspicious pattern")
        elif dust_percentage > 15 and dust_count > 10:
            risk_score += 15
            reasons.append(f"NOTICE: {dust_count} dust transactions ({dust_percentage:.0f}% of total) — Monitor for address poisoning")
    
    # ===== OUTGOING TRANSACTION PATTERNS =====
    outgoing_tx = wallet_data.get('outgoing_tx_count', 0)
    unique_outgoing = wallet_data.get('unique_outgoing_addresses', 0)
    
    if outgoing_tx > 100 and unique_outgoing > 50:
        risk_score += 40
        reasons.append(f"🔴 HIGH: {outgoing_tx} outgoing transactions to {unique_outgoing} unique addresses — Money laundering pattern")
    elif outgoing_tx > 50 and unique_outgoing > 30:
        risk_score += 25
        reasons.append(f"⚠️ WARNING: High volume of outgoing transactions to diverse addresses")
    elif outgoing_tx > 20 and unique_outgoing > 15:
        risk_score += 10
        reasons.append(f"NOTICE: Multiple outgoing transactions to different addresses")
    
    # ===== BALANCE ANALYSIS =====
    balance = wallet_data.get('balance', 0)
    if balance < 0.001 and total_tx > 20:  # Very low balance but high activity
        risk_score += 25
        reasons.append("⚠️ Active wallet with near-zero balance — Possible pass-through / mixer address")
    
    # ===== LARGE TRANSACTIONS =====
    max_amt = wallet_data.get('max_tx_amount', 0)
    if network == 'bitcoin':
        if max_amt > 100:
            risk_score += 25
            reasons.append(f"LARGE: Single transaction of {max_amt:.2f} BTC — Unusual")
        elif max_amt > 10:
            risk_score += 10
            reasons.append(f"NOTICE: Large transaction of {max_amt:.2f} BTC")
    else:
        if max_amt > 10000:
            risk_score += 25
            reasons.append(f"LARGE: Single transaction of {max_amt:.2f} ETH")
        elif max_amt > 1000:
            risk_score += 10
            reasons.append(f"NOTICE: Large transaction of {max_amt:.2f} ETH")
    
    # ===== RECENT ACTIVITY =====
    if wallet_data.get('recent_activity'):
        risk_score += 5
        reasons.append("Active in last 24 hours")
    
    # ===== NEW WALLET =====
    if total_tx == 0:
        risk_score += 10
        reasons.append("Brand new wallet — No transaction history (exercise caution)")
    elif total_tx < 5:
        risk_score += 3
        reasons.append("New wallet with few transactions")
    
    # ===== TOTAL VOLUME =====
    volume = wallet_data.get('total_volume', 0)
    if network == 'bitcoin':
        if volume > 500:
            risk_score += 20
            reasons.append(f"HIGH volume: {volume:.2f} BTC")
        elif volume > 100:
            risk_score += 10
            reasons.append(f"Notable volume: {volume:.2f} BTC")
    
    # Cap the risk score
    risk_score = min(100, risk_score)
    
    # Determine risk level
    if risk_score >= 60:
        return "HIGH RISK ⚠️", risk_score, reasons
    elif risk_score >= 35:
        return "MEDIUM RISK ⚡", risk_score, reasons
    elif risk_score >= 15:
        return "LOW RISK 📊", risk_score, reasons
    return "VERY LOW RISK ✅", risk_score, reasons if reasons else ["No suspicious patterns detected"]

# ─── MAIN DATA FETCHER ──────────────────────────────────────────────────────

def get_wallet_data(wallet_address):
    wallet_address = wallet_address.strip()
    network = detect_network(wallet_address)
    
    if network == 'ethereum':
        return get_ethereum_wallet_data(wallet_address)
    elif network == 'bitcoin':
        return get_bitcoin_wallet_data(wallet_address)
    else:
        return {'error': 'Invalid wallet address format. Please enter a valid Ethereum (0x...) or Bitcoin address (1..., 3..., or bc1...).', 
                'is_real_data': False,
                'total_tx': 0, 'small_tx_count': 0, 'dust_tx_count': 0, 'large_tx_count': 0,
                'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999}


# ─── ROUTES ──────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/check_wallet', methods=['POST'])
def check_wallet():
    try:
        data = request.get_json()
        wallet = data.get('wallet', '').strip()
        
        if not wallet:
            return jsonify({'error': 'Please enter a wallet address'})
        
        network = detect_network(wallet)
        if not network:
            return jsonify({'error': 'Invalid format — Please enter a valid Ethereum or Bitcoin address'})
        
        real_data = get_wallet_data(wallet)
        
        if real_data.get('error'):
            return jsonify({'error': real_data['error']})
        
        risk_level, risk_score, reasons = detect_fraud(real_data)
        
        currency = real_data.get('currency', 'ETH')
        decimals = 8 if currency == 'BTC' else 2
        volume_format = f"{real_data['total_volume']:.{decimals}f} {currency}" if real_data['total_volume'] > 0 else f"0 {currency}"
        max_format = f"{real_data['max_tx_amount']:.{decimals}f}" if real_data['max_tx_amount'] > 0 else "0"
        
        days = real_data['last_active_days']
        last_active = ("No transactions" if days == 999
                       else "Today" if days == 0
                       else "1 day ago" if days == 1
                       else f"{days} days ago")
        
        balance_info = {}
        if 'balance' in real_data and real_data['balance'] > 0:
            balance_info['balance'] = f"{real_data['balance']:.8f} BTC"
        
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
            'dust_tx_count': real_data.get('dust_tx_count', 0),
            'large_tx_count': real_data['large_tx_count'],
            'max_tx_amount': max_format,
            'outgoing_tx_count': real_data.get('outgoing_tx_count', 0),
            'unique_outgoing': real_data.get('unique_outgoing_addresses', 0),
            'is_real_data': real_data['is_real_data'],
            **balance_info
        })
        
    except Exception as e:
        print(f"Error in check_wallet: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'})


@app.route('/agent', methods=['POST'])
def agent():
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        context      = data.get('context', '')
        api_key      = os.environ.get('GROQ_API_KEY', '').strip()

        if not api_key:
            return jsonify({'error': 'NO_KEY'}), 500
        if not user_message:
            return jsonify({'error': 'Empty message'}), 400

        system_prompt = (
            "You are ShieldAI, an expert blockchain security agent. Help users understand "
            "Ethereum and Bitcoin wallet risks, crypto scams, dusting attacks, and blockchain security. "
            "Be concise and clear. Keep answers under 150 words. Never give financial advice."
        )
        if context:
            system_prompt += f"\n\nLatest wallet scan context: {context}"

        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_message}
            ],
            "max_tokens": 512,
            "temperature": 0.7
        }

        res = requests.post(url, headers=headers, json=payload, timeout=20)

        if res.status_code == 200:
            result = res.json()
            reply = result['choices'][0]['message']['content'].strip()
            return jsonify({'reply': reply})
        elif res.status_code == 401:
            return jsonify({'error': 'INVALID_KEY'}), 401
        elif res.status_code == 429:
            return jsonify({'error': 'RATE_LIMIT'}), 429
        else:
            return jsonify({'error': f'Groq error {res.status_code}'}), 500

    except Exception as e:
        print(f"Agent error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/test_api', methods=['GET'])
def test_api():
    eth_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    groq_key = os.environ.get('GROQ_API_KEY', '').strip()
    is_valid, msg = test_etherscan_api_key(eth_key)
    
    bitcoin_working = False
    try:
        test_btc_addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        r = requests.get(f"https://blockstream.info/api/address/{test_btc_addr}", timeout=5)
        bitcoin_working = r.status_code == 200
    except:
        pass
    
    return jsonify({
        'etherscan_valid': is_valid,
        'etherscan_message': msg,
        'groq_configured': bool(groq_key),
        'bitcoin_api_working': bitcoin_working
    })


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("\n" + "=" * 60)
    print("🔒 CryptoShield — Fraud Detection System (Ethereum + Bitcoin)")
    print("=" * 60)

    eth_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    groq_key = os.environ.get('GROQ_API_KEY', '').strip()

    if eth_key:
        valid, msg = test_etherscan_api_key(eth_key)
        print(f"🟣 Etherscan : {'✅ OK' if valid else '❌ INVALID'}")
    else:
        print("🟣 Etherscan : ⚠️ NOT CONFIGURED")

    if groq_key:
        print(f"🤖 Groq AI   : ✅ Configured")
    else:
        print("🤖 Groq AI   : ⚠️ NOT CONFIGURED")
    
    print("🟠 Bitcoin   : Using Blockstream API (free, no key needed)")
    
    print(f"🌐 Server    : http://localhost:{port}")
    print("=" * 60)
    print("\n✨ Balanced fraud detection enabled:")
    print("   • Dust percentage based detection (not just raw count)")
    print("   • Realistic thresholds for normal wallets")
    print("   • Pass-through wallet identification")
    print("   • Outgoing transaction pattern analysis")
    print("\n" + "=" * 60 + "\n")

    app.run(host='0.0.0.0', port=port, debug=True)