import os
import sys

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

from flask import Flask, render_template, request, jsonify
import requests
import time
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST')
    return response

# ─── ETHERSCAN ────────────────────────────────────────────────────────────────

def test_api_key(api_key):
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


def get_real_wallet_data(wallet_address):
    api_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    if not api_key:
        return {'error': 'No Etherscan API key configured', 'is_real_data': False,
                'total_tx': 0, 'small_tx_count': 0, 'large_tx_count': 0,
                'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999}
    if not wallet_address.startswith('0x') or len(wallet_address) != 42:
        return {'error': 'Invalid wallet address format', 'is_real_data': False,
                'total_tx': 0, 'small_tx_count': 0, 'large_tx_count': 0,
                'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999}

    url = (f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist"
           f"&address={wallet_address}&startblock=0&endblock=99999999&sort=desc&apikey={api_key}")
    try:
        print(f"Fetching wallet: {wallet_address}")
        r = requests.get(url, timeout=15)
        d = r.json()

        if d.get('message') == 'NOTOK':
            err = d.get('result', 'Unknown error')
            if 'rate limit' in err.lower():
                err = 'Rate limit exceeded. Please wait and try again.'
            return {'error': err, 'is_real_data': False, 'total_tx': 0,
                    'small_tx_count': 0, 'large_tx_count': 0,
                    'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999}

        if d.get('status') == '1' and d.get('result'):
            txs = d['result']
            total_tx = len(txs)
            small_tx_count = large_tx_count = max_amount = total_volume = 0
            recent_activity = False

            for tx in txs[:500]:
                try:
                    amt = int(tx['value']) / 1e18
                    if amt > 0:
                        total_volume += amt
                        if amt < 0.01:
                            small_tx_count += 1
                        if amt > 10:
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

            print(f"Found {total_tx} txs, {total_volume:.2f} ETH")
            return {'total_tx': total_tx, 'small_tx_count': small_tx_count,
                    'large_tx_count': large_tx_count, 'max_tx_amount': max_amount,
                    'total_volume': total_volume, 'last_active_days': days,
                    'recent_activity': recent_activity, 'is_real_data': True}

        return {'total_tx': 0, 'small_tx_count': 0, 'large_tx_count': 0,
                'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999,
                'recent_activity': False, 'is_real_data': True}

    except requests.exceptions.Timeout:
        return {'error': 'Request timeout', 'is_real_data': False, 'total_tx': 0,
                'small_tx_count': 0, 'large_tx_count': 0,
                'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999}
    except Exception as e:
        return {'error': str(e), 'is_real_data': False, 'total_tx': 0,
                'small_tx_count': 0, 'large_tx_count': 0,
                'max_tx_amount': 0, 'total_volume': 0, 'last_active_days': 999}


def detect_fraud(wallet_data):
    risk_score = 0
    reasons = []
    if wallet_data.get('error'):
        return "CANT_ANALYZE", 0, [wallet_data['error']]

    sc = wallet_data['small_tx_count']
    if sc > 50:   risk_score += 45; reasons.append(f"CRITICAL: {sc} micro-transactions (<0.01 ETH) — Classic dusting attack pattern")
    elif sc > 20: risk_score += 30; reasons.append(f"HIGH: {sc} small transactions — Possible dusting attack")
    elif sc > 10: risk_score += 15; reasons.append(f"WARNING: {sc} micro-transactions — Unusual pattern")

    mx = wallet_data['max_tx_amount']
    if mx > 100000:   risk_score += 60; reasons.append(f"EXTREME: Single tx of {mx:,.2f} ETH — Highly suspicious")
    elif mx > 50000:  risk_score += 45; reasons.append(f"MASSIVE: {mx:,.2f} ETH transaction — Very suspicious")
    elif mx > 10000:  risk_score += 30; reasons.append(f"LARGE: {mx:,.2f} ETH transaction — Unusual")
    elif mx > 1000:   risk_score += 15; reasons.append(f"NOTABLE: {mx:,.2f} ETH transaction")

    if wallet_data.get('recent_activity'):
        risk_score += 35; reasons.append("CRITICAL: Wallet active in last 24 hours")
    elif wallet_data['last_active_days'] < 3:
        risk_score += 15; reasons.append("Recent activity within 3 days — Exercise caution")
    elif wallet_data['last_active_days'] < 7:
        risk_score += 5;  reasons.append("Active within last week")

    tx = wallet_data['total_tx']
    if tx == 0:   risk_score += 25; reasons.append("Brand new wallet — No transaction history")
    elif tx < 5:  risk_score += 10; reasons.append("New wallet with very few transactions")

    vol = wallet_data['total_volume']
    if vol > 500000:   risk_score += 50; reasons.append(f"EXTREME volume: {vol:,.2f} ETH")
    elif vol > 100000: risk_score += 35; reasons.append(f"HIGH volume: {vol:,.2f} ETH")
    elif vol > 10000:  risk_score += 20; reasons.append(f"Notable volume: {vol:,.2f} ETH")

    lc = wallet_data['large_tx_count']
    if lc > 10:  risk_score += 35; reasons.append(f"CRITICAL: {lc} large transactions (>10 ETH)")
    elif lc > 5: risk_score += 20; reasons.append(f"WARNING: {lc} large transactions — Unusual pattern")
    elif lc > 2: risk_score += 10; reasons.append(f"{lc} large transactions detected")

    risk_score = min(100, risk_score)
    if risk_score >= 70:   return "HIGH RISK",      risk_score, reasons
    elif risk_score >= 40: return "MEDIUM RISK",    risk_score, reasons
    elif risk_score >= 15: return "LOW RISK",       risk_score, reasons
    return "VERY LOW RISK", risk_score, reasons if reasons else ["No suspicious patterns detected"]


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
        if not wallet.startswith('0x') or len(wallet) != 42:
            return jsonify({'error': 'Invalid format — must be 42 characters starting with 0x'})

        real_data = get_real_wallet_data(wallet)
        if real_data.get('error'):
            return jsonify({'error': real_data['error']})

        risk_level, risk_score, reasons = detect_fraud(real_data)
        vol = f"{real_data['total_volume']:.2f} ETH" if real_data['total_volume'] > 0 else "0 ETH"
        days = real_data['last_active_days']
        last_active = ("No transactions" if days == 999
                       else "Today" if days == 0
                       else "1 day ago" if days == 1
                       else f"{days} days ago")

        return jsonify({
            'wallet': wallet,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'reasons': reasons,
            'transactions_found': real_data['total_tx'],
            'total_volume': vol,
            'last_active': last_active,
            'small_tx_count': real_data['small_tx_count'],
            'large_tx_count': real_data['large_tx_count'],
            'max_tx_amount': f"{real_data['max_tx_amount']:.4f}" if real_data['max_tx_amount'] > 0 else "0",
            'is_real_data': real_data['is_real_data']
        })
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'})


@app.route('/agent', methods=['POST'])
def agent():
    """Proxy Groq (Llama3) API calls — fast, free, no domain restrictions"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        context      = data.get('context', '')
        api_key      = os.environ.get('GROQ_API_KEY', '').strip()

        # Debug logging
        print(f"GROQ_API_KEY present: {bool(api_key)}")
        if api_key:
            print(f"GROQ_API_KEY length: {len(api_key)}")
            print(f"GROQ_API_KEY prefix: {api_key[:10]}...")

        if not api_key:
            return jsonify({'error': 'NO_KEY'}), 500
        if not user_message:
            return jsonify({'error': 'Empty message'}), 400

        system_prompt = (
            "You are ShieldAI, an expert blockchain security agent inside CryptoShield — "
            "a crypto fraud detection platform. Help users understand Ethereum wallet risks, "
            "crypto scams, dusting attacks, and blockchain security. "
            "Be concise and clear. Keep answers under 150 words. "
            "Never give financial advice. Be friendly and professional."
        )
        if context:
            system_prompt += f"\n\nLatest wallet scan context: {context}"

        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "llama-3.1-8b-instant",  # Updated to a known working model
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_message}
            ],
            "max_tokens": 512,
            "temperature": 0.7
        }

        print(f"Groq request to model: {payload['model']}")
        print(f"User message: {user_message[:60]}...")
        res = requests.post(url, headers=headers, json=payload, timeout=20)
        print(f"Groq response status: {res.status_code}")
        
        # Log response details for debugging
        if res.status_code != 200:
            print(f"Groq error response: {res.text[:500]}")

        if res.status_code == 200:
            result = res.json()
            reply = result['choices'][0]['message']['content'].strip()
            print(f"Groq reply received: {reply[:80]}...")
            return jsonify({'reply': reply})
        elif res.status_code == 401:
            return jsonify({'error': 'INVALID_KEY'}), 401
        elif res.status_code == 429:
            return jsonify({'error': 'RATE_LIMIT'}), 429
        else:
            err_text = res.text[:200]
            print(f"Groq error: {err_text}")
            return jsonify({'error': f'Groq error {res.status_code}: {err_text}'}), 500

    except requests.exceptions.Timeout:
        return jsonify({'error': 'TIMEOUT'}), 500
    except Exception as e:
        print(f"Agent error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/test_api', methods=['GET'])
def test_api():
    eth_key   = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    groq_key  = os.environ.get('GROQ_API_KEY', '').strip()
    is_valid, msg = test_api_key(eth_key)
    
    # Test Groq API key format
    groq_valid = bool(groq_key and groq_key.startswith('gsk_') and len(groq_key) > 20)
    
    return jsonify({
        'etherscan_valid': is_valid,
        'etherscan_message': msg,
        'groq_configured': bool(groq_key),
        'groq_valid_format': groq_valid,
        'groq_key_length': len(groq_key) if groq_key else 0
    })


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("\n" + "=" * 50)
    print("CryptoShield — Fraud Detection System")
    print("=" * 50)

    eth_key  = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    groq_key = os.environ.get('GROQ_API_KEY', '').strip()

    if eth_key:
        valid, msg = test_api_key(eth_key)
        print(f"Etherscan : {'OK' if valid else 'INVALID — ' + msg}")
    else:
        print("Etherscan : NOT CONFIGURED")

    if groq_key:
        print(f"Groq AI   : Configured (length: {len(groq_key)})")
        if not groq_key.startswith('gsk_'):
            print("⚠️  Warning: Groq API key should start with 'gsk_'")
    else:
        print("Groq AI   : NOT CONFIGURED — add GROQ_API_KEY to .env")
    
    print(f"Server    : http://localhost:{port}")
    print("=" * 50 + "\n")

    app.run(host='0.0.0.0', port=port, debug=True)