import os
import sys
import json
import re
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from functools import wraps
from collections import defaultdict
import hashlib

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

from flask import Flask, render_template, request, jsonify, session
import requests
from dotenv import load_dotenv
from threading import Lock
from datetime import timedelta

load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Creator Information
CREATOR_INFO = {
    'name': 'Muhammad Hassan Shahzad',
    'age': 22,
    'university': 'Iqra University',
    'cgpa': 3.72,
    'degree': 'BS Computer Science',
    'favourite food': 'Biryani',
    'girlfriend':'Lol, thats a secret',
    'skills': ['Python', 'Flask', 'Blockchain', 'Web Development', 'Networking' , 'Data Analysis'],
    'interests': ['Blockchain Security', 'AI Fraud Detection', 'Cryptocurrency Forensics', 'Cybersecurity', 'Machine Learning' , 'Data Sciences'],
    'bio': 'A passionate 22-year-old computer science student at Iqra University with a strong focus on blockchain security and AI-powered fraud detection systems. Currently maintaining a 3.72 CGPA while building innovative security solutions.',
    'achievements': [
        'Built CryptoShield AI - an advanced blockchain fraud detection system',
        'Specialized in Ethereum and Bitcoin transaction analysis',
        'Expert in identifying dusting attacks and money laundering patterns',
        'Developed AI-powered wallet risk assessment algorithms'
    ],

    'email': 'mhsmk589@gmail.com',
    'location': 'Karachi, Pakistan'
}

# Rate limiting
rate_limits = defaultdict(list)
RATE_LIMIT = 30
RATE_WINDOW = 60

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        window_start = now - RATE_WINDOW
        
        rate_limits[ip] = [t for t in rate_limits[ip] if t > window_start]
        
        if len(rate_limits[ip]) >= RATE_LIMIT:
            return jsonify({'error': 'RATE_LIMIT', 'message': 'Too many requests. Please wait a moment.'}), 429
        
        rate_limits[ip].append(now)
        return f(*args, **kwargs)
    return decorated_function

# Cache for API calls
api_cache = {}
cache_lock = Lock()

# ─── HELPER FUNCTIONS ────────────────────────────────────────────────────────

def validate_ethereum_address(address: str) -> bool:
    return address.startswith('0x') and len(address) == 42 and all(c in '0123456789abcdefABCDEF' for c in address[2:])

def validate_bitcoin_address(address: str) -> bool:
    address = address.strip()
    if re.match(r'^1[1-9A-HJ-NP-Za-km-z]{25,34}$', address):
        return True
    if re.match(r'^3[1-9A-HJ-NP-Za-km-z]{25,34}$', address):
        return True
    if re.match(r'^(bc1)[a-zA-HJ-NP-Z0-9]{39,59}$', address):
        return True
    return False

def detect_network(address: str) -> Optional[str]:
    address = address.strip()
    if address.startswith('0x') and len(address) == 42:
        return 'ethereum'
    elif validate_bitcoin_address(address):
        return 'bitcoin'
    return None

def get_with_cache(url: str, ttl: int = 300) -> Optional[Dict]:
    cache_key = hashlib.md5(url.encode()).hexdigest()
    with cache_lock:
        if cache_key in api_cache:
            cached_data, timestamp = api_cache[cache_key]
            if time.time() - timestamp < ttl:
                return cached_data
            del api_cache[cache_key]
    
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            with cache_lock:
                api_cache[cache_key] = (data, time.time())
            return data
    except Exception as e:
        print(f"Cache fetch error: {e}")
    return None

def normalize_risk_score(score: int) -> Dict:
    score = max(0, min(100, score))
    if score >= 70:
        return {'level': 'CRITICAL RISK', 'color': '#ef4444', 'icon': '🚨', 'class': 'critical'}
    elif score >= 50:
        return {'level': 'HIGH RISK', 'color': '#f59e0b', 'icon': '⚠️', 'class': 'high'}
    elif score >= 25:
        return {'level': 'MEDIUM RISK', 'color': '#eab308', 'icon': '⚡', 'class': 'medium'}
    elif score >= 10:
        return {'level': 'LOW RISK', 'color': '#06b6d4', 'icon': '📊', 'class': 'low'}
    else:
        return {'level': 'VERY LOW RISK', 'color': '#10b981', 'icon': '✅', 'class': 'safe'}

# ─── ETHERSCAN (ETHEREUM) ────────────────────────────────────────────────────

def get_ethereum_wallet_data(wallet_address: str) -> Dict:
    api_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    if not api_key:
        return {'error': 'No Etherscan API key configured', 'is_real_data': False}
    
    url = (f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist"
           f"&address={wallet_address}&startblock=0&endblock=99999999&sort=desc&apikey={api_key}")
    
    try:
        data = get_with_cache(url, ttl=120)
        if not data:
            return {'error': 'Failed to fetch data', 'is_real_data': False}
        
        if data.get('message') == 'NOTOK':
            return {'error': data.get('result', 'Unknown error'), 'is_real_data': False}
        
        if data.get('status') == '1' and data.get('result'):
            txs = data['result']
            if isinstance(txs, list) and len(txs) > 0:
                return _process_ethereum_transactions(txs, wallet_address)
        
        return _empty_ethereum_data()
        
    except Exception as e:
        print(f"Etherscan error: {e}")
        return {'error': str(e), 'is_real_data': False}

def _process_ethereum_transactions(txs: List[Dict], wallet_address: str) -> Dict:
    total_tx = len(txs)
    small_tx_count = 0
    dust_tx_count = 0
    large_tx_count = 0
    max_amount = 0
    total_volume = 0
    total_received = 0
    total_sent = 0
    incoming_tx_count = 0
    outgoing_tx_count = 0
    unique_senders = set()
    unique_receivers = set()
    last_active_timestamp = 0
    hourly_activity = [0] * 24
    
    for tx in txs[:1000]:
        try:
            value = int(tx.get('value', '0')) / 1e18
            timestamp = int(tx.get('timeStamp', 0))
            if timestamp > 0:
                hour = datetime.fromtimestamp(timestamp).hour
                if 0 <= hour < 24:
                    hourly_activity[hour] += 1
            
            if timestamp > last_active_timestamp:
                last_active_timestamp = timestamp
            
            to_addr = tx.get('to', '').lower() if tx.get('to') else ''
            from_addr = tx.get('from', '').lower() if tx.get('from') else ''
            wallet_lower = wallet_address.lower()
            
            if to_addr == wallet_lower:
                incoming_tx_count += 1
                total_received += value
                if from_addr:
                    unique_senders.add(from_addr)
            elif from_addr == wallet_lower:
                outgoing_tx_count += 1
                total_sent += value
                if to_addr:
                    unique_receivers.add(to_addr)
            
            total_volume += value
            
            if value < 0.0001:
                dust_tx_count += 1
            if value < 0.01:
                small_tx_count += 1
            if value > 10:
                large_tx_count += 1
            if value > max_amount:
                max_amount = value
        except Exception as e:
            continue
    
    days_inactive = 999
    if last_active_timestamp > 0:
        days_inactive = max(0, int((time.time() - last_active_timestamp) / 86400))
    
    balance = _get_eth_balance(wallet_address)
    
    return {
        'total_tx': total_tx,
        'incoming_tx_count': incoming_tx_count,
        'outgoing_tx_count': outgoing_tx_count,
        'small_tx_count': small_tx_count,
        'dust_tx_count': dust_tx_count,
        'large_tx_count': large_tx_count,
        'max_tx_amount': max_amount,
        'total_volume': total_volume,
        'total_received': total_received,
        'total_sent': total_sent,
        'unique_senders': len(unique_senders),
        'unique_receivers': len(unique_receivers),
        'last_active_days': days_inactive,
        'recent_activity': days_inactive == 0,
        'balance': balance,
        'activity_hours': hourly_activity,
        'network': 'ethereum',
        'currency': 'ETH',
        'is_real_data': True
    }

def _get_eth_balance(wallet_address: str) -> float:
    api_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    if not api_key:
        return 0
    url = f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=balance&address={wallet_address}&tag=latest&apikey={api_key}"
    try:
        data = get_with_cache(url, ttl=60)
        if data and data.get('status') == '1':
            result = data.get('result', '0')
            if isinstance(result, str):
                return int(result) / 1e18
            return float(result) / 1e18
    except:
        pass
    return 0

def _empty_ethereum_data() -> Dict:
    return {
        'total_tx': 0, 'incoming_tx_count': 0, 'outgoing_tx_count': 0,
        'small_tx_count': 0, 'dust_tx_count': 0, 'large_tx_count': 0,
        'max_tx_amount': 0, 'total_volume': 0, 'total_received': 0,
        'total_sent': 0, 'unique_senders': 0, 'unique_receivers': 0,
        'last_active_days': 999, 'recent_activity': False, 'balance': 0,
        'activity_hours': [0]*24, 'network': 'ethereum', 'currency': 'ETH',
        'is_real_data': True
    }

# ─── BLOCKSTREAM (BITCOIN) ────────────────────────────────────────────────────

def get_bitcoin_wallet_data(wallet_address: str) -> Dict:
    try:
        url = f"https://blockstream.info/api/address/{wallet_address}"
        data = get_with_cache(url, ttl=120)
        
        if not data:
            return {'error': 'Bitcoin address not found', 'is_real_data': False}
        
        tx_url = f"https://blockstream.info/api/address/{wallet_address}/txs"
        txs_data = get_with_cache(tx_url, ttl=120)
        
        if not txs_data:
            return {'error': 'Failed to fetch transactions', 'is_real_data': False}
        
        return _process_bitcoin_transactions(txs_data, data, wallet_address)
        
    except Exception as e:
        print(f"Bitcoin API error: {e}")
        return {'error': str(e), 'is_real_data': False}

def _process_bitcoin_transactions(txs: List[Dict], address_data: Dict, wallet_address: str) -> Dict:
    total_tx = len(txs) if isinstance(txs, list) else 0
    small_tx_count = 0
    dust_tx_count = 0
    large_tx_count = 0
    max_amount = 0
    total_volume = 0
    total_received = 0
    total_sent = 0
    incoming_tx_count = 0
    outgoing_tx_count = 0
    unique_senders = set()
    unique_receivers = set()
    last_active_timestamp = 0
    hourly_activity = [0] * 24
    
    for tx in txs[:500]:
        try:
            timestamp = tx.get('status', {}).get('block_time', 0)
            if timestamp > last_active_timestamp:
                last_active_timestamp = timestamp
            
            if timestamp > 0:
                hour = datetime.fromtimestamp(timestamp).hour
                if 0 <= hour < 24:
                    hourly_activity[hour] += 1
            
            is_sending = False
            tx_value = 0
            wallet_lower = wallet_address.lower()
            
            for vin in tx.get('vin', []):
                prevout = vin.get('prevout', {})
                if prevout.get('scriptpubkey_address', '').lower() == wallet_lower:
                    is_sending = True
                    amount_sent = prevout.get('value', 0) / 1e8
                    if amount_sent > 0:
                        tx_value -= amount_sent
                        total_sent += amount_sent
                        outgoing_tx_count += 1
            
            for vout in tx.get('vout', []):
                addr = vout.get('scriptpubkey_address', '')
                if addr and addr.lower() == wallet_lower:
                    amount_received = vout.get('value', 0) / 1e8
                    tx_value += amount_received
                    total_received += amount_received
                    incoming_tx_count += 1
                elif is_sending and addr:
                    unique_receivers.add(addr)
            
            abs_value = abs(tx_value)
            if abs_value > 0:
                total_volume += abs_value
                if abs_value < 0.00001:
                    dust_tx_count += 1
                if abs_value < 0.001:
                    small_tx_count += 1
                if abs_value > 1.0:
                    large_tx_count += 1
                if abs_value > max_amount:
                    max_amount = abs_value
        except Exception as e:
            continue
    
    days_inactive = 999
    if last_active_timestamp > 0:
        days_inactive = max(0, int((time.time() - last_active_timestamp) / 86400))
    
    funded_txo_sum = address_data.get('chain_stats', {}).get('funded_txo_sum', 0) / 1e8
    spent_txo_sum = address_data.get('chain_stats', {}).get('spent_txo_sum', 0) / 1e8
    balance = funded_txo_sum - spent_txo_sum
    
    return {
        'total_tx': total_tx,
        'incoming_tx_count': incoming_tx_count,
        'outgoing_tx_count': outgoing_tx_count,
        'small_tx_count': small_tx_count,
        'dust_tx_count': dust_tx_count,
        'large_tx_count': large_tx_count,
        'max_tx_amount': max_amount,
        'total_volume': total_volume,
        'total_received': total_received,
        'total_sent': total_sent,
        'unique_senders': len(unique_senders),
        'unique_receivers': len(unique_receivers),
        'last_active_days': days_inactive,
        'recent_activity': days_inactive == 0,
        'balance': balance,
        'activity_hours': hourly_activity,
        'network': 'bitcoin',
        'currency': 'BTC',
        'is_real_data': True
    }

# ─── AI FRAUD DETECTION ────────────────────────────────────────────────────────

def get_ai_fraud_analysis(wallet_data: Dict, wallet_address: str) -> Dict:
    api_key = os.environ.get('GROQ_API_KEY', '').strip()
    if not api_key:
        return _rule_based_fraud_detection(wallet_data)
    
    prompt = _build_ai_analysis_prompt(wallet_data, wallet_address)
    
    try:
        response = _call_groq_api(prompt, api_key)
        if response:
            return _parse_ai_response(response, wallet_data)
    except Exception as e:
        print(f"AI analysis error: {e}")
    
    return _rule_based_fraud_detection(wallet_data)

def _build_ai_analysis_prompt(wallet_data: Dict, wallet_address: str) -> str:
    network = wallet_data.get('network', 'unknown')
    currency = wallet_data.get('currency', 'unknown')
    
    return f"""You are a blockchain forensic expert. Analyze this {network.upper()} wallet for fraud.

WALLET: {wallet_address}
NETWORK: {network.upper()}

METRICS:
- Total transactions: {wallet_data.get('total_tx', 0)}
- Incoming: {wallet_data.get('incoming_tx_count', 0)}
- Outgoing: {wallet_data.get('outgoing_tx_count', 0)}
- Unique senders: {wallet_data.get('unique_senders', 0)}
- Unique receivers: {wallet_data.get('unique_receivers', 0)}
- Dust transactions: {wallet_data.get('dust_tx_count', 0)}
- Small transactions: {wallet_data.get('small_tx_count', 0)}
- Large transactions: {wallet_data.get('large_tx_count', 0)}
- Max transaction: {wallet_data.get('max_tx_amount', 0):.4f} {currency}
- Total volume: {wallet_data.get('total_volume', 0):.2f} {currency}
- Total received: {wallet_data.get('total_received', 0):.2f} {currency}
- Total sent: {wallet_data.get('total_sent', 0):.2f} {currency}
- Current balance: {wallet_data.get('balance', 0):.8f} {currency}
- Days inactive: {wallet_data.get('last_active_days', 999)}
- Recent activity: {wallet_data.get('recent_activity', False)}

Respond in JSON only:
{{
    "risk_score": 0-100,
    "fraud_types": [],
    "reasons": [],
    "recommendation": "",
    "pattern_description": ""
}}"""

def _call_groq_api(prompt: str, api_key: str) -> Optional[str]:
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": "You are a blockchain forensic expert. Respond only in valid JSON format. Do not use markdown formatting like **bold** or *italic*. Use plain text only."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 800,
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=25)
        if response.status_code == 200:
            result = response.json()
            return result['choices'][0]['message']['content']
    except Exception as e:
        print(f"Groq API error: {e}")
    return None

def _parse_ai_response(ai_response: str, wallet_data: Dict) -> Dict:
    try:
        ai_response = re.sub(r'```json\s*|\s*```', '', ai_response.strip())
        analysis = json.loads(ai_response)
        
        risk_score = max(0, min(100, int(analysis.get('risk_score', 50))))
        normalized = normalize_risk_score(risk_score)
        
        return {
            'risk_level': normalized['level'],
            'risk_score': risk_score,
            'fraud_types': analysis.get('fraud_types', []),
            'reasons': analysis.get('reasons', ['Analysis complete']),
            'recommendation': analysis.get('recommendation', 'Exercise normal caution.'),
            'pattern_description': analysis.get('pattern_description', 'Standard wallet activity'),
            'confidence': 'HIGH',
            'is_ai_analysis': True
        }
    except json.JSONDecodeError:
        return _rule_based_fraud_detection(wallet_data)

def _rule_based_fraud_detection(wallet_data: Dict) -> Dict:
    risk_score = 0
    reasons = []
    fraud_types = []
    
    total_tx = wallet_data.get('total_tx', 0)
    dust_count = wallet_data.get('dust_tx_count', 0)
    unique_receivers = wallet_data.get('unique_receivers', 0)
    balance = wallet_data.get('balance', 0)
    total_volume = wallet_data.get('total_volume', 0)
    outgoing_count = wallet_data.get('outgoing_tx_count', 0)
    
    if total_tx == 0:
        return {
            'risk_level': 'VERY LOW RISK',
            'risk_score': 0,
            'fraud_types': ['No transaction history'],
            'reasons': ['No transaction history found for this wallet'],
            'recommendation': 'This wallet has no transaction history. Exercise normal caution.',
            'pattern_description': 'Inactive wallet with no transaction history.',
            'confidence': 'HIGH',
            'is_ai_analysis': False
        }
    
    if total_tx > 0:
        dust_percentage = (dust_count / total_tx) * 100
        if dust_percentage > 40 and dust_count > 15:
            risk_score += 45
            reasons.append(f"🚨 {dust_count} dust transactions ({dust_percentage:.0f}% of total) — Strong address poisoning indicators")
            fraud_types.append("dusting attack")
        elif dust_percentage > 20 and dust_count > 10:
            risk_score += 30
            reasons.append(f"⚠️ {dust_count} dust transactions ({dust_percentage:.0f}% of total) — Suspicious dusting pattern")
            fraud_types.append("potential dusting attack")
    
    if outgoing_count > 50 and unique_receivers > 30:
        risk_score += 35
        reasons.append(f"🔴 {outgoing_count} outgoing transactions to {unique_receivers} unique addresses — Money laundering pattern")
        fraud_types.append("money laundering")
    elif outgoing_count > 20 and unique_receivers > 15:
        risk_score += 20
        reasons.append(f"⚠️ High volume of outgoing transactions to diverse addresses")
        fraud_types.append("unusual transaction pattern")
    
    if balance < 0.001 and total_volume > 10 and total_tx > 20:
        risk_score += 30
        reasons.append("🔄 Active wallet with near-zero balance — Possible mixing service")
        fraud_types.append("mixing service usage")
    
    risk_score = min(100, risk_score)
    normalized = normalize_risk_score(risk_score)
    
    if not reasons:
        reasons = ["No suspicious patterns detected in transaction history"]
    if not fraud_types:
        fraud_types = ["normal activity"]
    
    return {
        'risk_level': normalized['level'],
        'risk_score': risk_score,
        'fraud_types': list(set(fraud_types)),
        'reasons': reasons,
        'recommendation': _get_recommendation(risk_score),
        'pattern_description': _get_pattern_description(risk_score, fraud_types),
        'confidence': 'HIGH' if total_tx > 50 else 'MEDIUM',
        'is_ai_analysis': False
    }

def _get_recommendation(risk_score: int) -> str:
    if risk_score >= 70:
        return "🚨 CRITICAL: DO NOT interact with this wallet. High probability of fraudulent activity. Report immediately to blockchain security platforms."
    elif risk_score >= 50:
        return "⚠️ HIGH RISK: Exercise extreme caution. Verify all information independently before any transaction. Consider using escrow services."
    elif risk_score >= 25:
        return "⚡ MEDIUM RISK: Some concerning patterns detected. Verify addresses carefully and start with small test transactions."
    elif risk_score >= 10:
        return "📊 LOW RISK: Minor concerns detected. Use standard security practices."
    return "✅ SAFE: Normal activity detected. Continue practicing good security hygiene."

def _get_pattern_description(risk_score: int, fraud_types: List[str]) -> str:
    if risk_score >= 70:
        return f"This wallet exhibits critical risk patterns including {', '.join(fraud_types[:3])}. Immediate action advised."
    elif risk_score >= 50:
        return f"High-risk transaction patterns detected: {', '.join(fraud_types[:2])}. Further investigation strongly recommended."
    elif risk_score >= 25:
        return "Unusual transaction patterns detected. Standard security precautions recommended."
    elif risk_score >= 10:
        return "Minor anomalies detected in transaction history. Normal security practices sufficient."
    return "Transaction patterns appear normal with no significant red flags."

# ─── WALLET HISTORY ───────────────────────────────────────────────────────────

def get_wallet_history() -> List[Dict]:
    return session.get('wallet_history', [])

def add_to_history(wallet_address: str, scan_data: Dict) -> None:
    history = session.get('wallet_history', [])
    
    for i, item in enumerate(history):
        if item['wallet'] == wallet_address:
            history.pop(i)
            break
    
    history.insert(0, {
        'wallet': wallet_address,
        'network': scan_data.get('network'),
        'risk_level': scan_data.get('risk_level'),
        'risk_score': scan_data.get('risk_score'),
        'timestamp': datetime.now().isoformat()
    })
    
    session['wallet_history'] = history[:20]
    session.permanent = True

# ─── FLASK ROUTES ───────────────────────────────────────────────────────────

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST')
    return response

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/creator', methods=['GET'])
def creator_info():
    """Get information about the creator Muhammad Hassan Shahzad"""
    return jsonify(CREATOR_INFO)

@app.route('/check_wallet', methods=['POST'])
@rate_limit
def check_wallet():
    try:
        data = request.get_json()
        wallet = data.get('wallet', '').strip()
        
        if not wallet:
            return jsonify({'error': 'Please enter a wallet address'})
        
        network = detect_network(wallet)
        if not network:
            return jsonify({'error': 'Invalid format — Please enter a valid Ethereum or Bitcoin address'})
        
        if network == 'ethereum':
            raw_data = get_ethereum_wallet_data(wallet)
        else:
            raw_data = get_bitcoin_wallet_data(wallet)
        
        if raw_data.get('error'):
            return jsonify({'error': raw_data['error']})
        
        ai_analysis = get_ai_fraud_analysis(raw_data, wallet)
        
        currency = raw_data.get('currency', 'ETH')
        decimals = 8 if currency == 'BTC' else 4
        
        last_active = "Never" if raw_data.get('last_active_days', 999) == 999 else \
                      "Today" if raw_data.get('last_active_days', 999) == 0 else \
                      f"{raw_data.get('last_active_days')} days ago"
        
        result = {
            'wallet': wallet,
            'network': network,
            'currency': currency,
            'risk_level': ai_analysis['risk_level'],
            'risk_score': ai_analysis['risk_score'],
            'fraud_types': ai_analysis['fraud_types'],
            'confidence': ai_analysis.get('confidence', 'MEDIUM'),
            'reasons': ai_analysis['reasons'],
            'recommendation': ai_analysis['recommendation'],
            'pattern_description': ai_analysis['pattern_description'],
            'transactions_found': raw_data.get('total_tx', 0),
            'total_volume': f"{raw_data.get('total_volume', 0):.{decimals}f} {currency}",
            'total_received': f"{raw_data.get('total_received', 0):.{decimals}f} {currency}",
            'total_sent': f"{raw_data.get('total_sent', 0):.{decimals}f} {currency}",
            'last_active': last_active,
            'small_tx_count': raw_data.get('small_tx_count', 0),
            'dust_tx_count': raw_data.get('dust_tx_count', 0),
            'large_tx_count': raw_data.get('large_tx_count', 0),
            'max_tx_amount': f"{raw_data.get('max_tx_amount', 0):.{decimals}f}",
            'incoming_tx_count': raw_data.get('incoming_tx_count', 0),
            'outgoing_tx_count': raw_data.get('outgoing_tx_count', 0),
            'unique_senders': raw_data.get('unique_senders', 0),
            'unique_receivers': raw_data.get('unique_receivers', 0),
            'balance': f"{raw_data.get('balance', 0):.8f} {currency}" if raw_data.get('balance', 0) > 0 else None,
            'is_ai_analysis': ai_analysis.get('is_ai_analysis', False)
        }
        
        add_to_history(wallet, result)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error in check_wallet: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Server error: {str(e)}'})

@app.route('/agent', methods=['POST'])
@rate_limit
def agent():
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip().lower()
        context = data.get('context', '')
        api_key = os.environ.get('GROQ_API_KEY', '').strip()

        if not api_key:
            return jsonify({'error': 'NO_KEY'}), 500
        if not user_message:
            return jsonify({'error': 'Empty message'}), 400

        # Check if user is asking about the creator
        creator_keywords = ['who built you', 'who created you', 'who made you', 'your creator', 'about the creator', 
                           'tell me about the creator', 'who is the developer', 'who developed you', 'hassan', 
                           'muhammad hassan', 'creator of this tool', 'who programmed you', 'author of cryptoshield']
        
        if any(keyword in user_message for keyword in creator_keywords):
            creator = CREATOR_INFO
            reply = f"""🌟 About My Creator - Muhammad Hassan Shahzad 🌟

Muhammad Hassan Shahzad is a {creator['age']}-year-old passionate Computer Science student at {creator['university']}, maintaining an impressive {creator['cgpa']} CGPA.

📚 Education: {creator['degree']} at {creator['university']}
💻 Skills: {', '.join(creator['skills'][:6])}
🎯 Interests: {', '.join(creator['interests'])}
📍 Location: {creator['location']}

🏆 Key Achievements:
- Built CryptoShield AI - Advanced blockchain fraud detection system
- Specialized in Ethereum and Bitcoin transaction analysis
- Expert in identifying dusting attacks and money laundering patterns

✨ He built me with a vision to make blockchain security accessible to everyone, using cutting-edge AI technology to detect crypto fraud in real-time.

💡 Fun fact: He maintains a 3.72 CGPA while building innovative security solutions like me!

Feel free to ask me more about Hassan's work or anything about crypto security! 🛡️"""
            return jsonify({'reply': reply})

        # Handle wallet scan analysis requests
        analyze_keywords = ['analyze the last wallet', 'explain the scan', 'what does the scan show', 
                           'interpret the results', 'scan analysis', 'wallet analysis']
        
        if any(keyword in user_message for keyword in analyze_keywords) and context and 'No wallet scanned' not in context:
            reply = f"""📊 Wallet Scan Analysis

Based on the scan data:
{context}

Key Findings:
- Risk Level: The wallet shows specific patterns that require attention
- Transaction History: Analyzed for suspicious activity
- Fraud Indicators: Checked against known scam patterns

Recommendations:
- Always verify addresses before sending transactions
- Use hardware wallets for large amounts
- Enable 2FA on all exchange accounts
- Never share private keys or seed phrases

For specific details about this wallet's risk score and fraud types, please check the scan results above.

Need more clarification? Ask me specific questions about the findings! 🛡️"""
            return jsonify({'reply': reply})

        if len(context) > 2000:
            context = context[:2000] + "..."
        
        system_prompt = f"""You are ShieldAI, a blockchain security expert created by Muhammad Hassan Shahzad (22-year-old CS student at Iqra University, 3.72 CGPA).

Important formatting rules:
- NEVER use markdown like **bold** or *italic*
- Use plain text only with line breaks
- Use emojis for emphasis instead of markdown
- Keep responses concise and clear

Your role:
- Analyze wallet addresses for fraud patterns
- Explain crypto scams clearly
- Provide security recommendations
- When asked, proudly share that you were built by Muhammad Hassan Shahzad

Creator Info (Muhammad Hassan Shahzad):
- Age: 22 years old
- University: Iqra University (BS Computer Science)
- CGPA: 3.72
- Skills: Python, Flask, Blockchain, AI/ML, Web Development, Smart Contract Security
- Passion: Blockchain security and AI-powered fraud detection
- Favourite Food: Biryani
- Girlfriend: Lol, that is a secret

Guidelines:
- Be concise (150-300 words)
- Use bullet points with dashes (-)
- Never give financial advice
- Reference scan data if provided

{context if context else 'No recent scan context. Be helpful and friendly.'}"""
        
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            "max_tokens": 800,
            "temperature": 0.7
        }

        res = requests.post(url, headers=headers, json=payload, timeout=25)

        if res.status_code == 200:
            result = res.json()
            reply = result['choices'][0]['message']['content'].strip()
            # Remove any remaining markdown bold/italic markers
            reply = re.sub(r'\*\*([^*]+)\*\*', r'\1', reply)
            reply = re.sub(r'\*([^*]+)\*', r'\1', reply)
            reply = re.sub(r'__([^_]+)__', r'\1', reply)
            reply = re.sub(r'_([^_]+)_', r'\1', reply)
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

@app.route('/history', methods=['GET'])
def get_history():
    return jsonify({'history': get_wallet_history()})

@app.route('/clear_history', methods=['POST'])
def clear_history():
    session.pop('wallet_history', None)
    return jsonify({'success': True})

@app.route('/test_api', methods=['GET'])
def test_api():
    eth_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    groq_key = os.environ.get('GROQ_API_KEY', '').strip()
    
    eth_valid = False
    eth_msg = "Not configured"
    if eth_key:
        test_wallet = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5"
        url = f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=balance&address={test_wallet}&tag=latest&apikey={eth_key}"
        try:
            r = requests.get(url, timeout=10)
            d = r.json()
            if d.get('status') == '1':
                eth_valid = True
                eth_msg = "Valid"
            else:
                eth_msg = "Invalid API key"
        except Exception as e:
            eth_msg = str(e)
    
    btc_working = False
    try:
        test_btc_addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        r = requests.get(f"https://blockstream.info/api/address/{test_btc_addr}", timeout=5)
        btc_working = r.status_code == 200
    except:
        pass
    
    groq_valid = False
    if groq_key:
        try:
            url = "https://api.groq.com/openai/v1/models"
            headers = {"Authorization": f"Bearer {groq_key}"}
            r = requests.get(url, headers=headers, timeout=10)
            groq_valid = r.status_code == 200
        except:
            pass
    
    return jsonify({
        'etherscan_valid': eth_valid,
        'etherscan_message': eth_msg,
        'bitcoin_api_working': btc_working,
        'groq_configured': bool(groq_key),
        'groq_valid': groq_valid,
        'ai_enabled': groq_valid
    })

# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    
    print("\n" + "=" * 70)
    print("🛡️  CryptoShield AI — Blockchain Fraud Detection System")
    print("=" * 70)
    print("\n👨‍💻 CREATOR: Muhammad Hassan Shahzad")
    print(f"   • Age: {CREATOR_INFO['age']} years")
    print(f"   • University: {CREATOR_INFO['university']}")
    print(f"   • CGPA: {CREATOR_INFO['cgpa']}")
    print(f"   • Degree: {CREATOR_INFO['degree']}")
    
    eth_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    groq_key = os.environ.get('GROQ_API_KEY', '').strip()
    
    print("\n🔌 API STATUS:")
    print(f"   🟣 Etherscan API : {'✅ CONFIGURED' if eth_key else '⚠️ NOT CONFIGURED'}")
    print(f"   🤖 Groq AI API   : {'✅ CONFIGURED' if groq_key else '⚠️ NOT CONFIGURED'}")
    print("   🟠 Bitcoin API   : ✅ FREE (Blockstream.info)")
    
    print("\n🌐 SERVER:")
    print(f"   • http://localhost:{port}")
    print(f"   • http://0.0.0.0:{port}")
    
    print("\n⚡ FEATURES:")
    print("   • Real-time ETH & BTC analysis")
    print("   • Wallet scan history")
    print("   • AI chatbot assistant")
    print("   • Rate limiting protection")
    print("   • Creator info integration")
    
    print("\n" + "=" * 70)
    print("✨ System ready! Ask me 'Who built you?' to learn about my creator!\n")
    
    app.run(host='0.0.0.0', port=port, debug=True)