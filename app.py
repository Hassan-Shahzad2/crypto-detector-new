import os
from flask import Flask, render_template, request, jsonify
import requests
import time
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

def test_api_key(api_key):
    """Test if API key is valid"""
    test_wallet = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5"
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={test_wallet}&tag=latest&apikey={api_key}"
    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        if data.get('status') == '1':
            return True, "Valid"
        else:
            return False, data.get('result', 'Invalid API key')
    except Exception as e:
        return False, str(e)

def get_real_wallet_data(wallet_address):
    YOUR_API_KEY = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    
    # Check if API key is provided
    if not YOUR_API_KEY:
        return {
            'total_tx': 0,
            'small_tx_count': 0,
            'large_tx_count': 0,
            'max_tx_amount': 0,
            'total_volume': 0,
            'last_active_days': 999,
            'is_real_data': False,
            'error': 'No API key found. Please set ETHERSCAN_API_KEY in .env file'
        }
    
    # Validate wallet address
    if not wallet_address.startswith('0x') or len(wallet_address) != 42:
        return {
            'total_tx': 0,
            'small_tx_count': 0,
            'large_tx_count': 0,
            'max_tx_amount': 0,
            'total_volume': 0,
            'last_active_days': 999,
            'is_real_data': False,
            'error': 'Invalid wallet address format'
        }
    
    # Try the API
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={wallet_address}&startblock=0&endblock=99999999&sort=desc&apikey={YOUR_API_KEY}"
    
    try:
        print(f"Fetching data for wallet: {wallet_address}")
        response = requests.get(url, timeout=10)
        data = response.json()
        
        # Check for API errors
        if data.get('message') == 'NOTOK':
            error_msg = data.get('result', 'Unknown error')
            print(f"API Error: {error_msg}")
            
            # Provide helpful error messages
            if 'Invalid API Key' in error_msg:
                return {
                    'total_tx': 0,
                    'small_tx_count': 0,
                    'large_tx_count': 0,
                    'max_tx_amount': 0,
                    'total_volume': 0,
                    'last_active_days': 999,
                    'is_real_data': False,
                    'error': 'Invalid API key. Please get a valid key from https://etherscan.io/register'
                }
            elif 'rate limit' in error_msg.lower():
                return {
                    'total_tx': 0,
                    'small_tx_count': 0,
                    'large_tx_count': 0,
                    'max_tx_amount': 0,
                    'total_volume': 0,
                    'last_active_days': 999,
                    'is_real_data': False,
                    'error': 'Rate limit exceeded. Please wait a few seconds and try again.'
                }
            else:
                return {
                    'total_tx': 0,
                    'small_tx_count': 0,
                    'large_tx_count': 0,
                    'max_tx_amount': 0,
                    'total_volume': 0,
                    'last_active_days': 999,
                    'is_real_data': False,
                    'error': f'API Error: {error_msg}'
                }
        
        if data['status'] == '1' and data['result']:
            transactions = data['result']
            total_tx = len(transactions)
            
            amounts = []
            small_tx_count = 0
            large_tx_count = 0
            max_amount = 0
            total_volume_eth = 0
            
            for tx in transactions[:100]:
                try:
                    amount = int(tx['value']) / 1000000000000000000
                    amounts.append(amount)
                    total_volume_eth += amount
                    
                    if amount < 0.01:
                        small_tx_count += 1
                    if amount > 10:
                        large_tx_count += 1
                    if amount > max_amount:
                        max_amount = amount
                except (ValueError, KeyError):
                    continue
            
            if transactions:
                try:
                    last_timestamp = int(transactions[0]['timeStamp'])
                    days_since_active = (time.time() - last_timestamp) / 86400
                except (ValueError, KeyError):
                    days_since_active = 999
            else:
                days_since_active = 999
            
            return {
                'total_tx': total_tx,
                'small_tx_count': small_tx_count,
                'large_tx_count': large_tx_count,
                'max_tx_amount': max_amount,
                'total_volume': total_volume_eth,
                'last_active_days': int(days_since_active) if days_since_active < 999 else 999,
                'is_real_data': True
            }
        else:
            return {
                'total_tx': 0,
                'small_tx_count': 0,
                'large_tx_count': 0,
                'max_tx_amount': 0,
                'total_volume': 0,
                'last_active_days': 999,
                'is_real_data': True
            }
            
    except requests.exceptions.Timeout:
        return {
            'total_tx': 0,
            'small_tx_count': 0,
            'large_tx_count': 0,
            'max_tx_amount': 0,
            'total_volume': 0,
            'last_active_days': 999,
            'is_real_data': False,
            'error': 'Request timeout - Etherscan took too long to respond'
        }
    except Exception as e:
        print(f"Error: {e}")
        return {
            'total_tx': 0,
            'small_tx_count': 0,
            'large_tx_count': 0,
            'max_tx_amount': 0,
            'total_volume': 0,
            'last_active_days': 999,
            'is_real_data': False,
            'error': f'Connection error: {str(e)}'
        }

def detect_fraud(wallet_data):
    risk_score = 0
    reasons = []
    
    if wallet_data.get('error'):
        return "⚪ CAN'T ANALYZE", 0, [f"Error: {wallet_data['error']}"]
    
    if wallet_data['small_tx_count'] > 20:
        risk_score += 40
        reasons.append(f"🚨 {wallet_data['small_tx_count']} tiny transactions - Possible dusting attack!")
    elif wallet_data['small_tx_count'] > 10:
        risk_score += 20
        reasons.append(f"⚠️ {wallet_data['small_tx_count']} small transactions - Be careful")
    
    if wallet_data['max_tx_amount'] > 50000:
        risk_score += 50
        reasons.append(f"💰 Massive transaction of {wallet_data['max_tx_amount']:,.2f} ETH - Very suspicious!")
    elif wallet_data['max_tx_amount'] > 10000:
        risk_score += 30
        reasons.append(f"💵 Large transaction of {wallet_data['max_tx_amount']:,.2f} ETH - Unusual activity")
    
    if wallet_data['last_active_days'] == 0:
        risk_score += 25
        reasons.append("⏰ Wallet active in last 24 hours - Recent scam possible")
    elif wallet_data['last_active_days'] < 3:
        risk_score += 10
        reasons.append("📅 Recent activity - Exercise caution")
    
    if wallet_data['total_tx'] == 0:
        risk_score += 15
        reasons.append("🆕 Brand new wallet - No transaction history")
    
    if wallet_data['total_volume'] > 100000:
        risk_score += 35
        reasons.append(f"💎 Huge total volume: {wallet_data['total_volume']:,.2f} ETH - Whale alert!")
    elif wallet_data['total_volume'] > 10000:
        risk_score += 20
        reasons.append(f"📊 High total volume: {wallet_data['total_volume']:,.2f} ETH")
    
    if wallet_data['large_tx_count'] > 5:
        risk_score += 25
        reasons.append(f"⚠️ {wallet_data['large_tx_count']} large transactions - Suspicious pattern")
    
    if risk_score >= 60:
        return "🔴 HIGH RISK", min(100, risk_score), reasons
    elif risk_score >= 30:
        return "🟠 MEDIUM RISK", risk_score, reasons
    else:
        return "🟢 LOW RISK", risk_score, reasons if reasons else ["No suspicious patterns detected"]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check_wallet', methods=['POST'])
def check_wallet():
    try:
        data = request.get_json()
        wallet_address = data.get('wallet', '').strip()
        
        if not wallet_address:
            return jsonify({'error': 'Please enter a wallet address'})
        
        real_data = get_real_wallet_data(wallet_address)
        
        if real_data.get('error'):
            return jsonify({'error': real_data['error']})
        
        risk_level, risk_score, reasons = detect_fraud(real_data)
        
        volume_display = f"{real_data['total_volume']:.2f} ETH" if real_data['total_volume'] > 0 else "0 ETH"
        
        return jsonify({
            'wallet': wallet_address,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'reasons': reasons,
            'transactions_found': real_data['total_tx'],
            'total_volume': volume_display,
            'last_active': real_data['last_active_days'],
            'is_real_data': real_data['is_real_data']
        })
    except Exception as e:
        print(f"Error in check_wallet: {e}")
        return jsonify({'error': f'Server error: {str(e)}'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)