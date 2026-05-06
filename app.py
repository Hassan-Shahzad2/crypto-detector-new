import os
from flask import Flask, render_template, request, jsonify
import requests
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# THIS IS HOW WE ACTUALLY CHECK REAL WALLETS
def get_real_wallet_data(wallet_address):
    """
    This function calls Etherscan API to get REAL transaction data
    It's like asking the blockchain: "Hey, what has this wallet done?"
    """
    
    # Get API key from environment variable (SAFE WAY)
    YOUR_API_KEY = os.environ.get('ETHERSCAN_API_KEY', '')
    
    # If no API key, show error
    if not YOUR_API_KEY:
        print("ERROR: Please set ETHERSCAN_API_KEY environment variable")
        return {
            'total_tx': 0,
            'small_tx_count': 0,
            'large_tx_count': 0,
            'max_tx_amount': 0,
            'total_volume': 0,
            'last_active_days': 999,
            'is_real_data': False,
            'error': 'API key not configured'
        }
    
    # Validate wallet address format
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
    
    # CORRECT Etherscan API URL
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={wallet_address}&startblock=0&endblock=99999999&sort=desc&apikey={YOUR_API_KEY}"
    
    try:
        print(f"Fetching data for wallet: {wallet_address}")
        response = requests.get(url, timeout=10)
        data = response.json()
        
        # Check if API returned an error
        if data.get('status') == '0':
            error_msg = data.get('message', 'Unknown error')
            print(f"API Error: {error_msg}")
            if 'No transactions found' in error_msg:
                # Wallet exists but has no transactions
                return {
                    'total_tx': 0,
                    'small_tx_count': 0,
                    'large_tx_count': 0,
                    'max_tx_amount': 0,
                    'total_volume': 0,
                    'last_active_days': 999,
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
                    'is_real_data': False,
                    'error': error_msg
                }
        
        if data['status'] == '1' and data['result']:
            transactions = data['result']
            
            # Calculate statistics from REAL data
            total_tx = len(transactions)
            
            # Convert from wei to ETH (crypto math)
            amounts = []
            small_tx_count = 0
            large_tx_count = 0
            max_amount = 0
            total_volume_eth = 0
            
            for tx in transactions[:100]:  # Check last 100 transactions
                try:
                    amount = int(tx['value']) / 1000000000000000000  # Convert wei to ETH
                    amounts.append(amount)
                    total_volume_eth += amount
                    
                    if amount < 0.01:  # Less than 0.01 ETH is "small"
                        small_tx_count += 1
                    if amount > 10:    # More than 10 ETH is "large"
                        large_tx_count += 1
                    if amount > max_amount:
                        max_amount = amount
                except (ValueError, KeyError):
                    continue
            
            # How many days since last transaction?
            if transactions:
                try:
                    last_timestamp = int(transactions[0]['timeStamp'])
                    days_since_active = (time.time() - last_timestamp) / 86400  # 86400 seconds in a day
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
            # Wallet has no transactions - it's new!
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
        print(f"Timeout error for wallet {wallet_address}")
        return {
            'total_tx': 0,
            'small_tx_count': 0,
            'large_tx_count': 0,
            'max_tx_amount': 0,
            'total_volume': 0,
            'last_active_days': 999,
            'is_real_data': False,
            'error': 'Request timeout'
        }
    except Exception as e:
        print(f"Error: {e}")
        # If API fails, return empty data
        return {
            'total_tx': 0,
            'small_tx_count': 0,
            'large_tx_count': 0,
            'max_tx_amount': 0,
            'total_volume': 0,
            'last_active_days': 999,
            'is_real_data': False,
            'error': str(e)
        }

# THE FRAUD DETECTION LOGIC (This is your "AI")
def detect_fraud(wallet_data):
    risk_score = 0
    reasons = []
    
    # RULE 1: Many small transactions = Dusting attack (scammers send tiny amounts)
    if wallet_data['small_tx_count'] > 20:
        risk_score += 40
        reasons.append(f"🚨 {wallet_data['small_tx_count']} tiny transactions - Possible dusting attack!")
    elif wallet_data['small_tx_count'] > 10:
        risk_score += 20
        reasons.append(f"⚠️ {wallet_data['small_tx_count']} small transactions - Be careful")
    
    # RULE 2: Very large transaction = Money laundering suspicion
    if wallet_data['max_tx_amount'] > 50000:
        risk_score += 50
        reasons.append(f"💰 Massive transaction of {wallet_data['max_tx_amount']:,.2f} ETH - Very suspicious!")
    elif wallet_data['max_tx_amount'] > 10000:
        risk_score += 30
        reasons.append(f"💵 Large transaction of {wallet_data['max_tx_amount']:,.2f} ETH - Unusual activity")
    
    # RULE 3: Super recent activity = Could be a "rug pull" scam
    if wallet_data['last_active_days'] == 0:
        risk_score += 25
        reasons.append("⏰ Wallet active in last 24 hours - Recent scam possible")
    elif wallet_data['last_active_days'] < 3:
        risk_score += 10
        reasons.append("📅 Recent activity - Exercise caution")
    
    # RULE 4: Brand new wallet (no history) = Could be scammer's new wallet
    if wallet_data['total_tx'] == 0:
        risk_score += 15
        reasons.append("🆕 Brand new wallet - No transaction history")
    
    # RULE 5: High total volume
    if wallet_data['total_volume'] > 100000:
        risk_score += 35
        reasons.append(f"💎 Huge total volume: {wallet_data['total_volume']:,.2f} ETH - Whale alert!")
    elif wallet_data['total_volume'] > 10000:
        risk_score += 20
        reasons.append(f"📊 High total volume: {wallet_data['total_volume']:,.2f} ETH")
    
    # RULE 6: Many large transactions
    if wallet_data['large_tx_count'] > 5:
        risk_score += 25
        reasons.append(f"⚠️ {wallet_data['large_tx_count']} large transactions - Suspicious pattern")
    
    # Determine risk level
    if risk_score >= 60:
        return "🔴 HIGH RISK", min(100, risk_score), reasons
    elif risk_score >= 30:
        return "🟠 MEDIUM RISK", risk_score, reasons
    else:
        return "🟢 LOW RISK", risk_score, reasons

# Homepage route
@app.route('/')
def home():
    return render_template('index.html')

# API endpoint that ACTUALLY checks wallets
@app.route('/check_wallet', methods=['POST'])
def check_wallet():
    try:
        data = request.get_json()
        wallet_address = data.get('wallet', '').strip()
        
        if not wallet_address:
            return jsonify({'error': 'Please enter a wallet address'})
        
        # Basic validation
        if not wallet_address.startswith('0x'):
            return jsonify({'error': 'Invalid wallet address. Must start with 0x'})
        
        # Get REAL blockchain data!
        real_data = get_real_wallet_data(wallet_address)
        
        # Check for errors
        if real_data.get('error'):
            return jsonify({'error': f"API Error: {real_data['error']}. Please check your API key or try again later."})
        
        # Run fraud detection on REAL data
        risk_level, risk_score, reasons = detect_fraud(real_data)
        
        # Format volume display
        volume_display = f"{real_data['total_volume']:.2f} ETH"
        if real_data['total_volume'] == 0:
            volume_display = "0 ETH"
        
        return jsonify({
            'wallet': wallet_address,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'reasons': reasons if reasons else ['No suspicious patterns detected'],
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
    # Use debug=False for production
    app.run(host='0.0.0.0', port=port, debug=True)