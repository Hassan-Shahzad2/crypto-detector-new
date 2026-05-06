import os
from flask import Flask, render_template, request, jsonify
import requests
import time

app = Flask(__name__)

# THIS IS HOW WE ACTUALLY CHECK REAL WALLETS
def get_real_wallet_data(wallet_address):
    """
    This function calls Etherscan API to get REAL transaction data
    It's like asking the blockchain: "Hey, what has this wallet done?"
    """
    
    # REPLACE THIS WITH YOUR FREE API KEY FROM ETHERSCAN
    # Go to https://etherscan.io/register and sign up (free!)
    YOUR_API_KEY = os.environ.get('ETHERSCAN_API_KEY', 'HP8R6M6HSP6BPPCAUIYFMXUSG3GIC3FXKH')
  # <--- CHANGE THIS!
    
    # Ask Etherscan for this wallet's transactions
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={wallet_address}&startblock=0&endblock=99999999&sort=desc&apikey={YOUR_API_KEY}"
    
    try:
        response = requests.get(url)
        data = response.json()
        
        if data['status'] == '1' and data['result']:
            transactions = data['result']
            
            # Calculate statistics from REAL data
            total_tx = len(transactions)
            
            # Convert from wei to ETH (crypto math)
            amounts = []
            small_tx_count = 0
            large_tx_count = 0
            max_amount = 0
            
            for tx in transactions[:100]:  # Check last 100 transactions
                amount = int(tx['value']) / 1000000000000000000  # Convert wei to ETH
                amounts.append(amount)
                
                if amount < 0.01:  # Less than 0.01 ETH is "small"
                    small_tx_count += 1
                if amount > 10:    # More than 10 ETH is "large"
                    large_tx_count += 1
                if amount > max_amount:
                    max_amount = amount
            
            # How many days since last transaction?
            if transactions:
                last_timestamp = int(transactions[0]['timeStamp'])
                days_since_active = (time.time() - last_timestamp) / 86400  # 86400 seconds in a day
            else:
                days_since_active = 999
            
            return {
                'total_tx': total_tx,
                'small_tx_count': small_tx_count,
                'large_tx_count': large_tx_count,
                'max_tx_amount': max_amount,
                'total_volume': sum(amounts),
                'last_active_days': int(days_since_active),
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
            'is_real_data': False
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
        reasons.append(f"💰 Massive transaction of ${wallet_data['max_tx_amount']:,.0f} - Very suspicious!")
    elif wallet_data['max_tx_amount'] > 10000:
        risk_score += 30
        reasons.append(f"💵 Large transaction of ${wallet_data['max_tx_amount']:,.0f} - Unusual activity")
    
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
        reasons.append(f"💎 Huge total volume: ${wallet_data['total_volume']:,.0f} - Whale alert!")
    
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
    wallet_address = request.json.get('wallet')
    
    if not wallet_address:
        return jsonify({'error': 'Please enter a wallet address'})
    
    # Get REAL blockchain data!
    real_data = get_real_wallet_data(wallet_address)
    
    # Run fraud detection on REAL data
    risk_level, risk_score, reasons = detect_fraud(real_data)
    
    return jsonify({
        'wallet': wallet_address,
        'risk_level': risk_level,
        'risk_score': risk_score,
        'reasons': reasons,
        'transactions_found': real_data['total_tx'],
        'total_volume': f"${real_data['total_volume']:,.2f}",
        'last_active': real_data['last_active_days'],
        'is_real_data': real_data['is_real_data']
    })

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)