import os
from flask import Flask, render_template, request, jsonify
import requests
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Add CORS headers manually (instead of flask_cors)
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST')
    return response

def test_api_key(api_key):
    """Test if API key is valid"""
    if not api_key or api_key == 'YOUR_API_KEY_HERE':
        return False, "No API key provided"
    
    test_wallet = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5"
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={test_wallet}&tag=latest&apikey={api_key}"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        if data.get('status') == '1':
            return True, "Valid"
        else:
            error_msg = data.get('result', 'Unknown error')
            if 'Invalid API Key' in error_msg:
                return False, "Invalid API key"
            return False, error_msg
    except Exception as e:
        return False, str(e)

def get_real_wallet_data(wallet_address):
    # Get API key from environment
    YOUR_API_KEY = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    
    # Check if API key is provided
    if not YOUR_API_KEY or YOUR_API_KEY == 'YOUR_API_KEY_HERE':
        return {
            'total_tx': 0,
            'small_tx_count': 0,
            'large_tx_count': 0,
            'max_tx_amount': 0,
            'total_volume': 0,
            'last_active_days': 999,
            'is_real_data': False,
            'error': 'No valid API key found. Please add your Etherscan API key to .env file'
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
            'error': 'Invalid wallet address format. Must be 42 characters starting with 0x'
        }
    
    # Fetch transactions
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={wallet_address}&startblock=0&endblock=99999999&sort=desc&apikey={YOUR_API_KEY}"
    
    try:
        print(f"📡 Fetching data for wallet: {wallet_address}")
        response = requests.get(url, timeout=15)
        data = response.json()
        
        # Check for API errors
        if data.get('message') == 'NOTOK':
            error_msg = data.get('result', 'Unknown error')
            print(f"❌ API Error: {error_msg}")
            
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
            elif 'rate limit' in error_msg.lower() or 'max rate limit' in error_msg.lower():
                return {
                    'total_tx': 0,
                    'small_tx_count': 0,
                    'large_tx_count': 0,
                    'max_tx_amount': 0,
                    'total_volume': 0,
                    'last_active_days': 999,
                    'is_real_data': False,
                    'error': 'Rate limit exceeded. Please wait a moment and try again.'
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
        
        # Process successful response
        if data.get('status') == '1' and data.get('result'):
            transactions = data['result']
            total_tx = len(transactions)
            
            # Analyze transactions (limit to last 500 for performance)
            small_tx_count = 0
            large_tx_count = 0
            max_amount = 0
            total_volume_eth = 0
            recent_activity = False
            
            for tx in transactions[:500]:  # Analyze last 500 transactions
                try:
                    # Convert wei to ETH (1 ETH = 10^18 wei)
                    amount = int(tx['value']) / 1000000000000000000
                    
                    if amount > 0:  # Only count non-zero transactions
                        total_volume_eth += amount
                        
                        # Small transactions (dusting attacks)
                        if amount < 0.01 and amount > 0:
                            small_tx_count += 1
                        
                        # Large transactions
                        if amount > 10:
                            large_tx_count += 1
                        
                        # Track max transaction
                        if amount > max_amount:
                            max_amount = amount
                            
                except (ValueError, KeyError) as e:
                    print(f"⚠️ Error parsing transaction: {e}")
                    continue
            
            # Calculate days since last activity
            if transactions:
                try:
                    last_timestamp = int(transactions[0]['timeStamp'])
                    current_time = int(time.time())
                    days_since_active = (current_time - last_timestamp) / 86400
                    days_since_active = max(0, int(days_since_active))  # Ensure non-negative
                    
                    # Check for very recent activity (last 24 hours)
                    if days_since_active == 0:
                        recent_activity = True
                except (ValueError, KeyError) as e:
                    print(f"⚠️ Error parsing timestamp: {e}")
                    days_since_active = 999
            else:
                days_since_active = 999
            
            print(f"✅ Found {total_tx} transactions. Volume: {total_volume_eth:.2f} ETH")
            
            return {
                'total_tx': total_tx,
                'small_tx_count': small_tx_count,
                'large_tx_count': large_tx_count,
                'max_tx_amount': max_amount,
                'total_volume': total_volume_eth,
                'last_active_days': days_since_active,
                'recent_activity': recent_activity,
                'is_real_data': True
            }
        else:
            # No transactions found
            return {
                'total_tx': 0,
                'small_tx_count': 0,
                'large_tx_count': 0,
                'max_tx_amount': 0,
                'total_volume': 0,
                'last_active_days': 999,
                'recent_activity': False,
                'is_real_data': True
            }
            
    except requests.exceptions.Timeout:
        print("❌ Request timeout")
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
    except requests.exceptions.ConnectionError:
        print("❌ Connection error")
        return {
            'total_tx': 0,
            'small_tx_count': 0,
            'large_tx_count': 0,
            'max_tx_amount': 0,
            'total_volume': 0,
            'last_active_days': 999,
            'is_real_data': False,
            'error': 'Connection error - Please check your internet connection'
        }
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return {
            'total_tx': 0,
            'small_tx_count': 0,
            'large_tx_count': 0,
            'max_tx_amount': 0,
            'total_volume': 0,
            'last_active_days': 999,
            'is_real_data': False,
            'error': f'Error fetching data: {str(e)}'
        }

def detect_fraud(wallet_data):
    """Enhanced fraud detection with better scoring"""
    risk_score = 0
    reasons = []
    
    # Check for errors first
    if wallet_data.get('error'):
        return "⚪ CAN'T ANALYZE", 0, [f"Error: {wallet_data['error']}"]
    
    # 1. Dusting attack detection (many small transactions)
    if wallet_data['small_tx_count'] > 50:
        risk_score += 45
        reasons.append(f"🚨 CRITICAL: {wallet_data['small_tx_count']} micro-transactions (<0.01 ETH) - Classic dusting attack pattern!")
    elif wallet_data['small_tx_count'] > 20:
        risk_score += 30
        reasons.append(f"⚠️ HIGH: {wallet_data['small_tx_count']} small transactions - Possible dusting attack")
    elif wallet_data['small_tx_count'] > 10:
        risk_score += 15
        reasons.append(f"⚠️ {wallet_data['small_tx_count']} micro-transactions - Unusual pattern")
    
    # 2. Large transaction detection (potential scams/whales)
    if wallet_data['max_tx_amount'] > 100000:
        risk_score += 60
        reasons.append(f"💰 EXTREME: Single transaction of {wallet_data['max_tx_amount']:,.2f} ETH - Whale alert! Highly suspicious")
    elif wallet_data['max_tx_amount'] > 50000:
        risk_score += 45
        reasons.append(f"💎 MASSIVE: {wallet_data['max_tx_amount']:,.2f} ETH transaction - Very suspicious")
    elif wallet_data['max_tx_amount'] > 10000:
        risk_score += 30
        reasons.append(f"💵 Large: {wallet_data['max_tx_amount']:,.2f} ETH transaction - Unusual")
    elif wallet_data['max_tx_amount'] > 1000:
        risk_score += 15
        reasons.append(f"📊 Notable: {wallet_data['max_tx_amount']:,.2f} ETH transaction")
    
    # 3. Recent activity (scams often have recent activity)
    if wallet_data.get('recent_activity', False):
        risk_score += 35
        reasons.append("⏰ CRITICAL: Wallet active in last 24 hours - Recent scam operation possible")
    elif wallet_data['last_active_days'] < 3:
        risk_score += 15
        reasons.append("📅 Recent activity (within 3 days) - Exercise extreme caution")
    elif wallet_data['last_active_days'] < 7:
        risk_score += 5
        reasons.append("📅 Active within last week")
    
    # 4. New wallet with no history
    if wallet_data['total_tx'] == 0:
        risk_score += 25
        reasons.append("🆕 Brand new wallet - No transaction history (could be a scam wallet)")
    elif wallet_data['total_tx'] < 5:
        risk_score += 10
        reasons.append("🆕 New wallet with very few transactions")
    
    # 5. High total volume
    if wallet_data['total_volume'] > 500000:
        risk_score += 50
        reasons.append(f"💎 EXTREME volume: {wallet_data['total_volume']:,.2f} ETH - Large-scale operation")
    elif wallet_data['total_volume'] > 100000:
        risk_score += 35
        reasons.append(f"💰 High volume: {wallet_data['total_volume']:,.2f} ETH - Significant funds movement")
    elif wallet_data['total_volume'] > 10000:
        risk_score += 20
        reasons.append(f"📊 Notable volume: {wallet_data['total_volume']:,.2f} ETH")
    
    # 6. Multiple large transactions pattern
    if wallet_data['large_tx_count'] > 10:
        risk_score += 35
        reasons.append(f"⚠️ CRITICAL: {wallet_data['large_tx_count']} large transactions (>10 ETH) - Suspicious pattern")
    elif wallet_data['large_tx_count'] > 5:
        risk_score += 20
        reasons.append(f"⚠️ {wallet_data['large_tx_count']} large transactions - Unusual activity pattern")
    elif wallet_data['large_tx_count'] > 2:
        risk_score += 10
        reasons.append(f"📊 {wallet_data['large_tx_count']} large transactions detected")
    
    # Cap the risk score at 100
    risk_score = min(100, risk_score)
    
    # Determine risk level
    if risk_score >= 70:
        return "🔴 HIGH RISK", risk_score, reasons
    elif risk_score >= 40:
        return "🟠 MEDIUM RISK", risk_score, reasons
    elif risk_score >= 15:
        return "🟡 LOW RISK", risk_score, reasons
    else:
        return "🟢 VERY LOW RISK", risk_score, reasons if reasons else ["No suspicious patterns detected"]

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
        
        # Validate wallet address format
        if not wallet_address.startswith('0x') or len(wallet_address) != 42:
            return jsonify({'error': 'Invalid wallet address format. Must be 42 characters starting with 0x'})
        
        # Get real data from Etherscan
        real_data = get_real_wallet_data(wallet_address)
        
        if real_data.get('error'):
            return jsonify({'error': real_data['error']})
        
        # Detect fraud
        risk_level, risk_score, reasons = detect_fraud(real_data)
        
        # Format volume display
        if real_data['total_volume'] > 0:
            volume_display = f"{real_data['total_volume']:.2f} ETH"
        else:
            volume_display = "0 ETH"
        
        # Format last active
        if real_data['last_active_days'] == 999:
            last_active_display = "No transactions found"
        elif real_data['last_active_days'] == 0:
            last_active_display = "Today"
        elif real_data['last_active_days'] == 1:
            last_active_display = "1 day ago"
        else:
            last_active_display = f"{real_data['last_active_days']} days ago"
        
        return jsonify({
            'wallet': wallet_address,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'reasons': reasons,
            'transactions_found': real_data['total_tx'],
            'total_volume': volume_display,
            'last_active': last_active_display,
            'small_tx_count': real_data['small_tx_count'],
            'large_tx_count': real_data['large_tx_count'],
            'max_tx_amount': f"{real_data['max_tx_amount']:.2f}" if real_data['max_tx_amount'] > 0 else "0",
            'is_real_data': real_data['is_real_data']
        })
        
    except Exception as e:
        print(f"❌ Error in check_wallet: {e}")
        return jsonify({'error': f'Server error: {str(e)}'})

@app.route('/test_api', methods=['GET'])
def test_api():
    """Test endpoint to verify API key"""
    api_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    is_valid, message = test_api_key(api_key)
    return jsonify({
        'api_key_configured': bool(api_key),
        'api_key_valid': is_valid,
        'message': message
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("\n" + "="*50)
    print("🚀 CryptoShield Fraud Detection System")
    print("="*50)
    
    # Test API key on startup
    api_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    if not api_key:
        print("⚠️  WARNING: No Etherscan API key found!")
        print("Please create a .env file with: ETHERSCAN_API_KEY=your_key_here")
        print("Get a free API key from: https://etherscan.io/register")
    elif api_key == 'YOUR_API_KEY_HERE':
        print("⚠️  WARNING: Please replace YOUR_API_KEY_HERE with your actual Etherscan API key")
    else:
        print("✅ Etherscan API key found")
        is_valid, message = test_api_key(api_key)
        if is_valid:
            print("✅ API key is valid!")
        else:
            print(f"⚠️  API key validation: {message}")
    
    print(f"\n🌐 Server running on: http://localhost:{port}")
    print("="*50 + "\n")
    
    app.run(host='0.0.0.0', port=port, debug=True)