import requests
import os
import hashlib
import base64
import secrets
import json
import uuid
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse, urlencode
from dotenv import load_dotenv
from flask import Flask, request, redirect
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

# Create Flask app at module level for Gunicorn
app = Flask(__name__)

class ProductionBookmarkBot:
    def __init__(self):
        # Bot credentials
        self.telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.client_id = os.getenv('X_CLIENT_ID') 
        self.client_secret = os.getenv('X_CLIENT_SECRET')
        self.anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
        self.domain = os.getenv('BOT_DOMAIN', 'https://your-app.railway.app')
        
        # User data storage
        self.pending_auth = {}  # {session_id: telegram_user_id}
        self.user_tokens = {}   # {telegram_user_id: {access_token, refresh_token, expires_at}}
        
        # Session for API calls
        self.session = requests.Session()
    
    def exchange_code_for_tokens(self, auth_code, code_verifier):
        """Exchange authorization code for access tokens"""
        headers = {
            'Authorization': f'Basic {base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'redirect_uri': f"{self.domain}/callback",
            'code_verifier': code_verifier,
            'client_id': self.client_id
        }
        
        try:
            response = self.session.post("https://api.twitter.com/2/oauth2/token", data=data, headers=headers, timeout=15)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Token exchange failed: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Token exchange error: {e}")
            return None
    
    def send_telegram_message(self, user_id, message):
        """Send message to specific user (synchronous)"""
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                'chat_id': user_id,
                'text': message
            }
            response = requests.post(url, json=data)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
            return False
    
    def get_user_bookmarks(self, access_token, max_count=5):
        """Fetch bookmarks for authenticated user"""
        headers = {'Authorization': f'Bearer {access_token}'}
        
        try:
            # Get user info
            user_response = self.session.get("https://api.twitter.com/2/users/me", headers=headers, timeout=10)
            if user_response.status_code != 200:
                return None, "Failed to get user info"
            
            user_info = user_response.json()['data']
            user_id = user_info['id']
            
            # Get bookmarks
            params = {
                'max_results': max_count,
                'tweet.fields': 'created_at,text,author_id',
                'expansions': 'author_id',
                'user.fields': 'username,name'
            }
            
            bookmarks_url = f"https://api.twitter.com/2/users/{user_id}/bookmarks"
            response = self.session.get(bookmarks_url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                bookmarks = data.get('data', [])
                users = {user['id']: user for user in data.get('includes', {}).get('users', [])}
                return bookmarks, users
            else:
                return None, f"API error: {response.status_code}"
                
        except Exception as e:
            return None, f"Request error: {e}"
    
    def generate_ai_summary(self, bookmarks, users):
        """Generate AI summary using Anthropic Claude"""
        if not bookmarks or not self.anthropic_api_key:
            return "📚 Recent bookmarks found, but AI summary unavailable."
        
        # Prepare bookmark data
        bookmark_texts = []
        for i, bookmark in enumerate(bookmarks[:10], 1):
            author_id = bookmark.get('author_id')
            author = users.get(author_id, {})
            author_name = author.get('name', 'Unknown')
            text = bookmark.get('text', '')[:200]
            
            bookmark_texts.append(f"{i}. @{author_name}: {text}")
        
        combined_text = "\n\n".join(bookmark_texts)
        
        prompt = f"""Analyze these Twitter bookmarks and provide a brief, actionable summary:

{combined_text}

Provide a concise summary (100-150 words) focusing on:
- Main themes and topics
- Actionable items or things to remember
- Time-sensitive opportunities
- Key insights worth noting

Format as a helpful briefing."""
        
        try:
            headers = {
                'x-api-key': self.anthropic_api_key,
                'Content-Type': 'application/json',
                'anthropic-version': '2023-06-01'
            }
            
            data = {
                'model': 'claude-3-haiku-20240307',
                'max_tokens': 300,
                'messages': [{'role': 'user', 'content': prompt}]
            }
            
            response = self.session.post('https://api.anthropic.com/v1/messages', headers=headers, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                return result['content'][0]['text'].strip()
            else:
                logger.warning(f"Anthropic API failed: {response.status_code}")
                return "📚 Recent bookmarks found, but AI summary unavailable."
                
        except Exception as e:
            logger.warning(f"Anthropic API error: {e}")
            return "📚 Recent bookmarks found, but AI summary unavailable."

# Create bot instance at module level
bot_instance = ProductionBookmarkBot()

# Flask routes that connect to the bot instance
@app.route('/')
def home():
    return """
    <html>
    <head><title>AI Bookmark Bot</title></head>
    <body style="font-family: system-ui; text-align: center; padding: 50px;">
        <h1>🤖 AI Bookmark Summarizer</h1>
        <p>Get smart summaries of your Twitter bookmarks!</p>
        <p><a href="https://t.me/YourBotUsername">Start on Telegram →</a></p>
    </body>
    </html>
    """

@app.route('/auth/<user_id>')
def start_auth(user_id):
    """Initiate OAuth for specific user"""
    session_id = str(uuid.uuid4())
    bot_instance.pending_auth[session_id] = user_id
    
    # Generate PKCE parameters for security
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    
    # Store verifier for this session
    bot_instance.pending_auth[session_id + '_verifier'] = code_verifier
    
    auth_params = {
        'response_type': 'code',
        'client_id': bot_instance.client_id,
        'redirect_uri': f"{bot_instance.domain}/callback",
        'scope': 'tweet.read users.read bookmark.read offline.access',
        'state': session_id,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    
    auth_url = f"https://twitter.com/i/oauth2/authorize?{urlencode(auth_params)}"
    return redirect(auth_url)

@app.route('/callback')
def oauth_callback():
    """Handle Twitter OAuth callback"""
    auth_code = request.args.get('code')
    session_id = request.args.get('state')
    error = request.args.get('error')
    
    if error:
        return f"❌ Authentication failed: {error}"
    
    if not auth_code or session_id not in bot_instance.pending_auth:
        return "❌ Invalid authentication session"
    
    telegram_user_id = bot_instance.pending_auth[session_id]
    code_verifier = bot_instance.pending_auth.get(session_id + '_verifier')
    
    # Exchange code for tokens
    tokens = bot_instance.exchange_code_for_tokens(auth_code, code_verifier)
    
    if tokens:
        # Store tokens for this user
        bot_instance.user_tokens[telegram_user_id] = {
            'access_token': tokens.get('access_token'),
            'refresh_token': tokens.get('refresh_token'),
            'expires_at': (datetime.utcnow() + timedelta(seconds=tokens.get('expires_in', 7200))).isoformat(),
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Send success message to user
        bot_instance.send_telegram_message(telegram_user_id, 
            "✅ Twitter connected successfully!\n\n🎉 You're all set! Use /bookmarks to get AI summaries of your bookmarks."
        )
        
        # Cleanup
        del bot_instance.pending_auth[session_id]
        if session_id + '_verifier' in bot_instance.pending_auth:
            del bot_instance.pending_auth[session_id + '_verifier']
        
        return """
        <html>
        <head><title>Success!</title></head>
        <body style="font-family: system-ui; text-align: center; padding: 50px;">
            <h1>✅ Connected Successfully!</h1>
            <p>Go back to Telegram and use <code>/bookmarks</code></p>
            <script>window.close();</script>
        </body>
        </html>
        """
    else:
        return "❌ Failed to exchange authorization code"

@app.route('/bookmarks/<user_id>')
def get_bookmarks_api(user_id):
    """API endpoint for getting bookmarks (for webhook-based bot)"""
    if user_id not in bot_instance.user_tokens:
        return {"error": "User not authenticated"}, 401
    
    user_data = bot_instance.user_tokens[user_id]
    access_token = user_data['access_token']
    
    result = bot_instance.get_user_bookmarks(access_token, max_count=5)
    
    if result[0] is None:
        return {"error": result[1]}, 400
    
    bookmarks, users = result
    
    if not bookmarks:
        return {"message": "No recent bookmarks found"}, 200
    
    summary = bot_instance.generate_ai_summary(bookmarks, users)
    
    return {
        "bookmarks_count": len(bookmarks),
        "summary": summary
    }, 200

if __name__ == "__main__":
    # For local development only
    app.run(host='0.0.0.0', port=5000, debug=True)
