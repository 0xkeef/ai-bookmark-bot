import requests
import os
import hashlib
import base64
import secrets
import json
import asyncio
import threading
import uuid
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse, urlencode
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes
from flask import Flask, request, redirect
import logging

# Create Flask app at module level for Gunicorn
app = Flask(__name__)
bot_instance = None  # Will be set later

@app.route('/')
def home():
    return """
    <h1>🤖 AI Bookmark Summarizer Bot</h1>
    <p>Get smart summaries of your Twitter bookmarks!</p>
    <p><a href="https://t.me/YourBotUsername">Start on Telegram →</a></p>
    """

@app.route('/auth/<user_id>')
def start_auth(user_id):
    """Initiate OAuth for specific user"""
    # Copy your existing start_auth logic here, but use bot_instance instead of self
    session_id = str(uuid.uuid4())
    bot_instance.pending_auth[session_id] = user_id
    # ... rest of your existing OAuth logic

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

class ProductionBookmarkBot:
    def __init__(self):
        # Bot credentials (yours)
        self.telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
        # DEBUG: Print environment variables
        print(f"DEBUG: TELEGRAM_BOT_TOKEN = {self.telegram_token}")
        print(f"DEBUG: Available env vars: {list(os.environ.keys())}")
        self.client_id = os.getenv('X_CLIENT_ID') 
        self.client_secret = os.getenv('X_CLIENT_SECRET')
        self.anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
        self.domain = os.getenv('BOT_DOMAIN', 'https://your-app.railway.app')  # Will be your deployed URL
        
        # User data storage
        self.pending_auth = {}  # {session_id: telegram_user_id}
        self.user_tokens = {}   # {telegram_user_id: {access_token, refresh_token, expires_at}}
        
        # Session for API calls
        self.session = requests.Session()
        
        # Start Flask web server for OAuth
        self.start_web_server()
    
    def start_web_server(self):
        """Start Flask server for OAuth callbacks"""
        app = Flask(__name__)
        
        @app.route('/')
        def home():
            return """
            <h1>🤖 AI Bookmark Summarizer Bot</h1>
            <p>Get smart summaries of your Twitter bookmarks!</p>
            <p><a href="https://t.me/YourBotUsername">Start on Telegram →</a></p>
            """
        
        @app.route('/auth/<user_id>')
        def start_auth(user_id):
            """Initiate OAuth for specific user"""
            session_id = str(uuid.uuid4())
            self.pending_auth[session_id] = user_id
            
            # Generate PKCE parameters for security
            code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode('utf-8')).digest()
            ).decode('utf-8').rstrip('=')
            
            # Store verifier for this session
            self.pending_auth[session_id + '_verifier'] = code_verifier
            
            auth_params = {
                'response_type': 'code',
                'client_id': self.client_id,
                'redirect_uri': f"{self.domain}/callback",
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
            
            if not auth_code or session_id not in self.pending_auth:
                return "❌ Invalid authentication session"
            
            telegram_user_id = self.pending_auth[session_id]
            code_verifier = self.pending_auth.get(session_id + '_verifier')
            
            # Exchange code for tokens
            tokens = self.exchange_code_for_tokens(auth_code, code_verifier)
            
            if tokens:
                # Store tokens for this user
                self.user_tokens[telegram_user_id] = {
                    'access_token': tokens.get('access_token'),
                    'refresh_token': tokens.get('refresh_token'),
                    'expires_at': (datetime.utcnow() + timedelta(seconds=tokens.get('expires_in', 7200))).isoformat(),
                    'created_at': datetime.utcnow().isoformat()
                }
                
                # Send success message to user
                asyncio.create_task(self.send_telegram_message(telegram_user_id, 
                    "✅ Twitter connected successfully!\n\n"
                    "🎉 You're all set! Use /bookmarks to get AI summaries of your bookmarks."
                ))
                
                # Cleanup
                del self.pending_auth[session_id]
                if session_id + '_verifier' in self.pending_auth:
                    del self.pending_auth[session_id + '_verifier']
                
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
        
        # Run Flask in background thread
        port = int(os.environ.get('PORT', 5000))
        threading.Thread(
            target=lambda: app.run(host='0.0.0.0', port=port, debug=False), 
            daemon=True
        ).start()
        logger.info(f"🌐 Web server started on port {port}")
    
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
    
    async def send_telegram_message(self, user_id, message):
        """Send message to specific user"""
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                'chat_id': user_id,
                'text': message,
                'parse_mode': 'Markdown'
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
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        user_id = update.effective_user.id
        
        if user_id in self.user_tokens:
            # User already connected
            await update.message.reply_text(
                "🎉 You're already connected!\n\n"
                "📚 Use /bookmarks to get AI summaries\n"
                "🔄 Use /disconnect to unlink your account"
            )
            return
        
        # Show connect button
        connect_url = f"{self.domain}/auth/{user_id}"
        keyboard = [[InlineKeyboardButton("🔗 Connect Twitter", url=connect_url)]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "🤖 **AI Bookmark Summarizer**\n\n"
            "📚 Get smart summaries of your Twitter bookmarks\n"
            "🧠 Powered by Claude AI\n"
            "⚡ Instant analysis of your saved tweets\n\n"
            "👆 Click below to connect your Twitter account\n"
            "🔒 Secure OAuth - takes 10 seconds",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    async def bookmarks_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /bookmarks command"""
        user_id = update.effective_user.id
        
        if user_id not in self.user_tokens:
            await self.start_command(update, context)
            return
        
        await update.message.reply_text("📚 Fetching your recent bookmarks...")
        
        # Get user's tokens
        user_data = self.user_tokens[user_id]
        access_token = user_data['access_token']
        
        # Fetch bookmarks
        result = self.get_user_bookmarks(access_token, max_count=5)
        
        if result[0] is None:
            await update.message.reply_text(f"❌ {result[1]}")
            return
        
        bookmarks, users = result
        
        if not bookmarks:
            await update.message.reply_text("📚 No recent bookmarks found!")
            return
        
        # Generate AI summary
        summary = self.generate_ai_summary(bookmarks, users)
        
        # Send results
        await update.message.reply_text(
            f"📚 **Your Recent Bookmarks ({len(bookmarks)} found)**\n\n"
            f"🤖 **AI Summary:**\n{summary}",
            parse_mode='Markdown'
        )
    
    async def disconnect_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /disconnect command"""
        user_id = update.effective_user.id
        
        if user_id in self.user_tokens:
            del self.user_tokens[user_id]
            await update.message.reply_text(
                "🔓 Disconnected successfully!\n\n"
                "Use /start to reconnect anytime"
            )
        else:
            await update.message.reply_text("❌ You're not connected")
    
    def start_bot(self):
        """Start the Telegram bot"""
        if not self.telegram_token:
            logger.error("Missing TELEGRAM_BOT_TOKEN")
            return
        
        logger.info("🤖 Starting Production Bookmark Bot...")
        
        # Create application
        app = Application.builder().token(self.telegram_token).build()
        
        # Add handlers
        app.add_handler(CommandHandler("start", self.start_command))
        app.add_handler(CommandHandler("bookmarks", self.bookmarks_command))
        app.add_handler(CommandHandler("disconnect", self.disconnect_command))
        
        logger.info("✅ Bot started successfully!")
        logger.info(f"🌐 Web server: {self.domain}")
        logger.info(f"🧠 AI: {'✅ Enabled' if self.anthropic_api_key else '❌ Disabled'}")
        
        # Start polling
        app.run_polling(allowed_updates=Update.ALL_TYPES)

def main():
    bot = ProductionBookmarkBot()
    bot.start_bot()

if __name__ == "__main__":
    main()
