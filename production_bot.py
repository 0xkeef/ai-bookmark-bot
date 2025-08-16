import os
import threading
import logging
import requests
import hashlib
import base64
import secrets
import uuid
import json
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse, urlencode
from flask import Flask, request, redirect
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# Create Flask app
app = Flask(__name__)

class CompleteBotWithOAuth:
    def __init__(self):
        # Environment variables
        self.telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.client_id = os.getenv('X_CLIENT_ID') 
        self.client_secret = os.getenv('X_CLIENT_SECRET')
        self.anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
        self.domain = os.getenv('BOT_DOMAIN', 'https://ai-bookmark-bot-production.up.railway.app')
        
        # Debug environment
        logger.info(f"🤖 Bot Token: {'✅' if self.telegram_token else '❌'}")
        logger.info(f"🔑 X Client ID: {'✅' if self.client_id else '❌'}")
        logger.info(f"🔐 X Client Secret: {'✅' if self.client_secret else '❌'}")
        logger.info(f"🧠 Anthropic Key: {'✅' if self.anthropic_api_key else '❌'}")
        logger.info(f"🌐 Domain: {self.domain}")
        
        # In-memory storage
        self.pending_auth = {}  # {session_id: telegram_user_id}
        self.user_tokens = {}   # {telegram_user_id: {access_token, refresh_token, expires_at}}
        
        # Session for API calls
        self.session = requests.Session()
        
        # Telegram application reference
        self.telegram_app = None
    
    def setup_flask_routes(self):
        """Setup all Flask routes"""
        
        @app.route('/')
        def home():
            return """
            <html>
            <head>
                <title>AI Bookmark Summarizer Bot</title>
                <style>
                    body { font-family: system-ui; text-align: center; padding: 50px; background: #f0f2f5; }
                    .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .status { color: #28a745; font-size: 18px; margin: 20px 0; }
                    .button { display: inline-block; background: #1d9bf0; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 10px; }
                    .feature { margin: 15px 0; padding: 10px; background: #f8f9fa; border-radius: 6px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🤖 AI Bookmark Summarizer Bot</h1>
                    <p class="status">✅ Fully Deployed & Ready!</p>
                    
                    <div class="feature">
                        <h3>📚 Smart Bookmark Analysis</h3>
                        <p>Get AI-powered summaries of your Twitter bookmarks</p>
                    </div>
                    
                    <div class="feature">
                        <h3>🧠 Claude AI Integration</h3>
                        <p>Advanced natural language processing for insights</p>
                    </div>
                    
                    <div class="feature">
                        <h3>🔒 Secure OAuth</h3>
                        <p>Safe Twitter account connection via OAuth 2.0</p>
                    </div>
                    
                    <a href="https://t.me/YourBotUsername" class="button">Start on Telegram →</a>
                    <a href="/health" class="button">API Health Check</a>
                </div>
            </body>
            </html>
            """
        
        @app.route('/health')
        def health():
            return {
                "status": "healthy",
                "version": "complete_oauth",
                "features": {
                    "telegram": bool(self.telegram_token),
                    "twitter_oauth": bool(self.client_id and self.client_secret),
                    "ai_summaries": bool(self.anthropic_api_key),
                    "domain": self.domain
                },
                "active_users": len(self.user_tokens),
                "pending_auth": len(self.pending_auth)
            }
        
        @app.route('/auth/<user_id>')
        def start_auth(user_id):
            """Initiate OAuth for specific user"""
            try:
                # Validate inputs
                if not self.client_id or not self.client_secret:
                    return "❌ Twitter OAuth not configured. Missing X_CLIENT_ID or X_CLIENT_SECRET."
                
                session_id = str(uuid.uuid4())
                self.pending_auth[session_id] = user_id
                
                logger.info(f"🔐 Starting OAuth for user {user_id}, session: {session_id}")
                
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
                logger.info(f"🔗 Redirecting to Twitter OAuth: {auth_url[:100]}...")
                
                return redirect(auth_url)
                
            except Exception as e:
                logger.error(f"❌ Auth error: {e}")
                return f"❌ Authentication error: {e}"
        
        @app.route('/callback')
        def oauth_callback():
            """Handle Twitter OAuth callback"""
            try:
                auth_code = request.args.get('code')
                session_id = request.args.get('state')
                error = request.args.get('error')
                
                logger.info(f"📞 OAuth callback - Session: {session_id}, Code: {'✅' if auth_code else '❌'}, Error: {error}")
                
                if error:
                    return f"❌ Authentication failed: {error}"
                
                if not auth_code or session_id not in self.pending_auth:
                    return "❌ Invalid authentication session"
                
                telegram_user_id = self.pending_auth[session_id]
                code_verifier = self.pending_auth.get(session_id + '_verifier')
                
                logger.info(f"🔄 Exchanging code for tokens for user {telegram_user_id}")
                
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
                    
                    logger.info(f"✅ Tokens stored for user {telegram_user_id}")
                    
                    # Send success message to user via Telegram
                    try:
                        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
                        data = {
                            'chat_id': telegram_user_id,
                            'text': "✅ Twitter connected successfully!\n\n🎉 You're all set! Use /bookmarks to get AI summaries.",
                            'parse_mode': 'Markdown'
                        }
                        requests.post(url, json=data, timeout=10)
                    except Exception as e:
                        logger.error(f"Failed to send success message: {e}")
                    
                    # Cleanup
                    del self.pending_auth[session_id]
                    if session_id + '_verifier' in self.pending_auth:
                        del self.pending_auth[session_id + '_verifier']
                    
                    return """
                    <html>
                    <head><title>Success!</title></head>
                    <body style="font-family: system-ui; text-align: center; padding: 50px; background: #f0f2f5;">
                        <div style="max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px;">
                            <h1>✅ Connected Successfully!</h1>
                            <p>Your Twitter account is now linked to the AI Bookmark Bot.</p>
                            <p><strong>Next steps:</strong></p>
                            <ol style="text-align: left;">
                                <li>Go back to Telegram</li>
                                <li>Use <code>/bookmarks</code> to get summaries</li>
                                <li>Enjoy AI-powered bookmark analysis!</li>
                            </ol>
                            <script>setTimeout(() => window.close(), 5000);</script>
                        </div>
                    </body>
                    </html>
                    """
                else:
                    return "❌ Failed to exchange authorization code for tokens"
                    
            except Exception as e:
                logger.error(f"❌ Callback error: {e}")
                return f"❌ Callback error: {e}"
    
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
                token_data = response.json()
                logger.info(f"✅ Token exchange successful")
                return token_data
            else:
                logger.error(f"❌ Token exchange failed: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"❌ Token exchange error: {e}")
            return None
    
    def get_user_bookmarks(self, access_token, max_count=5):
        """Fetch bookmarks for authenticated user"""
        headers = {'Authorization': f'Bearer {access_token}'}
        
        try:
            # Get user info
            user_response = self.session.get("https://api.twitter.com/2/users/me", headers=headers, timeout=10)
            if user_response.status_code != 200:
                return None, f"Failed to get user info: {user_response.status_code}"
            
            user_info = user_response.json()['data']
            user_id = user_info['id']
            username = user_info['username']
            
            logger.info(f"📚 Fetching bookmarks for @{username}")
            
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
                logger.info(f"✅ Found {len(bookmarks)} bookmarks")
                return bookmarks, users, username
            else:
                logger.error(f"❌ Bookmarks API error: {response.status_code}")
                return None, f"API error: {response.status_code}"
                
        except Exception as e:
            logger.error(f"❌ Bookmark fetch error: {e}")
            return None, f"Request error: {e}"
    
    def generate_ai_summary(self, bookmarks, users):
        """Generate AI summary using Anthropic Claude"""
        if not bookmarks:
            return "📚 No bookmarks found to summarize."
        
        if not self.anthropic_api_key:
            return "📚 Recent bookmarks found, but AI summary requires ANTHROPIC_API_KEY."
        
        # Prepare bookmark data for Claude
        bookmark_texts = []
        for i, bookmark in enumerate(bookmarks[:10], 1):
            author_id = bookmark.get('author_id')
            author = users.get(author_id, {})
            author_name = author.get('name', 'Unknown')
            text = bookmark.get('text', '')[:200]  # Limit for API costs
            
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
                summary = result['content'][0]['text'].strip()
                logger.info("✅ Generated AI summary")
                return summary
            else:
                logger.warning(f"Anthropic API failed: {response.status_code}")
                return "📚 Recent bookmarks found, but AI summary is temporarily unavailable."
                
        except Exception as e:
            logger.warning(f"Anthropic API error: {e}")
            return "📚 Recent bookmarks found, but AI summary is temporarily unavailable."
    
    # Telegram Bot Commands
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        user_id = update.effective_user.id
        username = update.effective_user.username or "User"
        
        logger.info(f"👋 /start from @{username} (ID: {user_id})")
        
        if user_id in self.user_tokens:
            await update.message.reply_text(
                f"🎉 Welcome back, @{username}!\n\n"
                "You're already connected to Twitter.\n\n"
                "📚 Use /bookmarks to get AI summaries\n"
                "🔄 Use /disconnect to unlink your account\n"
                "ℹ️ Use /status to check your connection",
                parse_mode='Markdown'
            )
            return
        
        # Show connect button for new users
        connect_url = f"{self.domain}/auth/{user_id}"
        keyboard = [[InlineKeyboardButton("🔗 Connect Twitter Account", url=connect_url)]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            f"🤖 **Welcome to AI Bookmark Summarizer, @{username}!**\n\n"
            "📚 Get smart summaries of your Twitter bookmarks\n"
            "🧠 Powered by Claude AI for deep insights\n"
            "⚡ Instant analysis of your saved tweets\n"
            "🔒 Secure OAuth 2.0 authentication\n\n"
            "👆 Click below to connect your Twitter account\n"
            "Takes just 10 seconds!",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    async def bookmarks_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /bookmarks command"""
        user_id = update.effective_user.id
        username = update.effective_user.username or "User"
        
        logger.info(f"📚 /bookmarks from @{username} (ID: {user_id})")
        
        if user_id not in self.user_tokens:
            await self.start_command(update, context)
            return
        
        await update.message.reply_text("📚 Fetching your recent bookmarks... ⏳")
        
        # Get user's tokens
        user_data = self.user_tokens[user_id]
        access_token = user_data['access_token']
        
        # Fetch bookmarks
        result = self.get_user_bookmarks(access_token, max_count=5)
        
        if result[0] is None:
            error_msg = result[1]
            if "401" in error_msg or "expired" in error_msg.lower():
                await update.message.reply_text(
                    "🔄 Your Twitter connection expired. Please reconnect:\n\n"
                    "Use /start to get a new connection link."
                )
                # Remove expired tokens
                del self.user_tokens[user_id]
            else:
                await update.message.reply_text(f"❌ Error: {error_msg}")
            return
        
        bookmarks, users, twitter_username = result
        
        if not bookmarks:
            await update.message.reply_text(
                f"📚 No recent bookmarks found for @{twitter_username}!\n\n"
                "💡 Bookmark some tweets on Twitter first, then try again."
            )
            return
        
        # Generate AI summary
        await update.message.reply_text("🧠 Generating AI summary with Claude... ⏳")
        summary = self.generate_ai_summary(bookmarks, users)
        
        # Send results
        response = f"📚 **Your Recent Bookmarks ({len(bookmarks)} found)**\n"
        response += f"🐦 Twitter: @{twitter_username}\n\n"
        response += f"🤖 **AI Summary:**\n{summary}\n\n"
        response += f"💡 Use /bookmarks again anytime for fresh analysis!"
        
        await update.message.reply_text(response, parse_mode='Markdown')
    
    async def disconnect_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /disconnect command"""
        user_id = update.effective_user.id
        username = update.effective_user.username or "User"
        
        if user_id in self.user_tokens:
            del self.user_tokens[user_id]
            logger.info(f"🔓 Disconnected @{username} (ID: {user_id})")
            await update.message.reply_text(
                "🔓 **Disconnected successfully!**\n\n"
                "Your Twitter account has been unlinked.\n"
                "Use /start to reconnect anytime."
            )
        else:
            await update.message.reply_text("❌ You're not connected to any Twitter account.")
    
    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command"""
        user_id = update.effective_user.id
        username = update.effective_user.username or "User"
        
        if user_id in self.user_tokens:
            user_data = self.user_tokens[user_id]
            connected_at = user_data.get('created_at', 'Unknown')
            expires_at = user_data.get('expires_at', 'Unknown')
            
            await update.message.reply_text(
                f"📊 **Connection Status for @{username}**\n\n"
                f"🔗 **Twitter:** Connected ✅\n"
                f"🧠 **AI Summaries:** {'Enabled' if self.anthropic_api_key else 'Disabled'}\n"
                f"📅 **Connected:** {connected_at[:10] if connected_at != 'Unknown' else 'Unknown'}\n"
                f"⏰ **Expires:** {expires_at[:10] if expires_at != 'Unknown' else 'Unknown'}\n\n"
                f"💡 Use /bookmarks to get summaries!",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                f"📊 **Connection Status for @{username}**\n\n"
                f"❌ **Twitter:** Not connected\n"
                f"🧠 **AI Summaries:** {'Available' if self.anthropic_api_key else 'Unavailable'}\n\n"
                f"💡 Use /start to connect your account!",
                parse_mode='Markdown'
            )
    
    def start_bot(self):
        """Start the Telegram bot"""
        if not self.telegram_token:
            logger.error("❌ Missing TELEGRAM_BOT_TOKEN")
            return
        
        logger.info("🤖 Starting Telegram bot with full OAuth...")
        
        try:
            # Create application
            self.telegram_app = Application.builder().token(self.telegram_token).build()
            
            # Add command handlers
            self.telegram_app.add_handler(CommandHandler("start", self.start_command))
            self.telegram_app.add_handler(CommandHandler("bookmarks", self.bookmarks_command))
            self.telegram_app.add_handler(CommandHandler("disconnect", self.disconnect_command))
            self.telegram_app.add_handler(CommandHandler("status", self.status_command))
            
            logger.info("✅ Telegram bot configured with all commands!")
            
            # Start polling
            self.telegram_app.run_polling(allowed_updates=Update.ALL_TYPES)
            
        except Exception as e:
            logger.error(f"❌ Bot error: {e}")

# Global bot instance
bot = CompleteBotWithOAuth()

def start_telegram_bot():
    """Start Telegram bot in background thread"""
    try:
        logger.info("🚀 Starting complete bot with OAuth...")
        bot.start_bot()
    except Exception as e:
        logger.error(f"❌ Telegram bot thread error: {e}")

# Setup Flask routes
bot.setup_flask_routes()

# Start Telegram bot for Gunicorn
logger.info("🎯 Initializing complete OAuth bot for production...")
bot_thread = threading.Thread(target=start_telegram_bot, daemon=True)
bot_thread.start()
logger.info("✅ Complete OAuth bot ready!")
