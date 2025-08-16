import os
import threading
import logging
from flask import Flask
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# Create Flask app
app = Flask(__name__)

class SimpleBot:
    def __init__(self):
        self.telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.domain = os.getenv('BOT_DOMAIN', 'https://ai-bookmark-bot-production.up.railway.app')
        
        logger.info(f"🤖 Bot Token: {'✅' if self.telegram_token else '❌'}")
        logger.info(f"🌐 Domain: {self.domain}")
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        await update.message.reply_text(
            "🤖 **AI Bookmark Bot - Fixed Version**\n\n"
            "✅ Bot is running successfully!\n"
            "🌐 Web interface is working\n"
            "🔧 Port issues resolved\n\n"
            "Bot is alive and responding!",
            parse_mode='Markdown'
        )
    
    def start_bot(self):
        """Start the Telegram bot"""
        if not self.telegram_token:
            logger.error("❌ Missing TELEGRAM_BOT_TOKEN")
            return
        
        logger.info("🤖 Starting Telegram bot...")
        
        try:
            # Create application
            telegram_app = Application.builder().token(self.telegram_token).build()
            
            # Add handlers
            telegram_app.add_handler(CommandHandler("start", self.start_command))
            
            logger.info("✅ Telegram bot configured!")
            
            # Start polling
            telegram_app.run_polling(allowed_updates=Update.ALL_TYPES)
            
        except Exception as e:
            logger.error(f"❌ Bot error: {e}")

# Global bot instance
bot = SimpleBot()

@app.route('/')
def home():
    port = os.environ.get('PORT', 'unknown')
    return f"""
    <html>
    <head><title>AI Bookmark Bot - Fixed</title></head>
    <body style="font-family: system-ui; text-align: center; padding: 50px; background: #f0f2f5;">
        <h1>🤖 AI Bookmark Bot</h1>
        <p style="color: green; font-size: 18px;">✅ Status: FIXED & ACTIVE</p>
        <p>Port issues resolved!</p>
        <p><small>Railway Port: {port}</small></p>
        <hr>
        <p><strong>This is the corrected version!</strong></p>
        <p><a href="https://t.me/YourBotUsername" target="_blank">Test Bot →</a></p>
    </body>
    </html>
    """

@app.route('/health')
def health():
    return {
        "status": "healthy", 
        "version": "fixed",
        "port": os.environ.get('PORT', 'unknown'),
        "telegram_configured": bool(bot.telegram_token)
    }

def start_telegram_bot():
    """Start Telegram bot in background thread"""
    try:
        logger.info("🚀 Starting Telegram bot in background...")
        bot.start_bot()
    except Exception as e:
        logger.error(f"❌ Telegram bot thread error: {e}")

# Initialize bot for production (Gunicorn)
logger.info("🎯 Initializing for Gunicorn...")
bot_thread = threading.Thread(target=start_telegram_bot, daemon=True)
bot_thread.start()
logger.info("✅ Bot thread started for production!")

# Note: No app.run() here - Gunicorn handles serving the app
