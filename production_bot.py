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
            "🤖 **AI Bookmark Bot**\n\n"
            "✅ Bot is running successfully!\n"
            "🌐 Web interface is working\n"
            "🔧 Currently in setup mode\n\n"
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
    <head><title>AI Bookmark Bot</title></head>
    <body style="font-family: system-ui; text-align: center; padding: 50px; background: #f0f2f5;">
        <h1>🤖 AI Bookmark Bot</h1>
        <p style="color: green; font-size: 18px;">✅ Status: ACTIVE</p>
        <p>Bot is running successfully!</p>
        <p><small>Running on port: {port}</small></p>
        <hr>
        <p><strong>Next Steps:</strong></p>
        <ol style="text-align: left; max-width: 400px; margin: 0 auto;">
            <li>Test bot with /start command in Telegram</li>
            <li>Verify all environment variables are set</li>
            <li>Add Twitter OAuth functionality</li>
        </ol>
        <hr>
        <p><a href="https://t.me/YourBotUsername" target="_blank">Open Telegram Bot →</a></p>
    </body>
    </html>
    """

@app.route('/health')
def health():
    return {
        "status": "healthy", 
        "bot": "running",
        "port": os.environ.get('PORT', 'unknown'),
        "domain": bot.domain,
        "telegram_configured": bool(bot.telegram_token)
    }

def start_telegram_bot():
    """Start Telegram bot in background thread"""
    try:
        logger.info("🚀 Starting Telegram bot in background...")
        bot.start_bot()
    except Exception as e:
        logger.error(f"❌ Telegram bot thread error: {e}")

# Start Telegram bot in background (for both dev and production)
logger.info("🎯 Initializing Telegram bot thread...")
bot_thread = threading.Thread(target=start_telegram_bot, daemon=True)
bot_thread.start()

if __name__ == "__main__":
    # Local development only
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"🚀 Starting Flask in development mode on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
else:
    # Production (Gunicorn handles the port)
    logger.info("🚀 Flask app ready for Gunicorn!")
    port = os.environ.get('PORT', 'Railway-assigned')
    logger.info(f"🌐 Will run on port: {port}")

# This ensures the app is avai
