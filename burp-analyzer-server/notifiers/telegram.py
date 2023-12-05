import asyncio
import logging

import httpx

from config.settings import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)


class TelegramNotifier:
    async def notify(self, message, url):
        try:
            async with httpx.AsyncClient() as client:
                bot_token = settings.telegram_token
                bot_chat_id = settings.telegram_chat_id
                telegram_message = "```%s``` in ```%s```" % (message, url)
                telegram_message = telegram_message.replace(";", "").replace('"', "").replace(",", "").replace("#",
                                                                                                               "").replace(
                    "'", "")
                send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + bot_chat_id + '&parse_mode=Markdown'
                response = await client.post(send_text, data={"text": telegram_message})
                response.raise_for_status()
        except Exception:
            logger.error("Failed to send to telegram this message: %s in url %s", message, url)

    async def send_messages(self, messages, url):
        try:
            await asyncio.gather(*[self.notify(message, url) for message in messages])
        except Exception:
            logger.exception("FAIL SEND MESSAGES")
