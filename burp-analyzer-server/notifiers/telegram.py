import httpx

from config.settings import get_settings

settings = get_settings()


class TelegramNotifier:
    async def notify(self, message, url):
        async with httpx.AsyncClient() as client:
            bot_token = settings.telegram_token
            bot_chat_id = settings.telegram_chat_id
            telegram_message = "`%s` in `%s`" % (message, url)

            send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + bot_chat_id + '&parse_mode=Markdown'
            response = await client.post(send_text, data={"text": telegram_message})
            response.raise_for_status()
