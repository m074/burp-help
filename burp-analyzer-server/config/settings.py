from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    trufflehog_path: str = "D:\\burp\\trufflehog.exe"
    temp_dir: str = "Z:\\"
    http_timeout: int = 10
    telegram_token: str
    telegram_chat_id: str = "325968545"


@lru_cache
def get_settings():
    return Settings()
