from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    trufflehog_path: str = "D:\\burp\\trufflehog.exe"
    temp_dir: str = "Z:\\"


@lru_cache
def get_settings():
    return Settings()
