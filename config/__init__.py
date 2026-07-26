"""
Configuration module initialization.
Provides global access to the configuration settings.
"""
from .settings import Settings

settings = Settings()
__all__ = ["settings"]
