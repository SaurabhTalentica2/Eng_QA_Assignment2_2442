"""Configuration and shared setup for the API Security Testing Duo.

Loads environment variables, builds the shared Gemini-backed LLM, and exposes
the VAmPI target settings. Centralizing this keeps agents free of provider- and
target-specific wiring, and enforces the "config via environment" rule from the
assignment's ethical guidelines (no hardcoded secrets).
"""

import os

from crewai import LLM
from dotenv import load_dotenv

load_dotenv()

MODEL_NAME = os.getenv("MODEL_NAME", "gemini/gemini-3.6-flash")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# VAmPI runs locally in Docker. Testing is authorized ONLY against this target.
VAMPI_BASE_URL = os.getenv("VAMPI_BASE_URL", "http://localhost:5000").rstrip("/")

# Politeness controls so the testing agents never overwhelm the local container.
REQUEST_DELAY_SECONDS = float(os.getenv("REQUEST_DELAY_SECONDS", "0.2"))
MAX_REQUESTS_PER_TEST = int(os.getenv("MAX_REQUESTS_PER_TEST", "25"))


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


def validate_config() -> None:
    """Fail fast with a clear message when the API key is not configured."""
    if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
        raise ConfigError(
            "GEMINI_API_KEY is not set. Copy .env.example to .env and add your "
            "key from https://aistudio.google.com/app/apikey"
        )


def build_llm(temperature: float = 0.2) -> LLM:
    """Create the shared Gemini-backed LLM (low temperature = deterministic)."""
    validate_config()
    return LLM(model=MODEL_NAME, api_key=GEMINI_API_KEY, temperature=temperature)
