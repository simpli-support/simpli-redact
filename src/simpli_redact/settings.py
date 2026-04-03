"""Application settings loaded from environment variables."""

from simpli_core.connectors.settings import SalesforceSettings
from simpli_core.settings import SimpliSettings


class Settings(SimpliSettings, SalesforceSettings):
    litellm_model: str = "openai/gpt-5-mini"
    cors_origins: str = "*"
    redact_replacement: str = "[REDACTED]"
    detect_types: str = "credit_card,ssn,email,phone,address,name,account_number"


settings = Settings()
