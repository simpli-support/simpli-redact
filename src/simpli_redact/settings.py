"""Application settings loaded from environment variables."""

from simpli_core.connectors.settings import SalesforceSettings
from simpli_core.settings import CustomFieldSettings, SimpliSettings


class Settings(SimpliSettings, SalesforceSettings, CustomFieldSettings):
    litellm_model: str = "openrouter/google/gemini-2.5-flash-lite"
    redact_replacement: str = "[REDACTED]"
    detect_types: str = "credit_card,ssn,email,phone,address,name,account_number"


settings = Settings()
