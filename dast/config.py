"""
Configuration loading via pydantic-settings.
"""

from pathlib import Path
from typing import Optional

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # AWS Bedrock
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-east-1"
    aws_profile: Optional[str] = None

    # AI provider — which backend serves all LLM calls.
    #   "bedrock"   — AWS Bedrock (default; uses the AWS credential chain above)
    #   "anthropic" — Anthropic Messages API directly (uses anthropic_api_key)
    #   "openai"    — OpenAI-compatible chat completions (uses openai_api_key;
    #                 point openai_base_url at any compatible gateway if needed)
    #   "gateway"   — internal Claude apps gateway (Anthropic Messages API over an
    #                 OAuth JWT reused from the Claude Code CLI session; no API key)
    # The provider is selected at runtime; model_id is interpreted by whichever
    # provider is active (an ARN for Bedrock, a model name like
    # "claude-opus-4-8" or "gpt-4o" for the direct APIs / gateway).
    ai_provider: str = "bedrock"

    # Anthropic direct API
    anthropic_api_key: Optional[str] = None
    anthropic_base_url: str = "https://api.anthropic.com"

    # OpenAI (or OpenAI-compatible) API
    openai_api_key: Optional[str] = None
    openai_base_url: str = "https://api.openai.com/v1"

    # Claude apps gateway — the base URL is an INTERNAL hostname, so it has NO
    # default here (this repo is public). Set GATEWAY_BASE_URL in .env. Auth is
    # an OAuth JWT reused from the Claude Code CLI session (macOS Keychain), or
    # GATEWAY_JWT for headless/CI hosts — never an API key, never in this file.
    gateway_base_url: str = ""

    # The single source of truth for the three named model tiers. Set these
    # via .env to your own Bedrock application-inference-profile ARNs (or
    # Anthropic/OpenAI model names when ai_provider != "bedrock"). Every other
    # module (DashboardContext tiered defaults, the AI tab's model dropdowns)
    # reads these instead of hardcoding its own copy.
    anthropic_default_sonnet_model: str = "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/YOUR_SONNET_PROFILE_ID"
    anthropic_default_haiku_model: str = "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/YOUR_HAIKU_PROFILE_ID"
    anthropic_default_opus_model: str = "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/YOUR_OPUS_PROFILE_ID"

    # AI model — the active primary model. Defaults to the Sonnet tier above
    # when left unset in .env.
    ai_model_id: str = ""

    @model_validator(mode="after")
    def _default_ai_model_id(self) -> "Settings":
        if not self.ai_model_id:
            self.ai_model_id = self.anthropic_default_sonnet_model
        return self

    @property
    def model_presets(self) -> list[dict]:
        """The three named model tiers as (id, label) pairs, for populating UI dropdowns."""
        return [
            {"id": self.anthropic_default_sonnet_model, "label": "Claude Sonnet"},
            {"id": self.anthropic_default_haiku_model, "label": "Claude Haiku"},
            {"id": self.anthropic_default_opus_model, "label": "Claude Opus"},
        ]

    @property
    def ai_model_label(self) -> str:
        """Return a short human-readable label for the active model."""
        active = self.ai_model_id
        if self.anthropic_default_sonnet_model and active == self.anthropic_default_sonnet_model:
            return "sonnet"
        if self.anthropic_default_haiku_model and active == self.anthropic_default_haiku_model:
            return "haiku"
        if self.anthropic_default_opus_model and active == self.anthropic_default_opus_model:
            return "opus"
        # Fall back to parsing the model ID string
        import re
        m = re.search(r'claude-(opus|sonnet|haiku)', active, re.IGNORECASE)
        if m:
            return m.group(1).lower()
        return active.split("/")[-1].split(".")[-1] or active

    # Scan behaviour
    max_depth: int = 5
    max_pages: int = 200
    parallel_workers: int = 4
    request_delay_ms: int = 100
    browser_headless: bool = True

    # Attack engine
    max_attack_iterations: int = 3
    confidence_threshold: float = 0.7

    # Out-of-band interaction server (interactsh). Leave both unset to use the
    # ProjectDiscovery public servers. Point interactsh_server at a self-hosted
    # instance (and set interactsh_token if it requires auth) for private OOB.
    interactsh_server: Optional[str] = None
    interactsh_token: Optional[str] = None

    # Output
    output_dir: Path = Path("./scan-results")
    report_format: str = "html,json,markdown"

    # Database
    database_url: str = "sqlite+aiosqlite:///./dast.db"

    aws_session_token: Optional[str] = None

    def validate_aws(self) -> bool:
        if self.aws_profile:
            return True
        if self.aws_access_key_id and self.aws_secret_access_key:
            return True
        try:
            import boto3
            session = boto3.Session(region_name=self.aws_region)
            creds = session.get_credentials()
            return creds is not None and creds.get_frozen_credentials() is not None
        except Exception:
            return False

    def build_boto3_session(self):
        """
        Build a boto3 Session using the best available credentials.

        Priority:
        1. AWS_PROFILE (SSO or named profile) — use 'aws sso login --profile <name>' first
        2. Static credentials (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY)
        3. Default boto3 chain (instance profile, env vars, ~/.aws/credentials, etc.)
        """
        import boto3
        if self.aws_profile:
            return boto3.Session(profile_name=self.aws_profile, region_name=self.aws_region)
        if self.aws_access_key_id and self.aws_secret_access_key:
            kwargs = {
                "aws_access_key_id": self.aws_access_key_id,
                "aws_secret_access_key": self.aws_secret_access_key,
                "region_name": self.aws_region,
            }
            if self.aws_session_token:
                kwargs["aws_session_token"] = self.aws_session_token
            return boto3.Session(**kwargs)
        return boto3.Session(region_name=self.aws_region)


settings = Settings()
