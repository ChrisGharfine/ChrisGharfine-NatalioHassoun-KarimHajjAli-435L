from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CHRIS_", extra="ignore", hide_input_in_errors=True)

    database_url: str = Field(repr=False)
    jwt_verification_key: SecretStr
    jwt_algorithm: Literal["HS256"] = "HS256"
    jwt_issuer: str = Field(default="security-sprint1-users", min_length=1)
    jwt_audience: str = Field(default="security-sprint1-services", min_length=1)
    http_timeout_seconds: float = Field(default=5, gt=0, le=5)
    max_upstream_bytes: int = Field(default=5_000_000, ge=1, le=5_000_000)
    max_upstream_records: int = Field(default=50_000, ge=1, le=50_000)
    recent_limit: int = Field(default=10, ge=1, le=10)
    users_url: str = "http://127.0.0.1:8001/api/natalio-hassoun"
    assets_url: str = "http://127.0.0.1:8002"
    incidents_url: str = "http://127.0.0.1:8003"
    threats_url: str = "http://127.0.0.1:8004"
    audit_url: str = "http://127.0.0.1:8005/api/natalio-hassoun"
    vulnerabilities_url: str = "http://127.0.0.1:8007"
    service_tokens: dict[str, SecretStr] = Field(default_factory=dict, repr=False)
    login_success_action: str = "login_success"
    login_failure_action: str = "login_failed"

    def service_key(self, service_name: str) -> str:
        key = self.service_tokens.get(service_name)
        if key is None:
            raise ValueError("Required service credentials are not configured")
        return key.get_secret_value()

    @field_validator("database_url")
    @classmethod
    def postgres_only(cls, value: str) -> str:
        url = make_url(value)
        if url.drivername != "postgresql+psycopg":
            raise ValueError("Use a postgresql+psycopg database URL")
        return value

    @field_validator(
        "users_url", "assets_url", "incidents_url", "threats_url",
        "audit_url", "vulnerabilities_url",
    )
    @classmethod
    def valid_service_url(cls, value: str) -> str:
        from urllib.parse import urlsplit

        parsed = urlsplit(value)
        # Accessing .port validates malformed/non-numeric ports eagerly.
        parsed.port
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError("Service URLs require HTTP(S), a host, and no credentials/query/fragment")
        return value.rstrip("/")

    @model_validator(mode="after")
    def validate_key(self):
        key = self.jwt_verification_key.get_secret_value()
        if not key.strip():
            raise ValueError("JWT verification material must be configured")
        if len(key.encode()) < 32 or "-----BEGIN" in key:
            raise ValueError("HS256 requires a symmetric key of at least 32 bytes")
        known_services = {
            "users", "assets", "incidents", "threats", "logs", "reports",
            "vulnerabilities", "notifications", "playbooks",
        }
        if set(self.service_tokens) - known_services:
            raise ValueError("Service credentials contain an unknown service name")
        keys = [value.get_secret_value() for value in self.service_tokens.values()]
        if any(not 32 <= len(value) <= 8192 or not value.isascii()
               or any(not 33 <= ord(char) <= 126 for char in value) for value in keys):
            raise ValueError("Service keys require 32 to 8192 printable ASCII characters without spaces")
        if len(set(keys)) != len(keys) or key in keys:
            raise ValueError("Service keys must be distinct from each other and the JWT secret")
        if self.login_success_action == self.login_failure_action:
            raise ValueError("Login success and failure action names must differ")
        return self
