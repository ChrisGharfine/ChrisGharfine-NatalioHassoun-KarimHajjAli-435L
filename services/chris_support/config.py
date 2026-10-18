from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CHRIS_", extra="ignore", hide_input_in_errors=True)

    database_url: str = Field(repr=False)
    jwt_verification_key: SecretStr
    jwt_algorithm: Literal["RS256", "ES256", "EdDSA", "HS256"] = "RS256"
    jwt_issuer: str = Field(min_length=1)
    jwt_audience: str = Field(min_length=1)
    jwt_role_claim: str = "role"
    jwt_account_status_claim: str = "account_status"
    jwt_active_status: str = "active"
    http_timeout_seconds: float = Field(default=5, gt=0, le=60)
    max_upstream_bytes: int = Field(default=5_000_000, ge=1, le=100_000_000)
    max_upstream_records: int = Field(default=50_000, ge=1, le=1_000_000)
    recent_limit: int = Field(default=10, ge=1, le=100)
    users_url: str = "http://users:8000"
    assets_url: str = "http://assets:8000"
    incidents_url: str = "http://incidents:8000"
    threats_url: str = "http://threats:8000"
    audit_url: str = "http://audit:8000"
    vulnerabilities_url: str = "http://vulnerabilities:8000"
    audit_service_token: SecretStr | None = None
    login_success_action: str = "auth.login.succeeded"
    login_failure_action: str = "auth.login.failed"

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
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("Service URLs require HTTP(S), a host, and no credentials/query/fragment")
        return value.rstrip("/")

    @model_validator(mode="after")
    def validate_key(self):
        key = self.jwt_verification_key.get_secret_value()
        if not key.strip():
            raise ValueError("JWT verification material must be configured")
        if self.jwt_algorithm == "HS256" and (len(key.encode()) < 32 or "-----BEGIN" in key):
            raise ValueError("HS256 requires a symmetric key of at least 32 bytes")
        if self.jwt_algorithm != "HS256":
            from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            try:
                public_key = load_pem_public_key(key.encode())
            except (ValueError, TypeError):
                raise ValueError("Configure a PEM public verification key for the chosen algorithm") from None
            valid = (
                self.jwt_algorithm == "RS256" and isinstance(public_key, rsa.RSAPublicKey)
                or self.jwt_algorithm == "ES256" and isinstance(public_key, ec.EllipticCurvePublicKey)
                and isinstance(public_key.curve, ec.SECP256R1)
                or self.jwt_algorithm == "EdDSA" and isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey))
            )
            if not valid:
                raise ValueError("JWT algorithm and public key type do not match")
        if self.login_success_action == self.login_failure_action:
            raise ValueError("Login success and failure action names must differ")
        return self
