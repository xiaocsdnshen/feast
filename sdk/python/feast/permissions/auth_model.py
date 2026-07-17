# --------------------------------------------------------------------
# Extends OIDC client auth model with an optional `token` field.
# Works on Pydantic v2-only.
#
# Accepted credential sets (exactly **one** of):
#   1 pre-issued `token`
#   2 `client_secret`            (client-credentials flow)
#   3 `username` + `password` + `client_secret`  (ROPG)
# --------------------------------------------------------------------
from __future__ import annotations

from typing import Literal, Optional

from pydantic import ConfigDict, model_validator

from feast.repo_config import FeastConfigBaseModel


class AuthConfig(FeastConfigBaseModel):
    type: Literal["oidc", "kubernetes", "dacp", "knova", "no_auth"] = "no_auth"


class OidcAuthConfig(AuthConfig):
    auth_discovery_url: str
    client_id: str


class OidcClientAuthConfig(OidcAuthConfig):
    # any **one** of the four fields below is sufficient
    username: Optional[str] = None
    password: Optional[str] = None
    client_secret: Optional[str] = None
    token: Optional[str] = None  # pre-issued `token`

    @model_validator(mode="after")
    def _validate_credentials(self):
        """Enforce exactly one valid credential set."""
        has_user_pass = bool(self.username) and bool(self.password)
        has_secret = bool(self.client_secret)
        has_token = bool(self.token)

        # 1 static token
        if has_token and not (has_user_pass or has_secret):
            return self

        # 2 client_credentials
        if has_secret and not has_user_pass and not has_token:
            return self

        # 3 ROPG
        if has_user_pass and has_secret and not has_token:
            return self

        raise ValueError(
            "Invalid OIDC client auth combination: "
            "provide either\n"
            "  • token\n"
            "  • client_secret (without username/password)\n"
            "  • username + password + client_secret"
        )


class NoAuthConfig(AuthConfig):
    pass


class KubernetesAuthConfig(AuthConfig):
    # Optional user token for users (not service accounts)
    user_token: Optional[str] = None

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")


class DacpAuthConfig(AuthConfig):
    """
    DACP authentication configuration.

    Uses environment variables to generate JWT tokens:
    - DACP_USER_NAME: User name
    - DACP_GROUP_NAME: Group name
    - DACP_ROLE: Role
    """

    type: Literal["dacp"] = "dacp"
    # Optional custom environment variable names
    user_name_env: Optional[str] = "DACP_USER_NAME"
    group_name_env: Optional[str] = "DACP_GROUP_NAME"
    role_env: Optional[str] = "DACP_ROLE"


class KnovaAuthConfig(AuthConfig):
    """
    Knova authentication configuration.

    Uses environment variables to generate JWT tokens:
    - KNOVA_USER_NAME: User name
    - KNOVA_GROUP_NAME: Group name
    - KNOVA_ROLE: Role
    """

    type: Literal["knova"] = "knova"
    # Optional custom environment variable names
    user_name_env: Optional[str] = "KNOVA_USER_NAME"
    group_name_env: Optional[str] = "KNOVA_GROUP_NAME"
    role_env: Optional[str] = "KNOVA_ROLE"
