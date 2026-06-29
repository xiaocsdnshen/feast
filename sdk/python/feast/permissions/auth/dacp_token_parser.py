import json
import logging
import os
from typing import Optional

import jwt
from starlette.authentication import AuthenticationError

from feast.permissions.auth.token_parser import TokenParser
from feast.permissions.user import User

logger = logging.getLogger(__name__)


class DacpTokenParser(TokenParser):
    """
    DACP Token Parser for server-side JWT validation.

    Parses unsigned JWT tokens with the following payload:
    {
        "group": "data_team",
        "role": "data_proc_fed,2",    # comma-separated roles
        "account": "admin",
        "iss": "dacp",
        "iat": 1234567890
    }

    Role mapping:
        - The "role" field supports comma-separated values (e.g., "data_proc_fed,2").
          Each role is split, trimmed, and looked up in DACP_ROLE_MAPPING.
          Unknown roles are skipped with a warning log.
        - External role names (e.g., "2", "data_proc_fed") can be mapped to Feast roles ("reader", "writer")
        - Configure via DACP_ROLE_MAPPING env variable, e.g.:
          DACP_ROLE_MAPPING='{"2":"writer","data_proc_fed":"writer","1":"reader"}'
    """

    def __init__(self):
        self.SECRET = os.getenv("JWT_SECRET", "123456789")
        # Load role mapping from environment variable
        self.role_mapping = self._load_role_mapping()

    def _load_role_mapping(self) -> dict:
        """Load role mapping from DACP_ROLE_MAPPING environment variable."""
        mapping_str = os.getenv(
            "DACP_ROLE_MAPPING", '{"data_proc_fed":"writer","2":"reader"}'
        )
        try:
            mapping = json.loads(mapping_str)
            logger.info(f"Loaded DACP role mapping: {mapping}")
            return mapping
        except json.JSONDecodeError as e:
            logger.warning(
                f"Invalid DACP_ROLE_MAPPING format: {e}. Using empty mapping."
            )
            return {}

    async def user_details_from_access_token(self, access_token: str) -> User:
        """
        Validate the DACP access token and extract user details.

        Returns:
            User: Current user with associated roles.

        Raises:
            AuthenticationError if token is invalid.
        """
        # 1. 检查 token 是否为空
        if not access_token:
            raise AuthenticationError("JWT_TOKEN_EMPTY: Missing authentication token")

        try:
            # DACP tokens are unsigned (issued by client-rbac from env vars)
            data = jwt.decode(
                access_token,
                self.SECRET,
                algorithms=["HS256"],
                # 允许服务端和客户端时间相差60秒
                leeway=60,
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("JWT_TOKEN_EXPIRED: Token has expired")
        except jwt.InvalidTokenError as e:
            logger.warning(e)
            raise AuthenticationError(f"JWT_TOKEN_INVALID: {str(e)}")
        except Exception as e:
            logger.warning(e)
            raise AuthenticationError(f"JWT_DECODE_ERROR: {str(e)}")

        # Build roles from claims
        roles = []

        # Add group as role
        group = data.get("group")
        account = data.get("account")
        raw_role = data.get("role")

        # 验证必需字段
        if not account:
            raise AuthenticationError("JWT_NO_ACCOUNT: No account found in token payload")
        if not group:
            raise AuthenticationError("JWT_NO_GROUP: No group found in token payload")
        if not raw_role:
            raise AuthenticationError("JWT_NO_ROLE: No role found in token payload")

        # Parse comma-separated roles and apply role mapping,
        # skip any unknown roles (not present in DACP_ROLE_MAPPING)
        mapped_roles = []
        for r in raw_role.split(","):
            r = r.strip()
            mapped = self.role_mapping.get(r)
            if mapped:
                mapped_roles.append(mapped)
            else:
                logger.warning(f"Unknown role '{r}' skipped, not in role mapping")

        if not mapped_roles:
            raise AuthenticationError("JWT_NO_ROLE: No role found in token payload")

        roles.extend(mapped_roles)

        logger.info(
            f"DACP authenticated user: {account}, "
            f"raw_role: {raw_role}, mapped_roles: {mapped_roles}, "
            f"roles: {roles}, cur_group: {group}"
        )

        return User(username=account, roles=roles, cur_group=group)
