# Copyright 2024 The Feast Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
import logging
import os

import jwt
from starlette.authentication import AuthenticationError

from feast.permissions.auth.token_parser import TokenParser
from feast.permissions.user import User

logger = logging.getLogger(__name__)


class KnovaTokenParser(TokenParser):
    """
    Knova Token Parser for server-side JWT validation.

    Parses HS256 JWT tokens with the following payload:
    {
        "group": "data_team",
        "role": "data_proc_fed,2",    # comma-separated roles
        "account": "admin",
        "iss": "knova",
        "iat": 1234567890
    }

    Role mapping:
        - The "role" field supports comma-separated values (e.g., "data_proc_fed,2").
          Each role is split, trimmed, and looked up in KNOVA_ROLE_MAPPING.
          Unknown roles are skipped with a warning log.
        - External role names (e.g., "2", "data_proc_fed") can be mapped to Feast roles ("reader", "writer")
        - Configure via KNOVA_ROLE_MAPPING env variable, e.g.:
          KNOVA_ROLE_MAPPING='{"2":"writer","data_proc_fed":"writer","1":"reader"}'
    """

    def __init__(self):
        self.SECRET = os.getenv("JWT_SECRET", "123456789")
        # 从环境变量加载角色映射
        self.role_mapping = self._load_role_mapping()

    def _load_role_mapping(self) -> dict:
        """从 KNOVA_ROLE_MAPPING 环境变量加载角色映射。"""
        mapping_str = os.getenv(
            "KNOVA_ROLE_MAPPING", '{"data_proc_fed":"writer","2":"reader"}'
        )
        try:
            mapping = json.loads(mapping_str)
            logger.info(f"Loaded Knova role mapping: {mapping}")
            return mapping
        except json.JSONDecodeError as e:
            logger.warning(
                f"Invalid KNOVA_ROLE_MAPPING format: {e}. Using empty mapping."
            )
            return {}

    async def user_details_from_access_token(self, access_token: str) -> User:
        """
        Validate the Knova access token and extract user details.

        Returns:
            User: Current user with associated roles.

        Raises:
            AuthenticationError if token is invalid.
        """
        # 1. 检查 token 是否为空
        if not access_token:
            raise AuthenticationError("JWT_TOKEN_EMPTY: Missing authentication token")

        try:
            # Knova tokens are signed with HS256
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

        # 从 claims 构建角色
        roles = []

        # 提取 claims
        group = data.get("group")
        account = data.get("account")
        raw_role = data.get("role")

        # 验证必需字段
        if not account:
            raise AuthenticationError(
                "JWT_NO_ACCOUNT: No account found in token payload"
            )
        if not group:
            raise AuthenticationError("JWT_NO_GROUP: No group found in token payload")
        if not raw_role:
            raise AuthenticationError("JWT_NO_ROLE: No role found in token payload")

        # 解析逗号分隔的角色并应用角色映射，
        # 跳过不在 KNOVA_ROLE_MAPPING 中的未知角色
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
            f"Knova authenticated user: {account}, "
            f"raw_role: {raw_role}, mapped_roles: {mapped_roles}, "
            f"roles: {roles}, cur_group: {group}"
        )

        return User(username=account, roles=roles, cur_group=group)
