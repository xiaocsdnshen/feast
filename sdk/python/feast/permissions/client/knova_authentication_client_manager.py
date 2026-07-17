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
import logging
import os
from datetime import datetime, timezone

import jwt

from feast.permissions.auth_model import KnovaAuthConfig
from feast.permissions.client.auth_client_manager import AuthenticationClientManager

logger = logging.getLogger(__name__)


class KnovaAuthClientManager(AuthenticationClientManager):
    """
    Knova 认证客户端管理器。

    从环境变量生成 JWT Token：
    - KNOVA_USER_NAME: 用户名（account claim）
    - KNOVA_GROUP_NAME: 组名（group claim）
    - KNOVA_ROLE: 角色（role claim）
    """

    def __init__(self, auth_config: KnovaAuthConfig):
        self.auth_config = auth_config
        logger.debug(f"KnovaAuthClientManager initialized with config: {auth_config}")

    def get_token(self) -> str:
        """
        从 Knova 环境变量生成 JWT Token。

        Returns:
            JWT token 字符串

        Raises:
            RuntimeError: 如果必需的环境变量未设置
        """
        # 从配置获取环境变量名
        user_name_env = self.auth_config.user_name_env or "KNOVA_USER_NAME"
        group_name_env = self.auth_config.group_name_env or "KNOVA_GROUP_NAME"
        role_env = self.auth_config.role_env or "KNOVA_ROLE"

        # 读取环境变量
        user_name = os.getenv(user_name_env)
        group_name = os.getenv(group_name_env)
        role = os.getenv(role_env)

        jwt_secret = os.getenv("JWT_SECRET", "123456789")

        # 验证必需的环境变量
        if not user_name:
            raise RuntimeError(
                f"Knova authentication requires {user_name_env} environment variable to be set"
            )
        if not group_name:
            raise RuntimeError(
                f"Knova authentication requires {group_name_env} environment variable to be set"
            )
        if not role:
            raise RuntimeError(
                f"Knova authentication requires {role_env} environment variable to be set"
            )

        # 构建 JWT payload
        payload = {
            "account": user_name,
            "group": group_name,
            "role": role,
            "iat": datetime.now(timezone.utc),
        }

        # 使用密钥生成 JWT
        token = jwt.encode(payload, jwt_secret, algorithm="HS256")

        logger.debug(
            f"Generated Knova JWT token for user: {user_name}, group: {group_name}, role: {role}"
        )
        return token
