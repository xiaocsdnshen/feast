import logging
import json
import threading
from importlib import resources as importlib_resources
from typing import Callable, Optional, Tuple

import uvicorn
from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from feast.infra.registry.remote import RemoteRegistry
import feast
import traceback

logger = logging.getLogger(__name__)

# ==================== SSO 错误码规范 ====================
# 2001: 无效token、token解析失败
# 2002: token签名校验失败（hmac校验失败，通常是签名密钥不对）
# 2003: token过期
# 2004: token参数异常（token中缺少关键参数，比如account）
# 2005: 系统内部错误（登录过程中发生不可预见的异常）
# 2999: 其它，在 ssoResultMsg 中详细说明

SSO_ERROR_CODES = {
    "JWT_TOKEN_EMPTY": ("2001", "Missing authentication token"),
    "JWT_TOKEN_INVALID": ("2001", "Invalid token format or parsing failed"),
    "JWT_SIGNATURE_INVALID": ("2002", "Token signature verification failed"),
    "JWT_TOKEN_EXPIRED": ("2003", "Token has expired"),
    "JWT_NO_GROUP": ("2004", "Missing required parameter: group"),
    "JWT_NO_ACCOUNT": ("2004", "Missing required parameter: user"),
    "JWT_NO_ROLE": ("2004", "Missing required parameter: role"),
    "INTERNAL_ERROR": ("2005", "Internal system error"),
    "UNKNOWN_ERROR": ("2999", "Unknown error"),
    "LOCAL_MODE_NOT_SUPPORTED": ("2005", "SSO only supported in registry remote mode"),
}


def parse_sso_error(error_msg: str) -> Tuple[str, str]:
    """
    解析 SSO 错误信息，返回 (error_code, error_msg)

    Args:
        error_msg: 错误信息字符串

    Returns:
        (error_code, error_message) 元组
    """
    if not error_msg:
        return SSO_ERROR_CODES["UNKNOWN_ERROR"]

    # 按优先级匹配错误标识
    if "JWT_TOKEN_EMPTY" in error_msg:
        return SSO_ERROR_CODES["JWT_TOKEN_EMPTY"]
    elif "JWT_SIGNATURE_INVALID" in error_msg or "signature" in error_msg.lower():
        return SSO_ERROR_CODES["JWT_SIGNATURE_INVALID"]
    elif "JWT_TOKEN_EXPIRED" in error_msg or "ExpiredSignatureError" in error_msg:
        return SSO_ERROR_CODES["JWT_TOKEN_EXPIRED"]
    elif "JWT_NO_GROUP" in error_msg:
        return SSO_ERROR_CODES["JWT_NO_GROUP"]
    elif "JWT_NO_ACCOUNT" in error_msg:
        return SSO_ERROR_CODES["JWT_NO_ACCOUNT"]
    elif "JWT_NO_ROLE" in error_msg:
        return SSO_ERROR_CODES["JWT_NO_ROLE"]
    elif "JWT_TOKEN_INVALID" in error_msg:
        return SSO_ERROR_CODES["JWT_TOKEN_INVALID"]
    elif "INTERNAL" in error_msg or "internal" in error_msg.lower():
        return SSO_ERROR_CODES["INTERNAL_ERROR"]
    else:
        # 返回 2999 并附带原始错误信息
        return ("2999", error_msg)


def get_app(
    store: "feast.FeatureStore",
    project_id: str,
    registry_ttl_secs: int,
    root_path: str = "",
):
    app = FastAPI()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Asynchronously refresh registry, notifying shutdown and canceling the active timer if the app is shutting down
    registry_proto = None
    shutting_down = False
    active_timer: Optional[threading.Timer] = None

    def async_refresh():
        store.refresh_registry()
        nonlocal registry_proto
        registry_proto = store.registry.proto()
        if shutting_down:
            return
        nonlocal active_timer
        active_timer = threading.Timer(registry_ttl_secs, async_refresh)
        active_timer.start()

    @app.on_event("shutdown")
    def shutdown_event():
        nonlocal shutting_down
        shutting_down = True
        if active_timer:
            active_timer.cancel()

    async_refresh()

    ui_dir_ref = importlib_resources.files(__spec__.parent) / "ui/build/"  # type: ignore[name-defined, arg-type]
    with importlib_resources.as_file(ui_dir_ref) as ui_dir:
        # Initialize with the projects-list.json file
        with ui_dir.joinpath("projects-list.json").open(mode="w") as f:
            # Get all projects from the registry
            discovered_projects = []
            registry = store.registry.proto()

            # Use the projects list from the registry
            if registry and registry.projects and len(registry.projects) > 0:
                for proj in registry.projects:
                    if proj.spec and proj.spec.name:
                        discovered_projects.append(
                            {
                                "name": proj.spec.name.replace("_", " ").title(),
                                "description": proj.spec.description
                                or f"Project: {proj.spec.name}",
                                "id": proj.spec.name,
                                "registryPath": f"{root_path}/registry",
                                "group": proj.spec.group if proj.spec.group else "",
                            }
                        )
            else:
                # If no projects in registry, use the current project from feature_store.yaml
                discovered_projects.append(
                    {
                        "name": "Project",
                        "description": "Test project",
                        "id": project_id,
                        "registryPath": f"{root_path}/registry",
                    }
                )

            # Add "All Projects" option at the beginning if there are multiple projects
            if len(discovered_projects) > 1:
                all_projects_entry = {
                    "name": "All Projects",
                    "description": "View data across all projects",
                    "id": "all",
                    "registryPath": f"{root_path}/registry",
                }
                discovered_projects.insert(0, all_projects_entry)

            projects_dict = {"projects": discovered_projects}
            f.write(json.dumps(projects_dict))

    @app.get("/auth/callback")
    async def auth_callback(request: Request):
        """
        SSO 登录回调接口

        其他平台调用此接口，Registry Server 验证 JWT 后设置 Cookie
        """
        try:
            token = request.query_params.get("dacp-token")
            if token is None:
                logger.warning("Missing dacp-token in query params")
                error_code, error_detail = SSO_ERROR_CODES["JWT_TOKEN_EMPTY"]
                return RedirectResponse(
                    url=f"{root_path}/error.html?error_code={error_code}",
                    status_code=302
                )
            logger.info("token = %s", token)
            # Registry Server 验证 JWT（通过调用 GetProjectsByJWT）
            if isinstance(store.registry, RemoteRegistry):
                from typing import cast
                remote_registry = cast(RemoteRegistry, store.registry)

                try:
                    # 调用 Registry Server 验证 JWT
                    projects = remote_registry.get_projects_by_jwt(
                        jwt_token=token,
                        allow_cache=True,
                    )
                    # 如果成功返回 projects，说明 JWT 有效
                    logger.info(f"JWT verified by Registry Server, found {len(projects)} projects")
                except Exception as e:
                    logger.warning("error===" + str(e))
                    error_msg = str(e)
                    # 使用统一的错误码解析
                    error_code, error_detail = parse_sso_error(error_msg)

                    return RedirectResponse(
                        url=f"{root_path}/error.html?error_code={error_code}",
                        status_code=302
                    )
            else:
                # Local mode 不支持 SSO
                error_code, error_detail = SSO_ERROR_CODES["LOCAL_MODE_NOT_SUPPORTED"]
                return RedirectResponse(
                    url=f"{root_path}/error.html?error_code={error_code}",
                    status_code=302
                )

            # JWT 验证通过，设置 HttpOnly Cookie，跳转到首页
            response = RedirectResponse(url=f"{root_path}/", status_code=302)
            response.set_cookie(
                key="dacp-token",
                value=token,
                httponly=True,
                secure=False,
                samesite="lax"
            )
            return response

        except Exception as e:
            logger.warning("error===" + str(e))
            error_code, _ = parse_sso_error(str(e))
            return RedirectResponse(
                url=f"{root_path}/error.html?error_code={error_code}",
                status_code=302
            )

    @app.get("/projects-list.json")
    def get_projects_list(request: Request):
        """
        动态返回项目列表 JSON（支持 Cookie 认证过滤）

        认证方式：
        - Cookie: dacp-token (HttpOnly JWT)

        流程：
        1. 从 Cookie 获取 JWT
        2. 通过 gRPC 调用 Registry Server 的 GetProjectsByJWT
        3. Registry Server 解析 JWT 获取 group 并过滤返回

        返回格式：
        {
            "projects": [
                {"name": "All Projects", "description": "...", "id": "all", "registryPath": "/registry", "group": ""},
                {"name": "Project1", "description": "...", "id": "project1", "registryPath": "/registry", "group": "retail_department"}
            ]
        }
        """
        try:
            # 从 Cookie 获取 JWT
            jwt_token = request.cookies.get("dacp-token")
            if not jwt_token:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Missing authentication token", "error_code": "2001"}
                )

            # 通过 gRPC 调用 Registry Server 获取过滤后的项目
            if isinstance(store.registry, RemoteRegistry):
                from typing import cast
                remote_registry = cast(RemoteRegistry, store.registry)

                try:
                    # 调用新的接口：Registry Server 解析 JWT 并过滤
                    projects = remote_registry.get_projects_by_jwt(
                        jwt_token=jwt_token,
                        allow_cache=True,
                    )
                except Exception as e:
                    error_msg = str(e)
                    logger.info(f"[projects-list] JWT error: {error_msg}")

                    # 使用统一的错误码解析
                    error_code, error_detail = parse_sso_error(error_msg)
                    return JSONResponse(
                        status_code=401 if error_code in ["2001", "2002", "2003"] else (400 if error_code == "2004" else 500),
                        content={"error": error_detail, "error_code": error_code}
                    )

                # 构造返回格式
                project_list = []
                for p in projects:
                    project_list.append({
                        "name": p.name.replace("_", " ").title(),
                        "description": p.description or f"Project: {p.name}",
                        "id": p.name,
                        "registryPath": f"{root_path}/registry",
                        "group": p.group,
                    })

                # 添加 "All Projects" 选项
                if len(project_list) > 0:
                    project_list.insert(0, {
                        "name": "All Projects",
                        "description": "View data across all projects",
                        "id": "all",
                        "registryPath": f"{root_path}/registry",
                    })

                logger.info(f"[projects-list] Returned {len(project_list)} projects from Registry Server")
                return {"projects": project_list}
            else:
                return JSONResponse(
                    status_code=500,
                    content={"error": "only supported in registry remote mode", "error_code": "2005"}
                )

        except Exception as e:
            logger.info(f"Error getting projects list: {e}")
            logger.info(traceback.format_exc())
            return JSONResponse(
                status_code=500,
                content={"error": str(e), "error_code": "2005", "projects": []}
            )

    @app.get("/registry")
    def read_registry(request: Request):
        if registry_proto is None:
            return JSONResponse(
                status_code=503,
                content={"error": "Registry not available", "error_code": "UNAVAILABLE"}
            )

        # logger.info(f"原始register = {registry_proto}")

        # 从 Cookie 获取 JWT
        jwt_token = request.cookies.get("dacp-token")

        if not jwt_token:
            return JSONResponse(
                status_code=401,
                content={"error": "Missing authentication token", "error_code": "2001"}
            )

        try:
            # 获取该用户组下的所有项目名称
            # Registry Server 解析 JWT 并返回过滤后的 projects
            # 延迟导入避免循环依赖
            from feast.infra.registry.remote import RemoteRegistry
            from typing import cast

            group = "unknown"  # 用于日志记录

            if isinstance(store.registry, RemoteRegistry):
                # 使用新的接口：传递 JWT，Registry Server 解析并过滤
                remote_registry = cast(RemoteRegistry, store.registry)
                try:
                    projects = remote_registry.get_projects_by_jwt(
                        jwt_token=jwt_token,
                        allow_cache=True,
                    )
                    logger.info(f"Got {len(projects)} projects from Registry Server")
                except Exception as e:
                    error_msg = str(e)
                    # 使用统一的错误码解析
                    error_code, error_detail = parse_sso_error(error_msg)
                    status_code = 401 if error_code in ["2001", "2002", "2003"] else (400 if error_code == "2004" else 500)
                    return JSONResponse(
                        status_code=status_code,
                        content={"error": error_detail, "error_code": error_code}
                    )
            else:
                error_code, error_detail = SSO_ERROR_CODES["LOCAL_MODE_NOT_SUPPORTED"]
                return JSONResponse(
                    status_code=500,
                    content={"error": error_detail, "error_code": error_code}
                )

            # 获取该 group 下的项目名称集合
            allowed_project_names = {p.name for p in projects}
            logger.info(f"Allowed projects for group '{group}': {allowed_project_names}")

            # 创建新的 Registry proto，只包含该 group 的数据
            from feast.protos.feast.core.Registry_pb2 import Registry as RegistryProto

            filtered_registry = RegistryProto()
            # 复制基础字段
            filtered_registry.registry_schema_version = registry_proto.registry_schema_version
            filtered_registry.version_id = registry_proto.version_id
            filtered_registry.last_updated.CopyFrom(registry_proto.last_updated)

            # 过滤 projects
            for project in registry_proto.projects:
                if project.spec.name in allowed_project_names:
                    filtered_registry.projects.append(project)

            # 过滤其他资源，只保留属于这些项目的
            def _get_project_name(resource):
                """获取资源所属的项目名称（处理不同资源类型的差异）"""
                # 方式1: 直接在顶层（如 data_source.project, saved_dataset.project）
                if hasattr(resource, 'project') and resource.project:
                    return resource.project
                # 方式2: 在 spec 中（如 feature_view.spec.project, entity.spec.project）
                if hasattr(resource, 'spec') and hasattr(resource.spec, 'project') and resource.spec.project:
                    return resource.spec.project
                return None

            def _filter_by_project(resources):
                """过滤资源，只保留属于允许项目的"""
                filtered = []
                for resource in resources:
                    project_name = _get_project_name(resource)
                    if project_name and project_name in allowed_project_names:
                        filtered.append(resource)
                return filtered

            # 过滤 entities
            for entity in _filter_by_project(registry_proto.entities):
                filtered_registry.entities.append(entity)

            # 过滤 feature_views
            for fv in _filter_by_project(registry_proto.feature_views):
                filtered_registry.feature_views.append(fv)

            # 过滤 on_demand_feature_views
            for odfv in _filter_by_project(registry_proto.on_demand_feature_views):
                filtered_registry.on_demand_feature_views.append(odfv)

            # 过滤 stream_feature_views
            for sfv in _filter_by_project(registry_proto.stream_feature_views):
                filtered_registry.stream_feature_views.append(sfv)

            # 过滤 feature_services
            for fs in _filter_by_project(registry_proto.feature_services):
                filtered_registry.feature_services.append(fs)

            # 过滤 data_sources
            for ds in _filter_by_project(registry_proto.data_sources):
                filtered_registry.data_sources.append(ds)

            # 过滤 saved_datasets
            for sd in _filter_by_project(registry_proto.saved_datasets):
                filtered_registry.saved_datasets.append(sd)

            # 过滤 validation_references
            for vr in _filter_by_project(registry_proto.validation_references):
                filtered_registry.validation_references.append(vr)

            # 过滤 permissions
            for perm in _filter_by_project(registry_proto.permissions):
                filtered_registry.permissions.append(perm)

            # 保留 infra（如果有的话）
            if registry_proto.HasField('infra'):
                filtered_registry.infra.CopyFrom(registry_proto.infra)

            logger.info(f"Filtered registry: {len(filtered_registry.projects)} projects, "
                  f"{len(filtered_registry.entities)} entities, "
                  f"{len(filtered_registry.feature_views)} feature_views"
                  f"{len(filtered_registry.on_demand_feature_views)} on_demand_feature_views"
                  f"{len(filtered_registry.feature_services)} on_demand_feature_views"
                  )

            # logger.info(f"过滤后register  = {filtered_registry}")
            return Response(
                content=filtered_registry.SerializeToString(),
                media_type="application/octet-stream",
            )

        except Exception as e:
            import traceback
            logger.info(f"Error in read_registry: {e}")
            logger.info(traceback.format_exc())
            error_code, _ = parse_sso_error(str(e))
            return JSONResponse(
                status_code=500,
                content={"error": str(e), "error_code": error_code}
            )

    @app.get("/health")
    def health():
        return (
            Response(status_code=status.HTTP_200_OK)
            if registry_proto
            else Response(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
        )

    # For all other paths (such as paths that would otherwise be handled by react router), pass to React
    @app.api_route("/p/{path_name:path}", methods=["GET"])
    def catch_all():
        filename = ui_dir.joinpath("index.html")

        with open(filename) as f:
            content = f.read()

        return Response(content, media_type="text/html")

    app.mount(
        "/",
        StaticFiles(directory=ui_dir, html=True),
        name="site",
    )

    return app


def start_server(
    store: "feast.FeatureStore",
    host: str,
    port: int,
    get_registry_dump: Callable,
    project_id: str,
    registry_ttl_sec: int,
    root_path: str = "",
    tls_key_path: str = "",
    tls_cert_path: str = "",
    log_level: str = "warning",
):
    app = get_app(
        store,
        project_id,
        registry_ttl_sec,
        root_path,
    )
    uvicorn_kwargs = dict(
        app=app,
        host=host,
        port=port,
        log_level=log_level.lower(),
    )
    if tls_key_path and tls_cert_path:
        uvicorn_kwargs["ssl_keyfile"] = tls_key_path
        uvicorn_kwargs["ssl_certfile"] = tls_cert_path
    uvicorn.run(**uvicorn_kwargs)
