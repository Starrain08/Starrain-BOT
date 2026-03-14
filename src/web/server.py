# -*- coding: utf-8 -*-
import asyncio
import os
import sys
import time
import json
import logging
import secrets
import hashlib
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Depends, status, Query, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse, PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator, constr
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.utils.logger import get_logger

_logger = get_logger()

security = HTTPBearer(auto_error=False)

MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_TIME = 300
TOKEN_EXPIRE_HOURS = 24
MAX_MESSAGE_LENGTH = 5000
MAX_WS_CONNECTIONS = 10
MAX_WS_CONNECTIONS_PER_IP = 3
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 60
WS_CONNECT_RATE_LIMIT = 10
WS_CONNECT_RATE_WINDOW = 60


class WebConfig:
    def __init__(self):
        self.enabled: bool = True
        self.host: str = "127.0.0.1"
        self.port: int = 8080
        self.secret: str = ""
        self.username: str = "admin"
        self.password_hash: str = ""
        self._password_set: bool = False
        self.cors_origins: List[str] = []
        self.cors_allow_credentials: bool = True
        self.cors_max_age: int = 600


web_config = WebConfig()
bot_instance = None
web_app = None
web_server = None
ws_clients: Dict[str, WebSocket] = {}
log_buffer: List[str] = []
log_buffer_max = 500
SENSITIVE_PATTERNS = [
    (r'password["\']?\s*[:=]\s*["\']?[^"\'\s,}]+', 'password": "***"'),
    (r'token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_-]{20,}', 'token": "***"'),
    (r'access_token["\']?\s*[:=]\s*["\']?[^"\'\s,}]+', 'access_token": "***"'),
    (r'secret["\']?\s*[:=]\s*["\']?[^"\'\s,}]+', 'secret": "***"'),
    (r'Bearer\s+[a-zA-Z0-9_-]+', 'Bearer ***'),
]

login_attempts: Dict[str, Dict] = defaultdict(lambda: {"count": 0, "lock_until": 0})
active_tokens: Dict[str, Dict] = {}
rate_limits: Dict[str, List[float]] = defaultdict(list)
ws_nonces: Dict[str, Dict] = {}
csrf_tokens: Dict[str, Dict] = {}
ws_connection_info: Dict[str, Dict] = {}
ws_connection_attempts: Dict[str, List[float]] = defaultdict(list)
token_salts: Dict[str, Dict] = {}
WS_NONCE_EXPIRE_SECONDS = 60
CSRF_EXPIRE_SECONDS = 3600
TOKEN_SALT_LENGTH = 32
TOKEN_HASH_ITERATIONS = 100000


def generate_csrf_token(token: str) -> str:
    csrf_token = secrets.token_urlsafe(32)
    csrf_tokens[token] = {
        "csrf_token": csrf_token,
        "created": datetime.now(),
        "expires": datetime.now() + timedelta(seconds=CSRF_EXPIRE_SECONDS)
    }
    expired_tokens = [t for t, data in csrf_tokens.items() if datetime.now() > data["expires"]]
    for t in expired_tokens:
        del csrf_tokens[t]
    return csrf_token


def verify_csrf_token(token: str, csrf_token: str) -> bool:
    if token not in csrf_tokens:
        return False
    token_data = csrf_tokens[token]
    if datetime.now() > token_data["expires"]:
        del csrf_tokens[token]
        return False
    return secrets.compare_digest(token_data["csrf_token"], csrf_token)


def generate_ws_nonce() -> str:
    nonce = secrets.token_urlsafe(32)
    ws_nonces[nonce] = {
        "created": datetime.now(),
        "expires": datetime.now() + timedelta(seconds=WS_NONCE_EXPIRE_SECONDS)
    }
    expired = [n for n, d in ws_nonces.items() if datetime.now() > d["expires"]]
    for n in expired:
        del ws_nonces[n]
    return nonce


def verify_ws_signature(nonce: str, signature: str) -> str:
    if nonce not in ws_nonces:
        return None
    nonce_data = ws_nonces[nonce]
    if datetime.now() > nonce_data["expires"]:
        del ws_nonces[nonce]
        return None
    for token, token_info in active_tokens.items():
        if datetime.now() > token_info["expires"]:
            continue
        expected = hashlib.sha256(f"{nonce}:{token}".encode()).hexdigest()
        if secrets.compare_digest(signature, expected):
            del ws_nonces[nonce]
            return token
    return None


def sanitize_log_message(message: str) -> str:
    import re
    sanitized = message
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m|\033\[[0-9;]*m|\[\d+(?:;\d+)*m')
    sanitized = ansi_escape.sub('', sanitized)
    colorlog_pattern = re.compile(r'\[(?:\d+;)*\d+m|\[m')
    sanitized = colorlog_pattern.sub('', sanitized)
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
    return sanitized


class LogHandler(logging.Handler):
    def emit(self, record):
        global log_buffer
        log_line = self.format(record)
        log_line = sanitize_log_message(log_line)
        log_buffer.append(log_line)
        if len(log_buffer) > log_buffer_max:
            log_buffer = log_buffer[-log_buffer_max:]


def hash_password(password: str, salt: str = None) -> tuple:
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt, hashed.hex()


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    _, computed_hash = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def is_valid_token(token: str, client_ip: str = None) -> bool:
    if token not in active_tokens:
        return False
    token_info = active_tokens[token]
    if datetime.now() > token_info["expires"]:
        del active_tokens[token]
        return False
    if client_ip and token_info.get("ip") and token_info["ip"] != client_ip:
        del active_tokens[token]
        return False
    return True


def generate_token_salt(token: str) -> str:
    """为token生成盐值"""
    salt = secrets.token_urlsafe(TOKEN_SALT_LENGTH)
    token_salts[token] = {
        "salt": salt,
        "created": datetime.now(),
        "expires": datetime.now() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    }
    return salt


def get_token_salt(token: str) -> Optional[str]:
    """获取token的盐值"""
    if token not in token_salts:
        return None
    salt_info = token_salts[token]
    if datetime.now() > salt_info["expires"]:
        del token_salts[token]
        return None
    return salt_info["salt"]


def hash_token_with_salt(token: str, salt: str) -> str:
    """使用盐值对token进行哈希"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        token.encode(),
        salt.encode(),
        TOKEN_HASH_ITERATIONS
    ).hex()


def verify_hashed_token(hashed_token: str, client_ip: str = None) -> Optional[str]:
    """验证哈希token并返回原始token，如果无效返回None"""
    global active_tokens, token_salts
    
    # 遍历所有active tokens，尝试匹配哈希
    for token, token_info in active_tokens.items():
        # 检查token是否过期
        if datetime.now() > token_info["expires"]:
            continue
        
        # 检查IP是否匹配（如果提供了）
        if client_ip and token_info.get("ip") and token_info["ip"] != client_ip:
            continue
        
        # 获取盐值
        salt = get_token_salt(token)
        if not salt:
            continue
        
        # 计算预期哈希
        expected_hash = hash_token_with_salt(token, salt)
        
        # 使用constant-time比较哈希
        if secrets.compare_digest(hashed_token, expected_hash):
            return token
    
    return None


def check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    requests = rate_limits[client_ip]
    rate_limits[client_ip] = [t for t in requests if now - t < RATE_LIMIT_WINDOW]
    if len(rate_limits[client_ip]) >= RATE_LIMIT_REQUESTS:
        return False
    rate_limits[client_ip].append(now)
    return True


def check_ws_connection_limits(client_ip: str) -> bool:
    """检查WebSocket连接限制"""
    global ws_connection_info
    
    # 清理过期的连接记录
    current_time = datetime.now()
    expired_tokens = []
    for token, info in ws_connection_info.items():
        if current_time > info.get("expires", current_time):
            expired_tokens.append(token)
    
    for token in expired_tokens:
        if token in ws_connection_info:
            del ws_connection_info[token]
    
    # 检查总连接数限制
    if len(ws_connection_info) >= MAX_WS_CONNECTIONS:
        return False
    
    # 检查该IP的连接数限制
    ip_connections = sum(1 for info in ws_connection_info.values() if info.get("client_ip") == client_ip)
    if ip_connections >= MAX_WS_CONNECTIONS_PER_IP:
        return False
    
    return True


def check_ws_connection_rate(client_ip: str) -> bool:
    """检查WebSocket连接频率限制"""
    global ws_connection_attempts
    
    now = time.time()
    attempts = ws_connection_attempts[client_ip]
    # 清理过期的连接尝试记录
    ws_connection_attempts[client_ip] = [t for t in attempts if now - t < WS_CONNECT_RATE_WINDOW]
    
    # 检查连接频率
    if len(ws_connection_attempts[client_ip]) >= WS_CONNECT_RATE_LIMIT:
        return False
    
    # 记录这次连接尝试
    ws_connection_attempts[client_ip].append(now)
    return True


def cleanup_stale_websocket_connections():
    """清理过期的WebSocket连接"""
    global ws_connection_info
    
    current_time = datetime.now()
    stale_timeout_seconds = 300  # 5分钟无活动视为过期
    
    stale_tokens = []
    for token, info in ws_connection_info.items():
        last_activity = info.get("last_activity", current_time)
        if (current_time - last_activity).seconds > stale_timeout_seconds:
            stale_tokens.append(token)
    
    for token in stale_tokens:
        connection_info = ws_connection_info.pop(token, {})
        _logger.warning(f"清理过期WebSocket连接: IP={connection_info.get('client_ip')}, Token={token[:10]}")


def check_login_attempts(ip: str) -> bool:
    now = time.time()
    attempt = login_attempts[ip]
    if attempt["lock_until"] > now:
        return False
    return True


def record_login_failure(ip: str):
    now = time.time()
    attempt = login_attempts[ip]
    attempt["count"] += 1
    if attempt["count"] >= MAX_LOGIN_ATTEMPTS:
        attempt["lock_until"] = now + LOGIN_LOCKOUT_TIME
        attempt["count"] = 0


def reset_login_attempts(ip: str):
    if ip in login_attempts:
        del login_attempts[ip]


def init_web(bot, config: dict):
    global bot_instance, web_config, web_app
    bot_instance = bot
    _logger = get_logger()
    
    web_cfg = config.get('web', {})
    web_config.enabled = web_cfg.get('enabled', True)
    web_config.host = web_cfg.get('host', '127.0.0.1')
    web_config.port = web_cfg.get('port', 8080)
    web_config.secret = web_cfg.get('secret', '')
    web_config.username = web_cfg.get('username', 'admin')
    
    # 读取CORS配置
    web_config.cors_origins = web_cfg.get('cors_origins', [])
    web_config.cors_allow_credentials = web_cfg.get('cors_allow_credentials', True)
    web_config.cors_max_age = web_cfg.get('cors_max_age', 600)
    
    password = web_cfg.get('password', '')
    if not password:
        password = secrets.token_urlsafe(12)
        _logger.warning("未设置Web密码，已自动生成随机密码")
        _logger.warning(f"生成的密码 (请妥善保存): {password}")
        _logger.warning("请在 config.yaml 中设置 web.password 以使用自定义密码")
    salt, hashed = hash_password(password)
    web_config.password_hash = f"{salt}:{hashed}"
    web_config._password_set = bool(web_cfg.get('password', ''))
    
    if web_config.host not in ('127.0.0.1', 'localhost'):
        _logger.warning("=" * 60)
        _logger.warning("安全警告: Web后台监听非本地地址!")
        _logger.warning(f"当前监听: {web_config.host}:{web_config.port}")
        _logger.warning("建议使用反向代理(如Nginx)配置HTTPS后再对外暴露")
        _logger.warning("否则Token将以明文形式传输，存在被窃取风险!")
        _logger.warning("=" * 60)
    
    log_handler = LogHandler()
    log_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logging.getLogger().addHandler(log_handler)
    
    web_app = create_app()
    return web_app


def get_bot():
    if bot_instance is None:
        raise HTTPException(status_code=503, detail="Service unavailable")
    return bot_instance


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def verify_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    client_ip = get_client_ip(request)
    
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="请求过于频繁，请稍后再试")
    
    if credentials is None:
        raise HTTPException(status_code=401, detail="未授权访问")
    
    token = credentials.credentials
    
    # 首先尝试直接验证token（向后兼容）
    if is_valid_token(token, client_ip):
        return True
    
    # 如果直接验证失败，尝试验证哈希token
    original_token = verify_hashed_token(token, client_ip)
    if original_token:
        return True
    
    raise HTTPException(status_code=401, detail="Token无效或已过期")


async def verify_ws_token(token: str, client_ip: str = None) -> bool:
    if not token:
        return False
    return is_valid_token(token, client_ip)


async def verify_csrf(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    if not check_rate_limit(request.client.host if request.client else "unknown"):
        raise HTTPException(status_code=429, detail="请求过于频繁")
    
    if credentials is None:
        raise HTTPException(status_code=401, detail="未授权访问")
    
    token = credentials.credentials
    
    if not is_valid_token(token, request.client.host if request.client else "unknown"):
        raise HTTPException(status_code=401, detail="Token无效或已过期")
    
    csrf_token = request.headers.get("X-CSRF-Token")
    if not csrf_token:
        csrf_token = request.headers.get("X-XSRF-Token")
    
    if not csrf_token:
        raise HTTPException(status_code=403, detail="缺少CSRF令牌")
    
    if not verify_csrf_token(token, csrf_token):
        raise HTTPException(status_code=403, detail="CSRF令牌无效或已过期")
    
    return True


class LoginRequest(BaseModel):
    username: constr(min_length=1, max_length=50)
    password: constr(min_length=1, max_length=100)


class PluginAction(BaseModel):
    plugin_name: constr(min_length=1, max_length=100)
    
    @validator('plugin_name')
    def validate_plugin_name(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('插件名称格式无效')
        return v


class PermissionUser(BaseModel):
    qq: int
    
    @validator('qq')
    def validate_qq(cls, v):
        if v <= 0 or v > 10**12:
            raise ValueError('无效的QQ号')
        return v


class GroupBlacklist(BaseModel):
    group_id: int
    
    @validator('group_id')
    def validate_group_id(cls, v):
        if v <= 0 or v > 10**12:
            raise ValueError('无效的群号')
        return v


class RestartRequest(BaseModel):
    confirm: bool


class SendMessageRequest(BaseModel):
    message_type: str
    user_id: Optional[int] = None
    group_id: Optional[int] = None
    message: constr(min_length=1, max_length=MAX_MESSAGE_LENGTH)
    
    @validator('message_type')
    def validate_message_type(cls, v):
        if v not in ['private', 'group']:
            raise ValueError('消息类型必须是 private 或 group')
        return v


async def broadcast_to_ws(data: dict):
    global ws_clients, ws_connection_info
    message = json.dumps(data, ensure_ascii=False)
    disconnected = []
    for token, client in ws_clients.items():
        try:
            await client.send_text(message)
            # 更新最后活动时间
            if token in ws_connection_info:
                ws_connection_info[token]["last_activity"] = datetime.now()
        except Exception as e:
            _logger.warning(f"WebSocket消息发送失败: Token={token[:10]}, 错误={str(e)}")
            disconnected.append(token)
    
    for token in disconnected:
        if token in ws_clients:
            del ws_clients[token]
        if token in ws_connection_info:
            connection_info = ws_connection_info.pop(token)
            _logger.info(f"WebSocket连接清理(发送失败): IP={connection_info.get('client_ip', 'unknown')}")


def create_app() -> FastAPI:
    # 在函数内部获取logger，确保已初始化
    logger = get_logger()
    
    app = FastAPI(
        title="Starrain-BOT 管理后台",
        description="QQ机器人Web管理系统",
        version="2.0.0",
        docs_url=None,
        redoc_url=None
    )
    
    cors_origins = []
    
    # 如果用户指定了自定义CORS origins，使用用户配置
    if web_config.cors_origins:
        cors_origins = web_config.cors_origins
        logger.info(f"使用自定义CORS origins: {cors_origins}")
    else:
        # 使用严格的默认CORS origins
        cors_origins = [
            f"http://localhost:{web_config.port}",
            f"http://127.0.0.1:{web_config.port}",
        ]
        
        # 只有当host为0.0.0.0时才添加本地网络访问
        if web_config.host == "0.0.0.0":
            logger.warning("=" * 60)
            logger.warning("CORS安全警告: Web后台监听非本地地址!")
            logger.warning("默认仅允许localhost和127.0.0.1访问")
            logger.warning("如需允许其他域名访问，请在config.yaml中配置:")
            logger.warning("  web:")
            logger.warning("    cors_origins:")
            logger.warning("      - http://your-domain.com")
            logger.warning("=" * 60)
        else:
            logger.info(f"使用默认CORS origins: {cors_origins}")
    
    # 验证CORS origins格式
    valid_origins = []
    for origin in cors_origins:
        origin = origin.strip()
        if not origin:
            continue
        # 简单验证URL格式
        if origin in ('*', 'null'):
            logger.error(f"CORS配置错误: 不允许使用 '{origin}' 作为origin")
            continue
        if not origin.startswith(('http://', 'https://')):
            logger.error(f"CORS配置错误: origin '{origin}' 必须以http://或https://开头")
            continue
        valid_origins.append(origin)
    
    if not valid_origins:
        # 如果没有有效的origins，使用最严格的默认值
        valid_origins = [f"http://localhost:{web_config.port}", f"http://127.0.0.1:{web_config.port}"]
        logger.warning(f"由于CORS配置无效，使用默认值: {valid_origins}")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=valid_origins,
        allow_credentials=web_config.cors_allow_credentials,
        allow_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-CSRF-Token",
            "X-XSRF-Token",
            "X-Requested-With"
        ],
        expose_headers=["X-CSRF-Token", "Content-Disposition"],
        max_age=web_config.cors_max_age,
        allow_origin_regex=None,  # 禁用正则表达式匹配
    )
    
    static_dir = Path(__file__).parent / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    
    @app.get("/", response_class=HTMLResponse)
    async def index():
        login_file = static_dir / "login.html"
        if login_file.exists():
            return FileResponse(login_file, media_type="text/html")
        return HTMLResponse(content=get_fallback_html(), status_code=200)
    
    @app.get("/app", response_class=HTMLResponse)
    async def app_page():
        app_file = static_dir / "app.html"
        if app_file.exists():
            return FileResponse(app_file, media_type="text/html")
        return HTMLResponse(content=get_fallback_html(), status_code=200)
    
    @app.get("/robots.txt")
    async def robots():
        robots_file = static_dir / "robots.txt"
        if robots_file.exists():
            return FileResponse(robots_file, media_type="text/plain")
        return PlainTextResponse("User-agent: *\nDisallow: /")
    
    @app.post("/api/login")
    async def login(request: Request, req: LoginRequest):
        client_ip = get_client_ip(request)
        
        if not check_login_attempts(client_ip):
            lock_remaining = int(login_attempts[client_ip]["lock_until"] - time.time())
            raise HTTPException(
                status_code=429, 
                detail=f"登录失败次数过多，请{lock_remaining}秒后再试"
            )
        
        if not check_rate_limit(client_ip):
            raise HTTPException(status_code=429, detail="请求过于频繁")
        
        try:
            parts = web_config.password_hash.split(":")
            if len(parts) != 2:
                is_valid = False
            else:
                salt, stored_hash = parts
                is_valid = verify_password(req.password, salt, stored_hash)
        except Exception:
            is_valid = False
        
        if req.username != web_config.username or not is_valid:
            record_login_failure(client_ip)
            raise HTTPException(status_code=401, detail="用户名或密码错误")
        
        reset_login_attempts(client_ip)
        
        token = generate_token()
        active_tokens[token] = {
            "expires": datetime.now() + timedelta(hours=TOKEN_EXPIRE_HOURS),
            "ip": client_ip,
            "created": datetime.now()
        }
        
        # 为token生成盐值
        token_salt = generate_token_salt(token)
        
        # 计算token哈希（用于安全传输）
        token_hash = hash_token_with_salt(token, token_salt)
        
        csrf_token = generate_csrf_token(token)
        
        # 安全提示
        security_hint = f"Token哈希已启用，盐值长度: {TOKEN_SALT_LENGTH}字符"
        
        response = {
            "success": True, 
            "token": token,  # 保留原始token，客户端可以选择使用哈希或原始token
            "token_salt": token_salt,  # 提供盐值给客户端
            "token_hash": token_hash,  # 提供预计算的哈希
            "csrf_token": csrf_token,
            "expires_in": TOKEN_EXPIRE_HOURS * 3600,
            "security_info": {
                "token_hash_enabled": True,
                "salt_length": TOKEN_SALT_LENGTH,
                "hash_iterations": TOKEN_HASH_ITERATIONS,
                "hint": security_hint
            }
        }
        
        return JSONResponse(content=response, headers={
            "X-CSRF-Token": csrf_token,
            "X-Auth-Token-Salt": token_salt,
            "X-Auth-Token-Hash": token_hash
        })
    
    @app.post("/api/logout")
    async def logout(
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        if credentials:
            token = credentials.credentials
            
            # 检查是否是哈希token
            original_token = None
            if token not in active_tokens:
                original_token = verify_hashed_token(token)
            
            # 清理原始token（验证失败时使用哈希token）
            token_to_remove = original_token if original_token else token
            
            if token_to_remove in active_tokens:
                del active_tokens[token_to_remove]
            if token_to_remove in csrf_tokens:
                del csrf_tokens[token_to_remove]
            if token_to_remove in token_salts:
                del token_salts[token_to_remove]
            
            # 同时清理哈希token本身（如果传入的不是原始token）
            if token != token_to_remove and token in active_tokens:
                del active_tokens[token]
            if token != token_to_remove and token in csrf_tokens:
                del csrf_tokens[token]
            if token != token_to_remove and token in token_salts:
                del token_salts[token]
                
        return {"success": True, "message": "已退出登录"}
    
    @app.get("/api/ws/nonce")
    async def get_ws_nonce(auth: bool = Depends(verify_auth)):
        nonce = generate_ws_nonce()
        return {"nonce": nonce, "expires_in": WS_NONCE_EXPIRE_SECONDS}
    
    @app.get("/api/ws/connections")
    async def get_ws_connections(auth: bool = Depends(verify_auth)):
        global ws_connection_info
        connections = []
        current_time = datetime.now()
        
        for token, info in ws_connection_info.items():
            connections.append({
                "ip": info.get("client_ip", "unknown"),
                "connected_time": info.get("connected_at").isoformat(),
                "last_activity": info.get("last_activity").isoformat(),
                "message_count": info.get("message_count", 0),
                "idle_seconds": (current_time - info.get("last_activity", current_time)).seconds,
                "token": token[:10] + "..." if len(token) > 10 else token
            })
        
        return {
            "total_connections": len(ws_connection_info),
            "max_connections": MAX_WS_CONNECTIONS,
            "connections": connections
        }
    
    @app.get("/api/ws/stats")
    async def get_ws_stats(auth: bool = Depends(verify_auth)):
        global ws_connection_info, ws_connection_attempts
        
        # 统计各IP的连接数
        ip_stats = {}
        for info in ws_connection_info.values():
            ip = info.get("client_ip", "unknown")
            if ip not in ip_stats:
                ip_stats[ip] = 0
            ip_stats[ip] += 1
        
        # 统计连接尝试频率
        attempt_stats = {}
        current_time = time.time()
        for ip, attempts in ws_connection_attempts.items():
            recent_attempts = [t for t in attempts if current_time - t < WS_CONNECT_RATE_WINDOW]
            attempt_stats[ip] = len(recent_attempts)
        
        return {
            "total_connections": len(ws_connection_info),
            "max_connections": MAX_WS_CONNECTIONS,
            "max_connections_per_ip": MAX_WS_CONNECTIONS_PER_IP,
            "connection_rate_limit": WS_CONNECT_RATE_LIMIT,
            "connection_rate_window": WS_CONNECT_RATE_WINDOW,
            "ip_connections": ip_stats,
            "recent_connection_attempts": attempt_stats
        }
    
    @app.get("/api/status")
    async def get_status(auth: bool = Depends(verify_auth)):
        bot = get_bot()
        uptime = bot.uptime_seconds
        adapters_info = []
        for a in bot.adapters:
            name = a.__class__.__name__
            connected = getattr(a, "connected", False) or (getattr(a, "is_connected", lambda: False)())
            adapters_info.append({"name": name, "connected": connected})
        
        import platform
        try:
            import psutil
            mem = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=0.1)
            mem_info = {"percent": mem.percent, "available": mem.available // (1024*1024)}
        except ImportError:
            cpu_percent = 0
            mem_info = {"percent": 0, "available": 0}
        
        return {
            "qq": bot.qq,
            "uptime": uptime,
            "uptime_formatted": format_uptime(uptime),
            "running": bot._running,
            "adapters": adapters_info,
            "plugins_count": len(bot.plugin_manager.plugins),
            "enabled_plugins_count": len(bot.plugin_manager.enabled_plugins),
            "system": {
                "python": sys.version.split()[0],
                "platform": f"{platform.system()} {platform.release()}",
                "cpu_cores": os.cpu_count() or 0,
                "cpu_percent": cpu_percent,
                "memory": mem_info
            }
        }
    
    @app.get("/api/plugins")
    async def list_plugins(auth: bool = Depends(verify_auth)):
        bot = get_bot()
        plugins = []
        for name, plugin in bot.plugin_manager.plugins.items():
            enabled = name in bot.plugin_manager.enabled_plugins
            meta = plugin.metadata
            if isinstance(meta, dict):
                version = meta.get("version", "?")
                author = meta.get("author", "Unknown")
                description = meta.get("description", "")
            else:
                version = getattr(meta, "version", "?")
                author = getattr(meta, "author", "Unknown")
                description = getattr(meta, "description", "")
            plugins.append({
                "name": name,
                "enabled": enabled,
                "version": version,
                "author": author,
                "description": description
            })
        return {"plugins": plugins}
    
    @app.post("/api/plugins/enable")
    async def enable_plugin(req: PluginAction, auth: bool = Depends(verify_csrf)):
        bot = get_bot()
        ok = bot.plugin_manager.enable_plugin(req.plugin_name)
        if ok:
            await broadcast_to_ws({"type": "plugin_update", "action": "enable", "plugin": req.plugin_name})
            return {"success": True, "message": f"插件 {req.plugin_name} 已启用"}
        raise HTTPException(status_code=400, detail="启用插件失败")
    
    @app.post("/api/plugins/disable")
    async def disable_plugin(req: PluginAction, auth: bool = Depends(verify_csrf)):
        bot = get_bot()
        ok = bot.plugin_manager.disable_plugin(req.plugin_name)
        if ok:
            await broadcast_to_ws({"type": "plugin_update", "action": "disable", "plugin": req.plugin_name})
            return {"success": True, "message": f"插件 {req.plugin_name} 已禁用"}
        raise HTTPException(status_code=400, detail="禁用插件失败")
    
    @app.post("/api/plugins/reload")
    async def reload_plugin(req: PluginAction, auth: bool = Depends(verify_csrf)):
        bot = get_bot()
        ok = bot.plugin_manager.reload_plugin(req.plugin_name)
        if ok:
            await broadcast_to_ws({"type": "plugin_update", "action": "reload", "plugin": req.plugin_name})
            return {"success": True, "message": f"插件 {req.plugin_name} 已重载"}
        raise HTTPException(status_code=400, detail="重载插件失败")
    
    @app.get("/api/permissions/admins")
    async def list_admins(auth: bool = Depends(verify_auth)):
        bot = get_bot()
        return {
            "admins": bot.permission_manager.list_admins(),
            "owners": bot.permission_manager.list_owners(),
            "developers": bot.permission_manager.list_developers()
        }
    
    @app.post("/api/permissions/admins/add")
    async def add_admin(req: PermissionUser, auth: bool = Depends(verify_csrf)):
        bot = get_bot()
        bot.permission_manager.add_admin(req.qq)
        await broadcast_to_ws({"type": "permission_update", "level": "admin"})
        return {"success": True, "message": f"已添加管理员: {req.qq}"}
    
    @app.post("/api/permissions/admins/remove")
    async def remove_admin(req: PermissionUser, auth: bool = Depends(verify_csrf)):
        bot = get_bot()
        bot.permission_manager.remove_admin(req.qq)
        await broadcast_to_ws({"type": "permission_update", "level": "admin"})
        return {"success": True, "message": f"已移除管理员: {req.qq}"}
    
    @app.post("/api/permissions/owners/add")
    async def add_owner(req: PermissionUser, auth: bool = Depends(verify_csrf)):
        bot = get_bot()
        bot.permission_manager.add_owner(req.qq)
        await broadcast_to_ws({"type": "permission_update", "level": "owner"})
        return {"success": True, "message": f"已添加所有者: {req.qq}"}
    
    @app.post("/api/permissions/owners/remove")
    async def remove_owner(req: PermissionUser, auth: bool = Depends(verify_csrf)):
        bot = get_bot()
        bot.permission_manager.remove_owner(req.qq)
        await broadcast_to_ws({"type": "permission_update", "level": "owner"})
        return {"success": True, "message": f"已移除所有者: {req.qq}"}
    
    @app.post("/api/permissions/developers/add")
    async def add_developer(req: PermissionUser, auth: bool = Depends(verify_csrf)):
        bot = get_bot()
        bot.permission_manager.add_developer(req.qq)
        await broadcast_to_ws({"type": "permission_update", "level": "developer"})
        return {"success": True, "message": f"已添加开发者: {req.qq}"}
    
    @app.post("/api/permissions/developers/remove")
    async def remove_developer(req: PermissionUser, auth: bool = Depends(verify_csrf)):
        bot = get_bot()
        bot.permission_manager.remove_developer(req.qq)
        await broadcast_to_ws({"type": "permission_update", "level": "developer"})
        return {"success": True, "message": f"已移除开发者: {req.qq}"}
    
    @app.get("/api/blacklist")
    async def list_blacklist(auth: bool = Depends(verify_auth)):
        bot = get_bot()
        return {"groups": bot.permission_manager.list_blacklisted_groups()}
    
    @app.post("/api/blacklist/add")
    async def add_blacklist(req: GroupBlacklist, auth: bool = Depends(verify_csrf)):
        bot = get_bot()
        bot.permission_manager.add_group_blacklist(req.group_id)
        await broadcast_to_ws({"type": "blacklist_update"})
        return {"success": True, "message": f"已拉黑群: {req.group_id}"}
    
    @app.post("/api/blacklist/remove")
    async def remove_blacklist(req: GroupBlacklist, auth: bool = Depends(verify_csrf)):
        bot = get_bot()
        bot.permission_manager.remove_group_blacklist(req.group_id)
        await broadcast_to_ws({"type": "blacklist_update"})
        return {"success": True, "message": f"已移除黑名单群: {req.group_id}"}
    
    @app.get("/api/logs")
    async def get_logs(lines: int = Query(default=100, le=500), auth: bool = Depends(verify_auth)):
        global log_buffer
        if not log_buffer:
            log_file = project_root / "logs" / "bot.log"
            if log_file.exists():
                try:
                    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                        all_lines = f.readlines()
                        log_buffer = [sanitize_log_message(line.strip()) for line in all_lines[-log_buffer_max:]]
                except Exception:
                    return {"logs": [], "error": "无法读取日志"}
        
        return {"logs": log_buffer[-lines:] if len(log_buffer) > lines else log_buffer}
    
    @app.post("/api/message/send")
    async def send_message(req: SendMessageRequest, auth: bool = Depends(verify_csrf)):
        bot = get_bot()
        
        if req.message_type == "group" and not req.group_id:
            raise HTTPException(status_code=400, detail="群消息需要group_id")
        if req.message_type == "private" and not req.user_id:
            raise HTTPException(status_code=400, detail="私聊消息需要user_id")
        
        adapter = None
        for a in bot.adapters:
            if getattr(a, "connected", False):
                adapter = a
                break
        
        if not adapter:
            raise HTTPException(status_code=503, detail="没有可用的连接")
        
        try:
            result = await adapter.send_message(
                message_type=req.message_type,
                user_id=req.user_id or 0,
                group_id=req.group_id,
                message=req.message
            )
            if result:
                await broadcast_to_ws({
                    "type": "message_sent",
                    "message_type": req.message_type,
                    "target": req.group_id or req.user_id
                })
                return {"success": True, "message": "消息发送成功"}
            raise HTTPException(status_code=500, detail="消息发送失败")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=500, detail="发送消息异常")
    
    @app.get("/api/friends")
    async def get_friends(auth: bool = Depends(verify_auth)):
        bot = get_bot()
        adapter = None
        for a in bot.adapters:
            if getattr(a, "connected", False):
                adapter = a
                break
        
        if not adapter:
            return {"friends": [], "error": "没有可用的连接"}
        
        try:
            result = await adapter.call_api("get_friend_list", {})
            if result and result.get("status") == "ok":
                return {"friends": result.get("data", [])}
            return {"friends": [], "error": "获取好友列表失败"}
        except Exception:
            return {"friends": [], "error": "获取好友列表失败"}
    
    @app.get("/api/groups")
    async def get_groups(auth: bool = Depends(verify_auth)):
        bot = get_bot()
        adapter = None
        for a in bot.adapters:
            if getattr(a, "connected", False):
                adapter = a
                break
        
        if not adapter:
            return {"groups": [], "error": "没有可用的连接"}
        
        try:
            result = await adapter.call_api("get_group_list", {})
            if result and result.get("status") == "ok":
                return {"groups": result.get("data", [])}
            return {"groups": [], "error": "获取群列表失败"}
        except Exception:
            return {"groups": [], "error": "获取群列表失败"}
    
    @app.post("/api/system/restart")
    async def restart_bot(req: RestartRequest, auth: bool = Depends(verify_csrf)):
        if not req.confirm:
            raise HTTPException(status_code=400, detail="需要确认重启")
        bot = get_bot()
        bot._restart_requested = True
        await broadcast_to_ws({"type": "system", "action": "restart"})
        asyncio.create_task(delayed_restart())
        return {"success": True, "message": "机器人将在1秒后重启"}
    
    @app.post("/api/system/shutdown")
    async def shutdown_bot(req: RestartRequest, auth: bool = Depends(verify_csrf)):
        if not req.confirm:
            raise HTTPException(status_code=400, detail="需要确认关闭")
        bot = get_bot()
        bot._shutdown_requested = True
        await broadcast_to_ws({"type": "system", "action": "shutdown"})
        asyncio.create_task(delayed_shutdown())
        return {"success": True, "message": "机器人将在1秒后关闭"}
    
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        client_ip = websocket.client.host if websocket.client else "unknown"
        connection_time = datetime.now()
        
        # 在accept之前进行初步限制检查
        if not check_ws_connection_rate(client_ip):
            _logger.warning(f"WebSocket连接频率限制触发: IP={client_ip}")
            await websocket.close(code=4008, reason="Connection rate limit exceeded")
            return
        
        # 定期清理过期的连接
        cleanup_stale_websocket_connections()
        
        # 先检查连接限制，再accept连接
        if not check_ws_connection_limits(client_ip):
            _logger.warning(f"WebSocket连接数限制触发: IP={client_ip}, 当前连接数={len(ws_connection_info)}")
            await websocket.close(code=4003, reason="Connection limit exceeded")
            return
        
        await websocket.accept()
        
        try:
            auth_msg = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
            auth_data = json.loads(auth_msg)
            nonce = auth_data.get("nonce")
            signature = auth_data.get("signature")
        except (asyncio.TimeoutError, json.JSONDecodeError, Exception):
            _logger.warning(f"WebSocket认证失败: IP={client_ip}, 原因=认证超时或无效")
            await websocket.close(code=4001, reason="Auth timeout or invalid")
            return
        
        if not nonce or not signature:
            _logger.warning(f"WebSocket认证失败: IP={client_ip}, 原因=缺少nonce或signature")
            await websocket.close(code=4001, reason="Missing nonce or signature")
            return
        
        token = verify_ws_signature(nonce, signature)
        if not token:
            _logger.warning(f"WebSocket认证失败: IP={client_ip}, 原因=无效signature")
            await websocket.close(code=4001, reason="Invalid signature")
            return
        
        token_info = active_tokens.get(token)
        if not token_info or datetime.now() > token_info["expires"]:
            _logger.warning(f"WebSocket认证失败: IP={client_ip}, 原因=Token过期")
            await websocket.close(code=4001, reason="Token expired")
            return
        
        if token_info.get("ip") and token_info["ip"] != client_ip:
            _logger.warning(f"WebSocket认证失败: IP={client_ip}, 原因=IP不匹配")
            await websocket.close(code=4001, reason="IP mismatch")
            return
        
        # 双重检查连接限制
        if not check_ws_connection_limits(client_ip):
            _logger.warning(f"WebSocket连接数限制触发(二次检查): IP={client_ip}")
            await websocket.close(code=4003, reason="Connection limit exceeded")
            return
        
        # 记录连接信息
        ws_connection_info[token] = {
            "client_ip": client_ip,
            "connected_at": connection_time,
            "last_activity": connection_time,
            "message_count": 0,
            "expires": datetime.now() + timedelta(hours=TOKEN_EXPIRE_HOURS)
        }
        
        ws_clients[token] = websocket
        _logger.info(f"WebSocket连接建立: IP={client_ip}, Token={token[:10]}..., 总连接数={len(ws_clients)}")
        
        await websocket.send_text(json.dumps({"type": "auth", "status": "ok"}))
        
        try:
            while True:
                data = await websocket.receive_text()
                # 更新活动时间
                if token in ws_connection_info:
                    ws_connection_info[token]["last_activity"] = datetime.now()
                    ws_connection_info[token]["message_count"] = ws_connection_info[token]["message_count"] + 1
                
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await websocket.send_text(json.dumps({"type": "pong"}))
                except json.JSONDecodeError:
                    pass
        except WebSocketDisconnect:
            _logger.info(f"WebSocket连接断开: IP={client_ip}, Token={token[:10] if len(token) > 10 else token}")
        except Exception as e:
            _logger.error(f"WebSocket连接异常: IP={client_ip}, 错误={str(e)}")
        finally:
            if token in ws_clients:
                del ws_clients[token]
            if token in ws_connection_info:
                connection_info = ws_connection_info.pop(token)
                _logger.info(f"WebSocket连接清理: IP={client_ip}, 消息数={connection_info.get('message_count', 0)}, 连接时长={(datetime.now() - connection_info['connected_at']).seconds}秒")
    
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=exc.status_code,
            content={"success": False, "error": exc.detail, "code": exc.status_code}
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": "服务器内部错误", "code": 500}
        )
    
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    
    return app


def format_uptime(seconds: float) -> str:
    if seconds <= 0:
        return "未启动"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    if d > 0:
        return f"{d}天{h}时{m}分"
    if h > 0:
        return f"{h}时{m}分{s}秒"
    if m > 0:
        return f"{m}分{s}秒"
    return f"{s}秒"


async def delayed_restart():
    global web_server
    await asyncio.sleep(1)
    if web_server:
        web_server.should_exit = True
        await asyncio.sleep(0.5)
    if bot_instance:
        await bot_instance.stop()
    os.execv(sys.executable, [sys.executable] + sys.argv)


async def delayed_shutdown():
    await asyncio.sleep(1)
    if bot_instance:
        await bot_instance.stop()
    sys.exit(0)


def get_fallback_html() -> str:
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Starrain-BOT</title></head>
<body style="background:#0f172a;color:#fff;font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0">
<div style="text-align:center">
<h1>Starrain-BOT</h1><p>Web管理界面加载中...</p>
</div></body></html>"""


async def run_web_server():
    global web_server
    import uvicorn
    logger = get_logger()
    if not web_config.enabled:
        logger.info("Web管理后台已禁用")
        return
    if web_app is None:
        logger.error("Web应用未初始化")
        return
    app = web_app  # type: ignore
    logger.info(f"启动Web管理后台: http://{web_config.host}:{web_config.port}")
    
    # 启动WebSocket连接清理任务
    async def cleanup_task():
        while True:
            try:
                cleanup_stale_websocket_connections()
                await asyncio.sleep(60)  # 每分钟清理一次
            except Exception as e:
                logger.error(f"WebSocket连接清理任务出错: {e}")
                await asyncio.sleep(60)
    
    # 创建清理任务但不await，让它作为后台任务运行
    asyncio.create_task(cleanup_task())
    logger.info("WebSocket连接清理任务已启动")
    
    config = uvicorn.Config(
        app,
        host=web_config.host,
        port=web_config.port,
        log_level="warning"
    )
    web_server = uvicorn.Server(config)
    await web_server.serve()
