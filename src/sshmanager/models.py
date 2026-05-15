from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class AuthType(str, Enum):
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"


class ForwardType(str, Enum):
    LOCAL = "local"
    REMOTE = "remote"
    DYNAMIC = "dynamic"


class TerminalMode(str, Enum):
    EMBEDDED = "embedded"
    SYSTEM = "system"


class ServerProfile(BaseModel):
    id: int | None = None
    name: str
    host: str
    port: int = 22
    username: str
    auth_type: AuthType = AuthType.PASSWORD
    password_enc: str | None = None
    private_key_path: str | None = None
    private_key_passphrase_enc: str | None = None
    jump_host_id: int | None = None
    remark: str = ""
    remember_password: bool = True
    last_used_at: datetime | None = None


class ForwardRule(BaseModel):
    id: int | None = None
    server_id: int
    type: ForwardType
    bind_host: str = "127.0.0.1"
    bind_port: int = 0
    target_host: str | None = None
    target_port: int | None = None
    enabled: bool = True
    last_used: bool = True


class ConnectionOptions(BaseModel):
    terminal_mode: TerminalMode = TerminalMode.EMBEDDED
    remember_password: bool = True
    use_saved_forwards: bool = True
    timeout: int = 10
    keepalive_interval: int = 30


class ConnectionResult(BaseModel):
    success: bool
    message: str
    connected_at: datetime = Field(default_factory=datetime.utcnow)


class CommandResult(BaseModel):
    success: bool
    outputs: list[str] = Field(default_factory=list)
    error: str | None = None


class RuleCheckResult(BaseModel):
    rule_id: int | None = None
    type: ForwardType
    ok: bool
    detail: str


class CheckItemResult(BaseModel):
    name: str
    ok: bool
    detail: str


class DiagnosticReport(BaseModel):
    ok: bool
    can_auto_fix: bool
    items: list[CheckItemResult] = Field(default_factory=list)
    sshd_effective: dict[str, str] = Field(default_factory=dict)
    raw_sshd_config_hints: list[str] = Field(default_factory=list)


class FixReport(BaseModel):
    ok: bool
    user_fix_ok: bool = False
    system_fix_ok: bool = False
    system_fix_skipped: bool = False
    items: list[CheckItemResult] = Field(default_factory=list)
    manual_commands: list[str] = Field(default_factory=list)
    backup_path: str | None = None
    detail: str = ""


class ExportedServer(BaseModel):
    name: str
    host: str
    port: int
    username: str
    auth_type: AuthType
    password_export_enc: str | None = None
    private_key_path: str | None = None
    private_key_passphrase_export_enc: str | None = None
    jump_host_name: str | None = None
    remark: str = ""
    remember_password: bool = True


class ExportBundleV1(BaseModel):
    schema_version: int = 1
    created_at: datetime = Field(default_factory=datetime.utcnow)
    kdf: str = "PBKDF2-HMAC-SHA256"
    salt: str
    servers: list[ExportedServer]
    forward_rules: dict[str, list[ForwardRule]]
    connection_options: dict[str, ConnectionOptions]
