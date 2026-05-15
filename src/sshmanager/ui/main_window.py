from __future__ import annotations

import asyncio
import json
import os
import platform
import re
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from sshmanager.core.ssh_service import SSHService
from sshmanager.core.terminal import launch_system_terminal
from sshmanager.models import (
    AuthType,
    ConnectionOptions,
    ExportBundleV1,
    ExportedServer,
    ForwardRule,
    ForwardType,
    ServerProfile,
    TerminalMode,
)
from sshmanager.security.export_crypto import decrypt_from_export, encrypt_for_export, generate_export_salt
from sshmanager.ui.terminal_window import TerminalWindow


I18N = {
    "zh_CN": {
        "window_title": "SSH 管理器",
        "toolbar_language": "语言",
        "lang_zh": "中文",
        "lang_en": "English",
        "tool_export": "导出 JSON",
        "tool_import": "导入 JSON",
        "tool_delete": "删除配置",
        "group_profile": "服务器配置",
        "group_connection": "连接",
        "group_forward": "端口转发规则",
        "group_terminal": "内置交互终端",
        "label_name": "名称",
        "label_host": "主机地址",
        "label_port": "端口",
        "label_username": "用户名",
        "label_auth_type": "认证方式",
        "label_password": "密码",
        "label_private_key": "私钥路径",
        "label_jump_host": "跳板机 ID",
        "label_remark": "备注",
        "check_remember_password": "记住密码",
        "label_terminal_mode": "终端模式",
        "button_save": "保存",
        "button_connect": "连接",
        "button_disconnect": "断开",
        "button_check_forward": "检测转发",
        "button_enable_key": "启用密钥登录",
        "button_diag_enable_key": "检测并开启密钥认证",
        "button_send": "发送",
        "button_refresh": "刷新输出",
        "note_terminal": "系统终端在密码认证下会自动切换到内置终端，以避免不安全注入。",
        "auth_password": "密码",
        "auth_private_key": "私钥",
        "terminal_embedded": "内置终端",
        "terminal_system": "系统终端",
        "forward_local": "本地转发",
        "forward_remote": "远程转发",
        "forward_dynamic": "动态代理",
        "forward_add": "+ 新增规则",
        "forward_remove": "- 删除规则",
        "forward_enabled": "启用",
        "forward_type": "类型",
        "forward_bind_host": "监听地址",
        "forward_bind_port": "本地端口",
        "forward_target_host": "目标地址",
        "forward_target_port": "目标端口",
        "msg_master_title": "主密码",
        "msg_master_init": "请设置主密码",
        "msg_master_confirm": "请再次输入主密码",
        "msg_master_invalid": "主密码不正确。",
        "msg_master_required": "需要先验证主密码。",
        "msg_error_title": "错误",
        "msg_saved": "已保存服务器 #{server_id}",
        "msg_select_server": "请先选择服务器。",
        "msg_terminal_title": "终端",
        "msg_terminal_fallback": "系统终端密码认证不安全，已自动切换内置终端。",
        "msg_disconnected": "已断开服务器 #{server_id}",
        "msg_export_success": "导出成功：{path}",
        "msg_import_success": "导入完成：新增 {count} 个服务器。",
        "msg_export_failed": "导出失败：{err}",
        "msg_import_failed": "导入失败：{err}",
        "msg_export_passphrase": "请输入导出口令（用于跨机器解密）",
        "msg_import_passphrase": "请输入导入口令",
        "msg_delete_confirm": "确认删除当前服务器配置吗？",
        "msg_deleted": "已删除服务器 #{server_id}",
        "msg_shell_opened": "内置终端会话已打开。",
        "msg_forward_check_summary": "转发检测：成功 {ok} 条，失败 {fail} 条。",
        "msg_key_requires_password": "当前服务器需要可用凭据（已保存密码或可用私钥）。",
        "msg_key_success": "密钥登录已启用并验证成功。",
        "msg_key_failed": "启用密钥登录失败：{err}",
        "msg_key_step_start": "[密钥登录] 开始：{name} ({user}@{host}:{port})，当前认证={auth}",
        "msg_key_step_precheck_ok": "[密钥登录] 前置检查通过：已保存可解密密码。",
        "msg_key_step_gen_start": "[密钥登录] 正在本地生成 ED25519 密钥...",
        "msg_key_step_gen_done": "[密钥登录] 本地密钥已生成：private={private_path} public={public_path}",
        "msg_key_step_remote_start": "[密钥登录] 正在写入远端 authorized_keys 与权限...",
        "msg_key_step_remote_done": "[密钥登录] 远端公钥写入完成。",
        "msg_key_step_switch_local": "[密钥登录] 本地配置已切换为私钥认证：{private_path}",
        "msg_key_step_test_start": "[密钥登录] 正在测试私钥登录...",
        "msg_key_step_test_done": "[密钥登录] 私钥登录测试通过：{detail}",
        "msg_key_step_rollback": "[密钥登录] 已回滚本地认证配置到原状态。",
        "msg_key_step_remote_fail": "[密钥登录] 远端写入失败：{err}",
        "msg_diag_start": "[公钥认证] 开始检测与自动修复：{name} ({user}@{host}:{port})",
        "msg_diag_item": "[公钥认证][检测] {name}: {status} - {detail}",
        "msg_diag_no_sudo": "[公钥认证] sudo 不可用：可检测但无法自动修复系统配置。",
        "msg_diag_continue_no_sudo": "[公钥认证] sudo 不可用，继续执行用户层修复与私钥验证。",
        "msg_fix_start": "[公钥认证] 开始执行自动修复...",
        "msg_fix_item": "[公钥认证][修复] {name}: {status} - {detail}",
        "msg_fix_failed": "[公钥认证] 自动修复失败：{detail}",
        "msg_fix_manual_header": "[公钥认证][手动操作建议] 自动系统修复不可用，请在远端手工执行：",
        "msg_fix_manual_cmd": "[公钥认证][手动操作建议] {cmd}",
        "msg_fix_manual_edit_hint": "[公钥认证][手动操作建议] 执行 sudoedit 后通常到文件末尾，将相关项从 no 改成 yes（如 PubkeyAuthentication）。",
        "msg_apply_start": "[公钥认证] 正在校验并重载 sshd...",
        "msg_apply_done": "[公钥认证] sshd 校验/重载成功：{detail}",
        "msg_apply_failed": "[公钥认证] sshd 校验/重载失败：{detail}",
        "msg_diag_test_start": "[公钥认证] 正在测试私钥登录...",
        "msg_diag_success": "公钥认证检测与开启完成，私钥登录可用。",
        "msg_diag_failed": "公钥认证检测或修复失败：{err}",
        "msg_pwd_copied": "已复制密码到剪贴板，进入系统终端后用 Ctrl+Shift+V 粘贴。",
        "msg_pwd_cleared": "出于安全考虑，剪贴板中的连接密码已自动清空。",
    },
    "en_US": {
        "window_title": "SSH Manager",
        "toolbar_language": "Language",
        "lang_zh": "中文",
        "lang_en": "English",
        "tool_export": "Export JSON",
        "tool_import": "Import JSON",
        "tool_delete": "Delete Profile",
        "group_profile": "Server Profile",
        "group_connection": "Connection",
        "group_forward": "Forward Rules",
        "group_terminal": "Embedded Terminal",
        "label_name": "Name",
        "label_host": "Host",
        "label_port": "Port",
        "label_username": "Username",
        "label_auth_type": "Auth Type",
        "label_password": "Password",
        "label_private_key": "Private Key Path",
        "label_jump_host": "Jump Host ID",
        "label_remark": "Remark",
        "check_remember_password": "Remember password",
        "label_terminal_mode": "Terminal Mode",
        "button_save": "Save",
        "button_connect": "Connect",
        "button_disconnect": "Disconnect",
        "button_check_forward": "Check Forward",
        "button_enable_key": "Enable Key Login",
        "button_diag_enable_key": "Diagnose+Enable Pubkey",
        "button_send": "Send",
        "button_refresh": "Refresh Output",
        "note_terminal": "Password auth in system terminal auto-falls back to embedded terminal.",
        "auth_password": "Password",
        "auth_private_key": "Private Key",
        "terminal_embedded": "Embedded",
        "terminal_system": "System",
        "forward_local": "Local",
        "forward_remote": "Remote",
        "forward_dynamic": "Dynamic",
        "forward_add": "+ Add Rule",
        "forward_remove": "- Remove Rule",
        "forward_enabled": "Enabled",
        "forward_type": "Type",
        "forward_bind_host": "Bind Host",
        "forward_bind_port": "Local Port",
        "forward_target_host": "Target Host",
        "forward_target_port": "Target Port",
        "msg_master_title": "Master Password",
        "msg_master_init": "Set master password",
        "msg_master_confirm": "Confirm master password",
        "msg_master_invalid": "Invalid master password.",
        "msg_master_required": "Master password required.",
        "msg_error_title": "Error",
        "msg_saved": "Saved server #{server_id}",
        "msg_select_server": "Select a server first.",
        "msg_terminal_title": "Terminal",
        "msg_terminal_fallback": "Password auth in system terminal is unsafe, switched to embedded mode.",
        "msg_disconnected": "Disconnected server #{server_id}",
        "msg_export_success": "Exported: {path}",
        "msg_import_success": "Imported {count} servers.",
        "msg_export_failed": "Export failed: {err}",
        "msg_import_failed": "Import failed: {err}",
        "msg_export_passphrase": "Input export passphrase",
        "msg_import_passphrase": "Input import passphrase",
        "msg_delete_confirm": "Delete selected server profile?",
        "msg_deleted": "Deleted server #{server_id}",
        "msg_shell_opened": "Embedded terminal opened.",
        "msg_forward_check_summary": "Forward checks: {ok} passed, {fail} failed.",
        "msg_key_requires_password": "Server needs usable credentials (saved password or valid private key).",
        "msg_key_success": "Key login enabled and verified.",
        "msg_key_failed": "Enable key login failed: {err}",
        "msg_key_step_start": "[Key Login] Start: {name} ({user}@{host}:{port}), auth={auth}",
        "msg_key_step_precheck_ok": "[Key Login] Precheck passed: decryptable password found.",
        "msg_key_step_gen_start": "[Key Login] Generating local ED25519 key...",
        "msg_key_step_gen_done": "[Key Login] Local key generated: private={private_path} public={public_path}",
        "msg_key_step_remote_start": "[Key Login] Installing key to remote authorized_keys...",
        "msg_key_step_remote_done": "[Key Login] Remote key install complete.",
        "msg_key_step_switch_local": "[Key Login] Local auth switched to private key: {private_path}",
        "msg_key_step_test_start": "[Key Login] Testing private key login...",
        "msg_key_step_test_done": "[Key Login] Private key test passed: {detail}",
        "msg_key_step_rollback": "[Key Login] Local auth rolled back to previous state.",
        "msg_key_step_remote_fail": "[Key Login] Remote install failed: {err}",
        "msg_diag_start": "[Pubkey] Diagnose+fix start: {name} ({user}@{host}:{port})",
        "msg_diag_item": "[Pubkey][Diagnose] {name}: {status} - {detail}",
        "msg_diag_no_sudo": "[Pubkey] sudo unavailable: can diagnose but cannot auto-fix system config.",
        "msg_diag_continue_no_sudo": "[Pubkey] sudo unavailable; continue with user-level fix and key validation.",
        "msg_fix_start": "[Pubkey] Running auto-fix...",
        "msg_fix_item": "[Pubkey][Fix] {name}: {status} - {detail}",
        "msg_fix_failed": "[Pubkey] Auto-fix failed: {detail}",
        "msg_fix_manual_header": "[Pubkey][Manual] System-level auto-fix unavailable. Run these on remote host:",
        "msg_fix_manual_cmd": "[Pubkey][Manual] {cmd}",
        "msg_fix_manual_edit_hint": "[Pubkey][Manual] After sudoedit, typically go to file end and change related no to yes (e.g. PubkeyAuthentication).",
        "msg_apply_start": "[Pubkey] Validating and reloading sshd...",
        "msg_apply_done": "[Pubkey] sshd validate/reload OK: {detail}",
        "msg_apply_failed": "[Pubkey] sshd validate/reload failed: {detail}",
        "msg_diag_test_start": "[Pubkey] Testing private key login...",
        "msg_diag_success": "Pubkey auth diagnose+enable completed.",
        "msg_diag_failed": "Pubkey auth diagnose/fix failed: {err}",
        "msg_pwd_copied": "Password copied to clipboard. Use Ctrl+Shift+V in system terminal.",
        "msg_pwd_cleared": "Clipboard password has been auto-cleared for safety.",
    },
}


class MainWindow(QMainWindow):
    def __init__(self, repository, crypto) -> None:
        super().__init__()
        self.repo = repository
        self.crypto = crypto
        self.ssh = SSHService()
        self.master_password: str | None = None
        self.current_server_id: int | None = None
        self.current_locale: str = "zh_CN"
        self.terminal_windows: dict[int, TerminalWindow] = {}
        self.main_splitter: QSplitter | None = None
        self._splitter_save_timer = QTimer(self)
        self._splitter_save_timer.setSingleShot(True)
        self._splitter_save_timer.timeout.connect(self._save_splitter_sizes)

        self.resize(1320, 820)
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        self._load_locale()
        self._build_ui()
        self.apply_theme()
        self.apply_translations()
        self._load_data()
        self._ensure_master_gui()

    def tr(self, key: str, **kwargs) -> str:
        text = I18N.get(self.current_locale, I18N["zh_CN"]).get(key, key)
        return text.format(**kwargs) if kwargs else text

    def _build_toolbar(self) -> None:
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, toolbar)
        self.language_label = QLabel()
        toolbar.addWidget(self.language_label)

        self.language_combo = QComboBox()
        self.language_combo.addItem("", "zh_CN")
        self.language_combo.addItem("", "en_US")
        idx = self.language_combo.findData(self.current_locale)
        self.language_combo.setCurrentIndex(max(idx, 0))
        self.language_combo.currentIndexChanged.connect(self.on_language_changed)
        toolbar.addWidget(self.language_combo)

        spacer = QWidget()
        spacer.setSizePolicy(spacer.sizePolicy().Policy.Expanding, spacer.sizePolicy().Policy.Preferred)
        toolbar.addWidget(spacer)

        self.export_action = QAction("", self)
        self.export_action.triggered.connect(self.export_json)
        toolbar.addAction(self.export_action)

        self.import_action = QAction("", self)
        self.import_action.triggered.connect(self.import_json)
        toolbar.addAction(self.import_action)

    def _build_ui(self) -> None:
        self._build_toolbar()
        root = QWidget()
        self.setCentralWidget(root)
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(14, 14, 14, 14)

        self.server_list = QListWidget()
        self.server_list.itemClicked.connect(self.on_server_single_click)
        self.server_list.itemDoubleClicked.connect(self.on_server_double_click)
        self.server_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.server_list.customContextMenuRequested.connect(self.on_server_context_menu)
        self.server_list.setMinimumWidth(220)

        self.form_box = QGroupBox()
        form = QFormLayout(self.form_box)
        self.name_edit = QLineEdit(); self.host_edit = QLineEdit(); self.port_spin = QSpinBox(); self.port_spin.setRange(1, 65535); self.port_spin.setValue(22)
        self.user_edit = QLineEdit(); self.password_edit = QLineEdit(); self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.remember_check = QCheckBox(); self.remember_check.setChecked(True)
        self.auth_combo = QComboBox(); self.auth_combo.addItem("", AuthType.PASSWORD.value); self.auth_combo.addItem("", AuthType.PRIVATE_KEY.value)
        self.key_edit = QLineEdit(); self.jump_spin = QSpinBox(); self.jump_spin.setRange(0, 999999); self.remark_edit = QLineEdit()
        self.name_label = QLabel(); self.host_label = QLabel(); self.port_label = QLabel(); self.user_label = QLabel(); self.auth_label = QLabel(); self.password_label = QLabel(); self.key_label = QLabel(); self.jump_label = QLabel(); self.remark_label = QLabel()
        form.addRow(self.name_label, self.name_edit); form.addRow(self.host_label, self.host_edit); form.addRow(self.port_label, self.port_spin); form.addRow(self.user_label, self.user_edit)
        form.addRow(self.auth_label, self.auth_combo); form.addRow(self.password_label, self.password_edit); form.addRow(QLabel(""), self.remember_check)
        form.addRow(self.key_label, self.key_edit); form.addRow(self.jump_label, self.jump_spin); form.addRow(self.remark_label, self.remark_edit)
        self.action_box = QGroupBox()
        action = QVBoxLayout(self.action_box)
        mode_line = QHBoxLayout()
        self.terminal_mode_label = QLabel()
        self.terminal_mode = QComboBox(); self.terminal_mode.addItem("", TerminalMode.EMBEDDED.value); self.terminal_mode.addItem("", TerminalMode.SYSTEM.value)
        mode_line.addWidget(self.terminal_mode_label); mode_line.addWidget(self.terminal_mode)
        action.addLayout(mode_line)
        btns = QHBoxLayout()
        self.save_btn = QPushButton(); self.connect_btn = QPushButton(); self.disconnect_btn = QPushButton(); self.check_forward_btn = QPushButton(); self.enable_key_btn = QPushButton(); self.diag_enable_key_btn = QPushButton()
        self.save_btn.clicked.connect(self.save_server); self.connect_btn.clicked.connect(self.connect_current); self.disconnect_btn.clicked.connect(self.disconnect_current); self.check_forward_btn.clicked.connect(self.check_forward_rules); self.enable_key_btn.clicked.connect(self.enable_key_login_for_current_server); self.diag_enable_key_btn.clicked.connect(self.diagnose_and_enable_pubkey_for_current_server)
        btns.addWidget(self.save_btn); btns.addWidget(self.connect_btn); btns.addWidget(self.disconnect_btn); btns.addWidget(self.check_forward_btn); btns.addWidget(self.enable_key_btn); btns.addWidget(self.diag_enable_key_btn)
        action.addLayout(btns)
        self.note = QLabel(); self.note.setWordWrap(True); action.addWidget(self.note)
        self.forward_box = QGroupBox()
        fwd = QVBoxLayout(self.forward_box)
        self.forward_table = QTableWidget(0, 6)
        self.forward_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.forward_table.verticalHeader().setVisible(False)
        fwd.addWidget(self.forward_table)
        fwd_btn = QHBoxLayout()
        self.add_rule_btn = QPushButton(); self.del_rule_btn = QPushButton()
        self.add_rule_btn.clicked.connect(self.add_forward_rule); self.del_rule_btn.clicked.connect(self.remove_selected_forward_rule)
        fwd_btn.addWidget(self.add_rule_btn); fwd_btn.addWidget(self.del_rule_btn); fwd_btn.addStretch(1)
        fwd.addLayout(fwd_btn)
        self.forward_box.setMinimumWidth(360)

        self.terminal_box = QGroupBox()
        terminal_layout = QVBoxLayout(self.terminal_box)
        self.terminal_output = QTextEdit(); self.terminal_output.setReadOnly(True)
        terminal_layout.addWidget(self.terminal_output)
        terminal_line = QHBoxLayout()
        self.terminal_input = QLineEdit(); self.terminal_send_btn = QPushButton(); self.terminal_refresh_btn = QPushButton()
        self.terminal_send_btn.clicked.connect(self.send_terminal_input); self.terminal_refresh_btn.clicked.connect(self.refresh_terminal_output)
        terminal_line.addWidget(self.terminal_input); terminal_line.addWidget(self.terminal_send_btn); terminal_line.addWidget(self.terminal_refresh_btn)
        terminal_layout.addLayout(terminal_line)
        self.log = QTextEdit(); self.log.setReadOnly(True)
        self.log.setMinimumHeight(180)
        self.terminal_box.setVisible(False)

        center_widget = QWidget()
        center_widget.setMinimumWidth(520)
        center_layout = QVBoxLayout(center_widget)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(10)
        center_layout.addWidget(self.form_box)
        center_layout.addWidget(self.action_box)
        center_layout.addWidget(self.terminal_box)
        center_layout.addWidget(self.log, 1)

        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_splitter.setChildrenCollapsible(False)
        self.main_splitter.addWidget(self.server_list)
        self.main_splitter.addWidget(center_widget)
        self.main_splitter.addWidget(self.forward_box)
        self.main_splitter.splitterMoved.connect(self._on_splitter_moved)
        root_layout.addWidget(self.main_splitter)
        self._restore_splitter_sizes()

    def _default_splitter_sizes(self) -> list[int]:
        total = max(self.width() - 28, 1200)
        left = max(220, int(total * 0.2))
        center = max(520, int(total * 0.4))
        right = max(360, total - left - center)
        return [left, center, right]

    def _restore_splitter_sizes(self) -> None:
        if not self.main_splitter:
            return
        raw = self.loop.run_until_complete(self.repo.get_setting("ui.main_splitter_sizes", ""))
        if raw:
            try:
                sizes = json.loads(raw)
                if (
                    isinstance(sizes, list)
                    and len(sizes) == 3
                    and all(isinstance(v, int) and v > 0 for v in sizes)
                ):
                    self.main_splitter.setSizes(sizes)
                    return
            except Exception:  # noqa: BLE001
                pass
        self.main_splitter.setSizes(self._default_splitter_sizes())

    def _on_splitter_moved(self, _pos: int, _index: int) -> None:
        self._splitter_save_timer.start(250)

    def _save_splitter_sizes(self) -> None:
        if not self.main_splitter:
            return
        sizes = self.main_splitter.sizes()
        self.loop.run_until_complete(self.repo.set_setting("ui.main_splitter_sizes", json.dumps(sizes)))

    def _load_locale(self) -> None:
        self.loop.run_until_complete(self.repo.init_db())
        locale = self.loop.run_until_complete(self.repo.get_setting("ui.language", "zh_CN"))
        self.current_locale = locale if locale in I18N else "zh_CN"

    def _ask_password_dialog(self, title: str, prompt: str) -> str | None:
        value, ok = QInputDialog.getText(self, title, prompt, QLineEdit.EchoMode.Password)
        if not ok or not value:
            return None
        return value

    def _ensure_master_gui(self) -> bool:
        if self.master_password:
            return True
        if not self.crypto.is_initialized():
            first = self._ask_password_dialog(self.tr("msg_master_title"), self.tr("msg_master_init"))
            if not first:
                QMessageBox.warning(self, self.tr("msg_error_title"), self.tr("msg_master_required"))
                return False
            second = self._ask_password_dialog(self.tr("msg_master_title"), self.tr("msg_master_confirm"))
            if first != second:
                QMessageBox.warning(self, self.tr("msg_error_title"), self.tr("msg_master_invalid"))
                return False
            self.crypto.initialize_master_password(first)
            self.master_password = first
            return True

        while True:
            pwd = self._ask_password_dialog(self.tr("msg_master_title"), self.tr("msg_master_title"))
            if not pwd:
                return False
            if self.crypto.verify_master_password(pwd):
                self.master_password = pwd
                return True
            retry = QMessageBox.question(self, self.tr("msg_error_title"), self.tr("msg_master_invalid"))
            if retry != QMessageBox.StandardButton.Yes:
                return False

    def on_language_changed(self) -> None:
        locale = self.language_combo.currentData()
        self.current_locale = locale if locale in I18N else "zh_CN"
        self.apply_translations()
        self.loop.run_until_complete(self.repo.set_setting("ui.language", self.current_locale))

    def apply_translations(self) -> None:
        self.setWindowTitle(self.tr("window_title"))
        self.language_label.setText(self.tr("toolbar_language") + ":")
        self.language_combo.setItemText(0, self.tr("lang_zh")); self.language_combo.setItemText(1, self.tr("lang_en"))
        self.export_action.setText(self.tr("tool_export")); self.import_action.setText(self.tr("tool_import"))
        self.form_box.setTitle(self.tr("group_profile")); self.action_box.setTitle(self.tr("group_connection")); self.forward_box.setTitle(self.tr("group_forward")); self.terminal_box.setTitle(self.tr("group_terminal"))
        self.name_label.setText(self.tr("label_name")); self.host_label.setText(self.tr("label_host")); self.port_label.setText(self.tr("label_port")); self.user_label.setText(self.tr("label_username"))
        self.auth_label.setText(self.tr("label_auth_type")); self.password_label.setText(self.tr("label_password")); self.key_label.setText(self.tr("label_private_key")); self.jump_label.setText(self.tr("label_jump_host")); self.remark_label.setText(self.tr("label_remark"))
        self.remember_check.setText(self.tr("check_remember_password"))
        self.auth_combo.setItemText(0, self.tr("auth_password")); self.auth_combo.setItemText(1, self.tr("auth_private_key"))
        self.terminal_mode_label.setText(self.tr("label_terminal_mode")); self.terminal_mode.setItemText(0, self.tr("terminal_embedded")); self.terminal_mode.setItemText(1, self.tr("terminal_system"))
        self.save_btn.setText(self.tr("button_save")); self.connect_btn.setText(self.tr("button_connect")); self.disconnect_btn.setText(self.tr("button_disconnect")); self.check_forward_btn.setText(self.tr("button_check_forward")); self.enable_key_btn.setText(self.tr("button_enable_key")); self.diag_enable_key_btn.setText(self.tr("button_diag_enable_key"))
        self.note.setText(self.tr("note_terminal"))
        self.add_rule_btn.setText(self.tr("forward_add")); self.del_rule_btn.setText(self.tr("forward_remove")); self.terminal_send_btn.setText(self.tr("button_send")); self.terminal_refresh_btn.setText(self.tr("button_refresh"))
        self.forward_table.setHorizontalHeaderLabels([self.tr("forward_enabled"), self.tr("forward_type"), self.tr("forward_bind_host"), self.tr("forward_bind_port"), self.tr("forward_target_host"), self.tr("forward_target_port")])

    def apply_theme(self) -> None:
        self.setStyleSheet(
            "QMainWindow{background:#f7f9fc;} QGroupBox{background:#fff;border:1px solid #d8e3f0;border-radius:10px;margin-top:10px;font-weight:600;}"
            "QGroupBox::title{subcontrol-origin:margin;left:10px;padding:0 6px;color:#2b3a55;}"
            "QLineEdit,QSpinBox,QComboBox,QListWidget,QTextEdit,QTableWidget{background:#fcfdff;border:1px solid #cfd9ea;border-radius:8px;padding:6px;}"
            "QComboBox{color:#1f2a3d;selection-background-color:#3a87d8;selection-color:#ffffff;}"
            "QComboBox QAbstractItemView{background:#ffffff;color:#1f2a3d;border:1px solid #cfd9ea;selection-background-color:#3a87d8;selection-color:#ffffff;outline:0;}"
            "QComboBox QAbstractItemView::item{min-height:24px;padding:4px 8px;}"
            "QComboBox QAbstractItemView::item:hover{background:#dcebff;color:#173055;}"
            "QComboBox QAbstractItemView::item:selected{background:#3a87d8;color:#ffffff;}"
            "QCheckBox{spacing:8px;color:#2b3a55;}"
            "QCheckBox::indicator{width:16px;height:16px;border:1px solid #7f94b3;border-radius:4px;background:#ffffff;}"
            "QCheckBox::indicator:hover{border:1px solid #3a87d8;}"
            "QCheckBox::indicator:checked{background:#3a87d8;border:1px solid #2f77c4;}"
            "QCheckBox::indicator:disabled{background:#eef3f9;border:1px solid #b7c6db;}"
            "QPushButton{background:#3a87d8;color:#fff;border:none;border-radius:8px;padding:7px 12px;font-weight:600;} QPushButton:hover{background:#2f77c4;}"
        )

    def _log(self, text: str) -> None:
        self.log.append(text)

    def _load_data(self) -> None:
        self.loop.run_until_complete(self.repo.init_db())
        self.reload_servers()

    def clear_current_form(self) -> None:
        self.current_server_id = None
        self.name_edit.clear(); self.host_edit.clear(); self.port_spin.setValue(22); self.user_edit.clear(); self.password_edit.clear(); self.key_edit.clear(); self.jump_spin.setValue(0); self.remark_edit.clear(); self.forward_table.setRowCount(0)

    def reload_servers(self) -> None:
        self.server_list.clear()
        servers = self.loop.run_until_complete(self.repo.list_servers())
        for server in servers:
            item = QListWidgetItem(f"[{server.id}] {server.name} ({server.username}@{server.host}:{server.port})")
            item.setData(256, server.id)
            self.server_list.addItem(item)

    def on_server_context_menu(self, pos) -> None:
        item = self.server_list.itemAt(pos)
        if not item:
            return
        menu = QMenu(self)
        act_delete = menu.addAction(self.tr("tool_delete"))
        action = menu.exec(self.server_list.mapToGlobal(pos))
        if action == act_delete:
            self.delete_server_item(item)

    def delete_server_item(self, item: QListWidgetItem) -> None:
        sid = item.data(256)
        if QMessageBox.question(self, self.tr("tool_delete"), self.tr("msg_delete_confirm")) != QMessageBox.StandardButton.Yes:
            return
        self.loop.run_until_complete(self.repo.delete_server(sid))
        self.reload_servers()
        if self.current_server_id == sid:
            self.clear_current_form()
        self._log(self.tr("msg_deleted", server_id=sid))

    def _create_forward_row(self, rule: ForwardRule | None = None) -> None:
        row = self.forward_table.rowCount()
        self.forward_table.insertRow(row)

        enabled = QCheckBox(); enabled.setChecked(True if rule is None else rule.enabled)
        self.forward_table.setCellWidget(row, 0, enabled)

        ftype = QComboBox(); ftype.addItem(self.tr("forward_local"), ForwardType.LOCAL.value); ftype.addItem(self.tr("forward_remote"), ForwardType.REMOTE.value); ftype.addItem(self.tr("forward_dynamic"), ForwardType.DYNAMIC.value)
        if rule: ftype.setCurrentIndex(ftype.findData(rule.type.value))
        self.forward_table.setCellWidget(row, 1, ftype)

        bind_host = QLineEdit(rule.bind_host if rule else "127.0.0.1"); self.forward_table.setCellWidget(row, 2, bind_host)
        bind_port = QSpinBox(); bind_port.setRange(1, 65535); bind_port.setValue(rule.bind_port if rule else 22); self.forward_table.setCellWidget(row, 3, bind_port)
        target_host = QLineEdit((rule.target_host or "127.0.0.1") if rule else "127.0.0.1"); self.forward_table.setCellWidget(row, 4, target_host)
        target_port = QSpinBox(); target_port.setRange(1, 65535); target_port.setValue((rule.target_port or 22) if rule else 22); self.forward_table.setCellWidget(row, 5, target_port)

        manual_override = {"flag": rule is not None and rule.bind_port != (rule.target_port or rule.bind_port)}

        def sync_ports(value: int) -> None:
            if not manual_override["flag"]:
                bind_port.blockSignals(True)
                bind_port.setValue(value)
                bind_port.blockSignals(False)

        def mark_manual(_: int) -> None:
            manual_override["flag"] = True

        def on_type_change() -> None:
            is_dynamic = ftype.currentData() == ForwardType.DYNAMIC.value
            target_host.setEnabled(not is_dynamic)
            target_port.setEnabled(not is_dynamic)

        target_port.valueChanged.connect(sync_ports)
        bind_port.valueChanged.connect(mark_manual)
        ftype.currentIndexChanged.connect(on_type_change)
        on_type_change()

    def add_forward_rule(self) -> None:
        self._create_forward_row(None)

    def remove_selected_forward_rule(self) -> None:
        row = self.forward_table.currentRow()
        if row >= 0:
            self.forward_table.removeRow(row)

    def _read_forward_rules(self, server_id: int) -> list[ForwardRule]:
        rules: list[ForwardRule] = []
        for row in range(self.forward_table.rowCount()):
            enabled = self.forward_table.cellWidget(row, 0).isChecked()
            ftype = ForwardType(self.forward_table.cellWidget(row, 1).currentData())
            bind_host = self.forward_table.cellWidget(row, 2).text().strip() or "127.0.0.1"
            bind_port = self.forward_table.cellWidget(row, 3).value()
            target_host = self.forward_table.cellWidget(row, 4).text().strip() or None
            target_port = self.forward_table.cellWidget(row, 5).value()
            if ftype == ForwardType.DYNAMIC:
                target_host = None
                target_port = None
            rules.append(ForwardRule(server_id=server_id, type=ftype, bind_host=bind_host, bind_port=bind_port, target_host=target_host, target_port=target_port, enabled=enabled, last_used=enabled))
        return rules

    def on_server_single_click(self, item: QListWidgetItem) -> None:
        server_id = item.data(256)
        self.current_server_id = server_id
        server = self.loop.run_until_complete(self.repo.get_server_by_id(server_id))
        if not server:
            return
        self.name_edit.setText(server.name); self.host_edit.setText(server.host); self.port_spin.setValue(server.port); self.user_edit.setText(server.username)
        self.auth_combo.setCurrentIndex(self.auth_combo.findData(server.auth_type.value)); self.key_edit.setText(server.private_key_path or ""); self.jump_spin.setValue(server.jump_host_id or 0); self.remark_edit.setText(server.remark)
        self.remember_check.setChecked(server.remember_password); self.password_edit.clear()
        opts = self.loop.run_until_complete(self.repo.get_connection_options(server_id))
        self.terminal_mode.setCurrentIndex(self.terminal_mode.findData(opts.terminal_mode.value))
        self.forward_table.setRowCount(0)
        for rule in self.loop.run_until_complete(self.repo.list_forward_rules(server_id)):
            self._create_forward_row(rule)

    def on_server_double_click(self, _: QListWidgetItem) -> None:
        self.connect_current()

    def _ensure_master(self) -> bool:
        return self._ensure_master_gui()

    def save_server(self) -> None:
        if not self._ensure_master():
            return
        password_enc = None
        if self.remember_check.isChecked() and self.password_edit.text().strip():
            password_enc = self.crypto.encrypt(self.password_edit.text().strip(), self.master_password or "")
        profile = ServerProfile(
            id=self.current_server_id,
            name=self.name_edit.text().strip(),
            host=self.host_edit.text().strip(),
            port=self.port_spin.value(),
            username=self.user_edit.text().strip(),
            auth_type=self.auth_combo.currentData(),
            password_enc=password_enc,
            private_key_path=self.key_edit.text().strip() or None,
            jump_host_id=self.jump_spin.value() or None,
            remark=self.remark_edit.text().strip(),
            remember_password=self.remember_check.isChecked(),
        )
        server_id = self.loop.run_until_complete(self.repo.upsert_server(profile))
        self.current_server_id = server_id
        self.loop.run_until_complete(self.repo.save_connection_options(server_id, ConnectionOptions(terminal_mode=self.terminal_mode.currentData())))
        self.loop.run_until_complete(self.repo.replace_forward_rules(server_id, self._read_forward_rules(server_id)))
        self.reload_servers()
        self._log(self.tr("msg_saved", server_id=server_id))

    def _get_server_password(self, server: ServerProfile) -> str | None:
        if not server.password_enc:
            return None
        return self.crypto.decrypt(server.password_enc, self.master_password or "")

    def _key_storage_dir(self) -> Path:
        configured = self.loop.run_until_complete(self.repo.get_setting("security.key_dir", ""))
        if configured:
            return Path(configured).expanduser()
        return Path.home() / ".sshmanager" / "keys"

    @staticmethod
    def _safe_key_name(text: str) -> str:
        return re.sub(r"[^a-zA-Z0-9._-]+", "_", text)

    def _generate_local_keypair(self, server: ServerProfile) -> tuple[str, str, str]:
        key_dir = self._key_storage_dir()
        key_dir.mkdir(parents=True, exist_ok=True)

        base = f"{self._safe_key_name(server.name)}_{self._safe_key_name(server.host)}"
        private_path = key_dir / f"{base}.key"
        public_path = key_dir / f"{base}.key.pub"

        private_key = ed25519.Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )

        private_path.write_bytes(private_bytes)
        os.chmod(private_path, 0o600)
        public_path.write_bytes(public_bytes + b"\n")
        os.chmod(public_path, 0o644)
        return str(private_path), str(public_path), public_bytes.decode("utf-8")

    def _install_public_key_remote(self, server: ServerProfile, password: str, public_key_text: str) -> tuple[bool, str]:
        quoted = public_key_text.replace("'", "'\"'\"'")
        commands = [
            "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys",
            "chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys",
            "chmod go-w ~ || true",
            f"grep -qxF '{quoted}' ~/.ssh/authorized_keys 2>/dev/null || echo '{quoted}' >> ~/.ssh/authorized_keys",
        ]
        result = self.loop.run_until_complete(self.ssh.exec_commands(server, password, commands))
        if not result.success:
            detail = result.error or "remote command failed"
            return False, detail
        return True, "ok"

    def enable_key_login_for_current_server(self) -> None:
        if not self.current_server_id:
            QMessageBox.information(self, self.tr("msg_error_title"), self.tr("msg_select_server"))
            return
        if not self._ensure_master():
            return

        server = self.loop.run_until_complete(self.repo.get_server_by_id(self.current_server_id))
        if not server:
            return
        self._log(
            self.tr(
                "msg_key_step_start",
                name=server.name,
                user=server.username,
                host=server.host,
                port=server.port,
                auth=server.auth_type.value,
            )
        )
        if server.auth_type != AuthType.PASSWORD or not server.password_enc:
            QMessageBox.warning(self, self.tr("msg_error_title"), self.tr("msg_key_requires_password"))
            return

        old_auth = server.auth_type
        old_key_path = server.private_key_path

        try:
            password = self._get_server_password(server)
            if not password:
                QMessageBox.warning(self, self.tr("msg_error_title"), self.tr("msg_key_requires_password"))
                return
            self._log(self.tr("msg_key_step_precheck_ok"))
            self._log(self.tr("msg_key_step_gen_start"))
            private_key_path, public_key_path, public_key_text = self._generate_local_keypair(server)
            self._log(
                self.tr(
                    "msg_key_step_gen_done",
                    private_path=private_key_path,
                    public_path=public_key_path,
                )
            )
            self._log(self.tr("msg_key_step_remote_start"))
            ok, msg = self._install_public_key_remote(server, password, public_key_text)
            if not ok:
                self._log(self.tr("msg_key_step_remote_fail", err=msg))
                raise RuntimeError(msg)
            self._log(self.tr("msg_key_step_remote_done"))

            server.auth_type = AuthType.PRIVATE_KEY
            server.private_key_path = private_key_path
            self.loop.run_until_complete(self.repo.upsert_server(server))
            self._log(self.tr("msg_key_step_switch_local", private_path=private_key_path))

            self._log(self.tr("msg_key_step_test_start"))
            passed, detail = self.loop.run_until_complete(self.ssh.test_private_key_login(server, private_key_path))
            if not passed:
                server.auth_type = old_auth
                server.private_key_path = old_key_path
                self.loop.run_until_complete(self.repo.upsert_server(server))
                self._log(self.tr("msg_key_step_rollback"))
                raise RuntimeError(detail)
            self._log(self.tr("msg_key_step_test_done", detail=detail))

            self.auth_combo.setCurrentIndex(self.auth_combo.findData(AuthType.PRIVATE_KEY.value))
            self.key_edit.setText(private_key_path)
            self._log(self.tr("msg_key_success"))
            QMessageBox.information(self, self.tr("button_enable_key"), self.tr("msg_key_success"))
        except Exception as exc:  # noqa: BLE001
            if server.auth_type != old_auth or server.private_key_path != old_key_path:
                server.auth_type = old_auth
                server.private_key_path = old_key_path
                self.loop.run_until_complete(self.repo.upsert_server(server))
                self._log(self.tr("msg_key_step_rollback"))
            self._log(self.tr("msg_key_failed", err=str(exc)))
            QMessageBox.warning(self, self.tr("msg_error_title"), self.tr("msg_key_failed", err=str(exc)))

    def diagnose_and_enable_pubkey_for_current_server(self) -> None:
        if not self.current_server_id:
            QMessageBox.information(self, self.tr("msg_error_title"), self.tr("msg_select_server"))
            return
        if not self._ensure_master():
            return
        server = self.loop.run_until_complete(self.repo.get_server_by_id(self.current_server_id))
        if not server:
            return
        try:
            password = self._get_server_password(server) if server.password_enc else None
            if not password and (not server.private_key_path or not Path(server.private_key_path).exists()):
                raise RuntimeError(self.tr("msg_key_requires_password"))
            self._log(self.tr("msg_diag_start", name=server.name, user=server.username, host=server.host, port=server.port))

            private_key_path = server.private_key_path
            public_key_text = None
            if private_key_path and Path(private_key_path).exists():
                pub_path = Path(f"{private_key_path}.pub")
                if pub_path.exists():
                    public_key_text = pub_path.read_text(encoding="utf-8").strip()
            if not public_key_text:
                self._log(self.tr("msg_key_step_gen_start"))
                private_key_path, _, public_key_text = self._generate_local_keypair(server)
                self._log(self.tr("msg_key_step_gen_done", private_path=private_key_path, public_path=f"{private_key_path}.pub"))

            report = self.loop.run_until_complete(self.ssh.diagnose_pubkey_auth(server, password, public_key_text))
            for item in report.items:
                self._log(self.tr("msg_diag_item", name=item.name, status=("OK" if item.ok else "FAIL"), detail=item.detail))
            if not report.can_auto_fix:
                self._log(self.tr("msg_diag_no_sudo"))
                self._log(self.tr("msg_diag_continue_no_sudo"))

            self._log(self.tr("msg_fix_start"))
            fix = self.loop.run_until_complete(self.ssh.fix_pubkey_auth(server, password, public_key_text))
            for item in fix.items:
                self._log(self.tr("msg_fix_item", name=item.name, status=("OK" if item.ok else "FAIL"), detail=item.detail))
            if not fix.user_fix_ok:
                self._log(self.tr("msg_fix_failed", detail=fix.detail))
                raise RuntimeError(fix.detail)
            if fix.system_fix_skipped or not fix.system_fix_ok:
                self._log(self.tr("msg_fix_manual_header"))
                for cmd in fix.manual_commands:
                    self._log(self.tr("msg_fix_manual_cmd", cmd=cmd))
                self._log(self.tr("msg_fix_manual_edit_hint"))

            if fix.system_fix_ok:
                self._log(self.tr("msg_apply_start"))
                ok, detail = self.loop.run_until_complete(self.ssh.validate_and_reload_sshd(server, password))
                if ok:
                    self._log(self.tr("msg_apply_done", detail=detail))
                else:
                    self._log(self.tr("msg_apply_failed", detail=detail))

            self._log(self.tr("msg_diag_test_start"))
            server.auth_type = AuthType.PRIVATE_KEY
            server.private_key_path = private_key_path
            self.loop.run_until_complete(self.repo.upsert_server(server))
            passed, test_detail = self.loop.run_until_complete(self.ssh.test_private_key_login(server, private_key_path))
            if not passed:
                raise RuntimeError(test_detail)

            self.auth_combo.setCurrentIndex(self.auth_combo.findData(AuthType.PRIVATE_KEY.value))
            self.key_edit.setText(private_key_path)
            self._log(self.tr("msg_diag_success"))
            QMessageBox.information(self, self.tr("button_diag_enable_key"), self.tr("msg_diag_success"))
        except Exception as exc:  # noqa: BLE001
            self._log(self.tr("msg_diag_failed", err=str(exc)))
            QMessageBox.warning(self, self.tr("msg_error_title"), self.tr("msg_diag_failed", err=str(exc)))

    def connect_current(self) -> None:
        if not self.current_server_id:
            QMessageBox.information(self, self.tr("msg_error_title"), self.tr("msg_select_server"))
            return
        if not self._ensure_master():
            return

        server = self.loop.run_until_complete(self.repo.get_server_by_id(self.current_server_id))
        if not server:
            return

        mode = TerminalMode(self.terminal_mode.currentData())
        if mode == TerminalMode.SYSTEM:
            if server.auth_type == AuthType.PASSWORD:
                try:
                    password = self.password_edit.text().strip() or self._get_server_password(server)
                    if password:
                        clipboard = QApplication.clipboard()
                        clipboard.setText(password)
                        self._log(self.tr("msg_pwd_copied"))

                        def _clear_password_clipboard() -> None:
                            if clipboard.text() == password:
                                clipboard.clear()
                                self._log(self.tr("msg_pwd_cleared"))

                        QTimer.singleShot(60000, _clear_password_clipboard)
                except Exception as exc:  # noqa: BLE001
                    self._log(f"Clipboard password copy failed: {exc}")
            ok, msg = launch_system_terminal(server)
            self._log(msg)
            if not ok:
                QMessageBox.warning(self, self.tr("msg_terminal_title"), msg)
            return

        password = None
        try:
            password = self._get_server_password(server)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, self.tr("msg_error_title"), str(exc))
            return

        result = self.loop.run_until_complete(
            self.ssh.connect(server, password=password, private_key_passphrase=None, options=ConnectionOptions(terminal_mode=mode))
        )
        self._log(result.message)
        if not result.success:
            return

        rules = self.loop.run_until_complete(self.repo.list_forward_rules(self.current_server_id))
        messages = self.loop.run_until_complete(self.ssh.apply_forward_rules(self.current_server_id, [r for r in rules if r.last_used and r.enabled]))
        for msg in messages:
            self._log(msg)
        self.loop.run_until_complete(self.repo.mark_server_used(self.current_server_id))

        msg = self.loop.run_until_complete(self.ssh.open_interactive_shell(self.current_server_id))
        self._log(msg)
        self._open_terminal_window(server)

    def _open_terminal_window(self, server: ServerProfile) -> None:
        if not self.current_server_id:
            return
        sid = self.current_server_id
        if sid in self.terminal_windows:
            win = self.terminal_windows[sid]
            win.show()
            win.raise_()
            win.activateWindow()
            return

        def _send_text(text: str) -> None:
            self.loop.run_until_complete(self.ssh.send_input(sid, text))

        def _send_control(code: str) -> None:
            self.loop.run_until_complete(self.ssh.send_control(sid, code))

        def _read_output() -> str:
            return self.loop.run_until_complete(self.ssh.read_output(sid))

        def _is_alive() -> bool:
            return self.ssh.is_shell_alive(sid)

        win = TerminalWindow(
            server_label=f"{server.username}@{server.host}:{server.port}",
            send_text=_send_text,
            send_control=_send_control,
            read_output=_read_output,
            is_alive=_is_alive,
            parent=None,
        )
        win.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        win.destroyed.connect(lambda *_: self.terminal_windows.pop(sid, None))
        self.terminal_windows[sid] = win
        win.show()

    def send_terminal_input(self) -> None:
        if not self.current_server_id:
            return
        text = self.terminal_input.text()
        if not text:
            return
        self.loop.run_until_complete(self.ssh.send_input(self.current_server_id, text + "\n"))
        self.terminal_input.clear()
        self.refresh_terminal_output()

    def refresh_terminal_output(self) -> None:
        if not self.current_server_id:
            return
        self.loop.run_until_complete(asyncio.sleep(0.15))
        data = self.loop.run_until_complete(self.ssh.read_output(self.current_server_id))
        if data:
            self.terminal_output.moveCursor(self.terminal_output.textCursor().MoveOperation.End)
            self.terminal_output.insertPlainText(data)

    def check_forward_rules(self) -> None:
        if not self.current_server_id:
            QMessageBox.information(self, self.tr("msg_error_title"), self.tr("msg_select_server"))
            return
        rules = self.loop.run_until_complete(self.repo.list_forward_rules(self.current_server_id))
        results = self.loop.run_until_complete(self.ssh.check_forward_rules(self.current_server_id, rules))
        ok_count = 0
        fail_count = 0
        for res in results:
            line = f"[{'OK' if res.ok else 'FAIL'}] {res.type.value} #{res.rule_id}: {res.detail}"
            self._log(line)
            if res.ok:
                ok_count += 1
            else:
                fail_count += 1
        QMessageBox.information(self, self.tr("button_check_forward"), self.tr("msg_forward_check_summary", ok=ok_count, fail=fail_count))

    def disconnect_current(self) -> None:
        if not self.current_server_id:
            return
        if self.current_server_id in self.terminal_windows:
            self.terminal_windows[self.current_server_id].close()
        self.loop.run_until_complete(self.ssh.disconnect(self.current_server_id))
        self._log(self.tr("msg_disconnected", server_id=self.current_server_id))

    def _build_export_bundle(self, passphrase: str) -> ExportBundleV1:
        if not self._ensure_master():
            raise RuntimeError("Master password missing")
        salt = generate_export_salt()
        servers = self.loop.run_until_complete(self.repo.list_servers())
        name_map = {s.id: s.name for s in servers if s.id is not None}

        exported_servers: list[ExportedServer] = []
        forward_rules: dict[str, list[ForwardRule]] = {}
        options: dict[str, ConnectionOptions] = {}

        for s in servers:
            pwd = self._get_server_password(s)
            key_pwd = None
            if s.private_key_passphrase_enc:
                key_pwd = self.crypto.decrypt(s.private_key_passphrase_enc, self.master_password or "")
            exported_servers.append(
                ExportedServer(
                    name=s.name,
                    host=s.host,
                    port=s.port,
                    username=s.username,
                    auth_type=s.auth_type,
                    password_export_enc=encrypt_for_export(pwd, passphrase, salt) if pwd else None,
                    private_key_path=s.private_key_path,
                    private_key_passphrase_export_enc=encrypt_for_export(key_pwd, passphrase, salt) if key_pwd else None,
                    jump_host_name=name_map.get(s.jump_host_id),
                    remark=s.remark,
                    remember_password=s.remember_password,
                )
            )
            sid = s.id or -1
            forward_rules[s.name] = self.loop.run_until_complete(self.repo.list_forward_rules(sid))
            options[s.name] = self.loop.run_until_complete(self.repo.get_connection_options(sid))

        return ExportBundleV1(
            schema_version=1,
            created_at=datetime.utcnow(),
            kdf="PBKDF2-HMAC-SHA256",
            salt=salt,
            servers=exported_servers,
            forward_rules=forward_rules,
            connection_options=options,
        )

    def export_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, self.tr("tool_export"), "sshmanager_export.json", "JSON Files (*.json)")
        if not path:
            return
        passphrase, ok = QInputDialog.getText(self, self.tr("tool_export"), self.tr("msg_export_passphrase"), QLineEdit.EchoMode.Password)
        if not ok or not passphrase:
            return
        try:
            bundle = self._build_export_bundle(passphrase)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(bundle.model_dump(mode="json"), f, ensure_ascii=False, indent=2)
            self._log(self.tr("msg_export_success", path=path))
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, self.tr("msg_error_title"), self.tr("msg_export_failed", err=str(exc)))

    def _unique_import_name(self, base_name: str) -> str:
        existing = {s.name for s in self.loop.run_until_complete(self.repo.list_servers())}
        if base_name not in existing:
            return base_name
        idx = 1
        while True:
            candidate = f"{base_name} (imported {idx})"
            if candidate not in existing:
                return candidate
            idx += 1

    def import_json(self) -> None:
        if not self._ensure_master():
            return
        path, _ = QFileDialog.getOpenFileName(self, self.tr("tool_import"), "", "JSON Files (*.json)")
        if not path:
            return
        passphrase, ok = QInputDialog.getText(self, self.tr("tool_import"), self.tr("msg_import_passphrase"), QLineEdit.EchoMode.Password)
        if not ok or not passphrase:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                bundle = ExportBundleV1.model_validate(json.load(f))
            salt = bundle.salt
            name_map_new_id: dict[str, int] = {}

            for es in bundle.servers:
                name = self._unique_import_name(es.name)
                pwd_enc = None
                if es.password_export_enc:
                    plain = decrypt_from_export(es.password_export_enc, passphrase, salt)
                    pwd_enc = self.crypto.encrypt(plain, self.master_password or "")
                key_pwd_enc = None
                if es.private_key_passphrase_export_enc:
                    plain = decrypt_from_export(es.private_key_passphrase_export_enc, passphrase, salt)
                    key_pwd_enc = self.crypto.encrypt(plain, self.master_password or "")

                sid = self.loop.run_until_complete(
                    self.repo.upsert_server(
                        ServerProfile(
                            name=name,
                            host=es.host,
                            port=es.port,
                            username=es.username,
                            auth_type=es.auth_type,
                            password_enc=pwd_enc,
                            private_key_path=es.private_key_path,
                            private_key_passphrase_enc=key_pwd_enc,
                            remark=es.remark,
                            remember_password=es.remember_password,
                        )
                    )
                )
                name_map_new_id[es.name] = sid

            for es in bundle.servers:
                sid = name_map_new_id[es.name]
                if es.jump_host_name and es.jump_host_name in name_map_new_id:
                    srv = self.loop.run_until_complete(self.repo.get_server_by_id(sid))
                    if srv:
                        srv.jump_host_id = name_map_new_id[es.jump_host_name]
                        self.loop.run_until_complete(self.repo.upsert_server(srv))

                imported_rules = bundle.forward_rules.get(es.name, [])
                rules = [ForwardRule(server_id=sid, type=r.type, bind_host=r.bind_host, bind_port=r.bind_port, target_host=r.target_host, target_port=r.target_port, enabled=r.enabled, last_used=r.last_used) for r in imported_rules]
                self.loop.run_until_complete(self.repo.replace_forward_rules(sid, rules))
                opts = bundle.connection_options.get(es.name)
                if opts:
                    self.loop.run_until_complete(self.repo.save_connection_options(sid, opts))

            self.reload_servers()
            self._log(self.tr("msg_import_success", count=len(bundle.servers)))
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, self.tr("msg_error_title"), self.tr("msg_import_failed", err=str(exc)))


def run_gui(repository, crypto) -> None:
    app = QApplication([])
    window = MainWindow(repository, crypto)
    window.show()
    app.exec()
