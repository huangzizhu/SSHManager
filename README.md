# SSHManager

一个跨 Windows/Linux 的 SSH 管理器，提供 GUI（PyQt6）和 CLI（Typer + Rich）双入口。

## 功能概览

- 服务器配置管理：保存主机、端口、用户名、认证方式、备注
- 凭据加密存储：主密码 + `cryptography` 加密，不明文保存密码
- 端口转发管理：支持本地/远程/动态转发规则并记忆上次配置
- 终端模式：
  - `system`：调用系统终端（支持密码手动输入）
  - `embedded`：内置交互终端（独立窗口）
- 一键“启用密钥登录”：自动生成本机私钥、写入远端 `authorized_keys`、切换为私钥认证
- 一键“检测并开启密钥认证”：自动诊断远端策略/权限，支持 sudo 时自动修复并重载 sshd
- GUI 与 CLI 可并行使用，数据统一存储在本地 SQLite

## 技术栈

- Python 3.13+
- AsyncSSH
- PyQt6
- Typer + Rich
- SQLite + aiosqlite
- cryptography
- Pydantic
- uv（项目与依赖管理）

## 快速开始

### 1. 安装依赖

```bash
uv sync
```

### 2. 启动 GUI（默认）

```bash
uv run python main.py
```

说明：无参数时默认进入 GUI，Windows 下可直接双击运行。

### 3. 查看 CLI 帮助

```bash
uv run python main.py --help
```

## 打包（Linux / Windows）

项目已提供 `PyInstaller` 打包脚本：`scripts/package.py`。

### 1. 安装打包依赖

```bash
uv sync --group dev
```

### 2. 在 Linux 打包

```bash
uv run python scripts/package.py --target linux --clean-output
```

产物目录：

- `dist/linux/sshmanager-gui/`（GUI）
- `dist/linux/sshmanager-cli/`（CLI）

### 3. 在 Windows 打包

请在 Windows 机器上执行（PyInstaller 不支持跨系统直接产出可用 exe）：

```bash
uv run python scripts/package.py --target windows --clean-output
```

产物目录：

- `dist/windows/sshmanager-gui/`（GUI）
- `dist/windows/sshmanager-cli/`（CLI）

### 4. 可选：打包成单文件

```bash
uv run python scripts/package.py --mode all --onefile --clean-output
```

说明：

- `main_gui.py`：只启动 GUI，适合桌面用户
- `main_cli.py`：只启动 CLI，适合终端用户

## VSCode 调试

已提供 `.vscode/launch.json`：

- `Python: Run main.py`：调试 CLI 入口
- `Python: Run GUI`：直接调试图形界面

## CLI 常用命令

### 列出服务器

```bash
uv run python main.py server list
```

### 新增服务器（密码认证）

```bash
uv run python main.py server add --name prod --host 1.2.3.4 --username root
```

### 编辑服务器

```bash
uv run python main.py server edit prod --host 8.8.8.8 --port 22
```

### 删除服务器

```bash
uv run python main.py server remove prod
```

### 连接服务器

```bash
uv run python main.py connect prod
```

### 使用系统终端连接

```bash
uv run python main.py connect prod --system-terminal
```

### 新增端口转发规则

```bash
uv run python main.py forward up prod --type local --bind-port 15432 --target-host 127.0.0.1 --target-port 5432
```

### 关闭端口转发规则

```bash
uv run python main.py forward down prod --rule 1
```

## 一键启用密钥登录

GUI 中选中一台“密码认证且已保存密码”的服务器后，点击 `启用密钥登录`：

1. 在本机生成 `ed25519` 密钥对
2. 自动写入远端 `~/.ssh/authorized_keys`（去重）
3. 切换本地配置为私钥认证
4. 自动测试私钥登录

默认密钥存储位置：

- `~/.sshmanager/keys/`

说明：

- 默认私钥是“本机专用”边界，不会随 JSON 导出自动跨机器迁移
- 若需要跨机器使用，需要你自行安全迁移私钥文件

## 启用密钥登录日志说明

点击按钮后，日志窗口会打印详细阶段信息：

- 开始启用（服务器信息/当前认证方式）
- 前置检查
- 本地密钥生成路径
- 远端写入 `authorized_keys` 和权限步骤
- 本地切换私钥认证
- 私钥测试结果
- 失败时回滚与错误详情

## 检测并开启密钥认证（自动诊断 + 自动修复）

在 `启用密钥登录` 按钮旁新增 `检测并开启密钥认证`，流程如下：

1. 先做远端诊断（用户层权限、公钥是否存在、`sshd -T` 生效配置）
2. 若远端支持 `sudo -n`，自动执行修复：
- 用户层：修正 `~/.ssh`/`authorized_keys` 权限并补齐公钥
- 系统层：确保 `PubkeyAuthentication yes`，必要时补 `AuthorizedKeysFile`
3. 执行 `sshd -t` 校验，成功后 `systemctl reload ssh`（或 `sshd`）
4. 自动测试私钥登录，成功后保持私钥认证

说明：

- 若无 sudo，会明确提示“可检测不可自动修复系统配置”
- 即使无 sudo，也会继续执行“用户层修复 + 私钥登录验证”
- 默认保持密码认证可用，不会自动关闭 password auth
- 日志窗口会输出每个检测/修复步骤的结果，便于排障
- 系统层自动修复失败时，会输出可复制的手工命令（`sshd -t` 与 reload）

## 系统终端密码粘贴辅助

- 当选择 `system` 且服务器为密码认证时，应用会自动把密码复制到剪贴板。
- 打开的系统终端中使用 `Ctrl+Shift+V` 粘贴输入。
- 出于安全考虑，60 秒后会自动清空该剪贴板内容（若内容未被你替换）。

## 内置终端自动滚动

- 默认输出会自动跟随到底部，适合 `tail -f`/`ping` 等持续输出。
- 当你手动上滑查看历史时，会暂停强制跟随，避免被抢焦点。

## 常见问题（Permission denied）

如果启用后仍出现 `Permission denied (publickey)`，请优先检查：

1. 远端目录权限
- `~/.ssh` 应为 `700`
- `~/.ssh/authorized_keys` 应为 `600`
- 用户 home 目录不应被 group/other 可写（OpenSSH `StrictModes`）

2. 服务端认证策略
- `/etc/ssh/sshd_config` 中 `PubkeyAuthentication` 未被禁用

3. 使用的私钥是否匹配
- 当前服务器配置中的 `private_key_path` 是否对应本次生成的私钥

4. 用户与主机是否一致
- 写入公钥和后续登录使用的是同一个远端用户

## 数据与安全

应用运行后会在用户目录创建：

- `~/.sshmanager/sshmanager.db`：SQLite 数据库
- `~/.sshmanager/master.secret`：主密码相关密钥材料

说明：

- 首次使用会要求设置主密码
- 保存的 SSH 密码会以密文形式写入数据库
- 如忘记主密码，将无法解密已有凭据

## 当前实现说明

- 已完成：核心分层、CLI、GUI、独立内置终端、加密存储、转发规则持久化
- 系统终端支持密码手动输入，也支持私钥连接
- 内置终端为独立窗口，连接后自动拉起

## 开发建议

```bash
uv run python -m compileall src
```

如果网络可访问 PyPI，可安装并运行测试：

```bash
uv add --dev pytest
uv run pytest
```
