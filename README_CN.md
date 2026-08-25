🌐 [English](README.md) | [Русский](README_RU.md)

# AIVPN

[![CI](https://github.com/infosave2007/aivpn/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/infosave2007/aivpn/actions/workflows/ci.yml)
[![Crates.io Server](https://img.shields.io/crates/v/aivpn-server.svg?label=aivpn-server)](https://crates.io/crates/aivpn-server)
[![Crates.io Client](https://img.shields.io/crates/v/aivpn-client.svg?label=aivpn-client)](https://crates.io/crates/aivpn-client)
![Rust](https://img.shields.io/badge/rust-1.75%2B-blue.svg)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%20%7C%20iOS%20%7C%20MikroTik-informational)

---

## 概述

AIVPN 是一款基于 UDP 的 VPN 系统，将标准隧道加密与**流量拟态**相结合：出站数据包被重塑为已知应用协议的形态（WebRTC、QUIC、DNS-over-UDP），使连接在统计上与正常应用流量无法区分。

核心技术特性：

- **零 RTT 数据启动** — 加密载荷可从第一个数据包开始传输，无需强制握手往返。
- **O(1) 会话查找** — 明文中不传输会话 ID。每个数据包携带一个 8 字节的*共振标签*，由时间戳和每会话密钥派生。服务器通过 `DashMap` 以常数时间解析会话。
- **完美前向保密** — 通过 X25519 棘轮机制进行飞行中会话密钥轮换。服务器密钥泄露不会暴露过去的流量。
- **神经共振模块** — 每个掩码的微型 MLP（约 66 KB）实时监控流量统计；高重建误差触发自动掩码轮换，不中断客户端连接。
- **生成式掩码分布** — 从真实流量自动录制的掩码，使用按 BIC 选择组件数的高斯混合模型（设计文档 §4「神经生成掩码」）对多模态的包大小/到达间隔行为建模，比单一高斯更真实地重现 DNS/QUIC/WebRTC 的实际分布。它是每个客户端透明采样的内部表示，而非新的掩码类型。
- **Rust 编写** — 内存安全，无 GC 停顿。客户端二进制约 2.5 MB，可在 $5 VPS 上运行。

---

## 架构

### 工作区布局

```
crates/aivpn-common/     — 共享加密、协议、掩码配置（无 I/O）
crates/aivpn-server/     — 仅 Linux VPN 网关和管理 CLI
crates/aivpn-client/     — 跨平台 VPN 客户端（Linux / macOS / Windows）
crates/aivpn-android-core/ — Android JNI 桥接（Rust → Kotlin via C FFI）
crates/aivpn-ios-core/   — iOS Rust 静态库（C FFI），链接至 PacketTunnelProvider
crates/aivpn-windows/    — Windows GUI（egui/eframe 0.31，管理 aivpn-client.exe 子进程）
crates/aivpn-linux/      — Linux GUI（iced 0.13，封装 aivpn-client 子进程）
platforms/android/       — Android Kotlin 应用（MVVM：MainViewModel + RecyclerView）
platforms/ios/           — iOS SwiftUI 应用 + NetworkExtension PacketTunnelProvider
platforms/macos/         — macOS SwiftUI 菜单栏应用 + 特权辅助守护程序
platforms/aivpn-web/     — Web 管理面板（Hono 4 + SvelteKit 2，SQLite/PostgreSQL）
platforms/linux/         — Linux 桌面打包（AppImage、.desktop）
platforms/linux-kernel/  — 可选的内核态数据路径模块
platforms/openwrt/       — OpenWrt 软件包
platforms/mikrotik/      — MikroTik RouterOS 容器
assets/masks/            — 捆绑的流量拟态 JSON 配置文件
assets/brand/            — 图标与品牌素材
deploy/                  — 服务器安装脚本、systemd unit、Dockerfile
deploy/ci/               — 由 Makefile 调用的 CI 门禁（见 `make help`）
```

### 核心模块

| 模块 | 位置 | 用途 |
|------|------|------|
| `crypto.rs` | `aivpn-common` | X25519 密钥交换、ChaCha20-Poly1305 AEAD、BLAKE3/HMAC、共振标签生成 |
| `protocol.rs` | `aivpn-common` | 线路格式：`[8字节标签][pad_len][内部头][加密载荷][poly1305标签]` |
| `mask.rs` | `aivpn-common` | `MaskProfile` — 流量整形：头部模板、FSM 状态、IAT 分布 |
| `gateway.rs` | `aivpn-server` | 核心事件循环：UDP 接收、会话分发、NAT 转发、神经检查 |
| `session.rs` | `aivpn-server` | `SessionManager` — `DashMap` O(1) 查找，256 条目重放窗口 |
| `neural.rs` | `aivpn-server` | 神经共振：每掩码 MLP 64→128→64，MSE 阈值 0.35，自动轮换 |
| `client.rs` | `aivpn-client` | 状态机：未配置 → 连接中 → 已连接，密钥交换，重连 |
| `tunnel.rs` | `aivpn-client` | 跨平台 TUN：`/dev/net/tun`（Linux）、`utun`（macOS）、Wintun（Windows） |
| `mimicry.rs` | `aivpn-client` | `MimicryEngine` — 对出站数据包应用 `MaskProfile` |

### 节点池同步

服务器间客户端数据库同步使用 `ControlPayload::PoolSync`，通过普通 VPN UDP 数据包传输 — 与客户端流量无法区分。无需单独 TCP 端口或防火墙规则。

---

## 平台支持

| 平台 | 服务器 | 客户端 | GUI | TUN 驱动 |
|------|:------:|:------:|:---:|---------|
| Linux CLI | ✅ | ✅ | — | `/dev/net/tun` |
| Linux GUI | — | ✅ | ✅ iced AppImage + 托盘 | `/dev/net/tun` |
| macOS | — | ✅ | ✅ 菜单栏 | `utun` |
| Windows | — | ✅ | ✅ egui GUI | [Wintun](https://www.wintun.net/) |
| Android | — | ✅ | ✅ 原生 Kotlin | `VpnService` API |
| iOS | — | ✅ | ✅ SwiftUI | `NetworkExtension` |
| MikroTik RouterOS 7.6+ | — | ✅ | — | 容器 veth + TUN |
| Entware 路由器（ARMv7 / MIPSel） | — | ✅ | — | musl 静态二进制 |

### 功能能力矩阵

| 功能 | Linux CLI | Linux GUI | Win | Mac | Android | iOS |
|------|:---------:|:---------:|:---:|:---:|:-------:|:---:|
| 流量伪装 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 自适应模式（4 级） | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 实时连接质量 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 分流隧道 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| DNS 代理 | ✅ | ✅ | ✅ | ✅ | 不适用* | ❌ |
| Kill Switch | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| mTLS 证书 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| FEC（前向纠错） | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 流量录制 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 设备密钥 / JIT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SOCKS5 代理 | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| 全流量隧道 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 诊断 / 基准测试 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Bootstrap 描述符发现 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 多态掩码 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 众包掩码反馈（可选启用） | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 实时指标图表† | — | — | — | — | — | — |

\* Android 的 `VpnService` API 默认将设备的所有流量(包括 DNS)通过加密隧道路由 —— 无需单独的本地 DNS 代理监听器,该平台不存在 DNS 泄漏风险。

† 实时指标图表是服务器与 [Web 管理面板](#web-管理面板) 的功能，不是客户端能力 —— 需要以 `--features metrics` 构建服务器，并在 Web 仪表盘中查看，而非在上表列出的任何客户端中查看。

---

## Web 管理面板

`platforms/aivpn-web/` 为 aivpn 服务器提供全栈 Web 管理界面。

**技术栈：** Hono 4 + Bun（后端）· SvelteKit 2 + Svelte 5 + TailwindCSS 4（前端）· Layerchart 图表 · SQLite（默认）或 PostgreSQL

**功能特性：**
- JWT 认证（15 分钟 access token + 7 天 refresh httpOnly cookie），argon2id 密码哈希
- TOTP 双因素认证（AES-256-GCM 加密存储密钥）和 WebAuthn passkey
- 角色：`admin`（完全访问）和 `viewer`（只读）
- 页面：Dashboard（实时图表）、Clients、Config、Masks、Backup、Logs、Settings
- 所有 `/api/v1/*` 请求代理至 aivpn Unix 套接字（`/run/aivpn/api.sock`）
- `/web/events` 实时 SSE 事件流
- **实时指标图表** —— Dashboard 渲染实时时间序列图表（活跃会话数、上下行带宽、包速率、p50/p95 数据包处理延迟），以及掩码/密钥轮换和已检测 DPI 攻击计数的脉冲徽标；数据全部通过同一条 `/web/events` SSE 流传输，来自内存中约 10 分钟的环形缓冲区，不引入新的持久化存储。需要以 `--features metrics` 构建服务器（参见[可选功能（Cargo）](#可选功能cargo)）；若服务器未启用该功能，仪表盘会显示提示而非图表。

**快速开始：**

```bash
# 1. 生成密钥
JWT_SECRET=$(openssl rand -base64 48)
TOTP_KEY=$(openssl rand -base64 32)

# 2. 通过 Docker 运行（最简方式）
docker run -d --name aivpn-web \
  -v /run/aivpn:/run/aivpn \
  -e JWT_SECRET="$JWT_SECRET" \
  -e TOTP_ENCRYPTION_KEY="$TOTP_KEY" \
  -e ORIGIN=https://vpn.example.com \
  -p 8080:8080 \
  ghcr.io/infosave2007/aivpn-web:latest

# 3. 从启动日志获取一次性管理员密码
docker logs aivpn-web 2>&1 | grep -A4 "FIRST-TIME SETUP"

# 4. 打开 https://vpn.example.com，使用用户名 "admin" 登录
```

或通过 `docker compose up -d aivpn-web`（密钥填写在 `platforms/aivpn-web/.env` 中）。

**运行（Bun，从源码）：**
```bash
cd platforms/aivpn-web
cp .env.example .env          # 填写 JWT_SECRET、TOTP_ENCRYPTION_KEY、ORIGIN
bun install && bun run build
bun run start                 # 监听 PORT（默认 8080）
```

**关键环境变量：**

| 变量 | 默认值 | 描述 |
|------|--------|------|
| `DATABASE_URL` | `file:./data/aivpn-web.db` | SQLite 路径或 `postgres://...` |
| `JWT_SECRET` | — | 用于令牌签名的长随机字符串 |
| `TOTP_ENCRYPTION_KEY` | — | 32 字节 base64 密钥（`openssl rand -base64 32`） |
| `ORIGIN` | — | 公共 HTTPS URL（WebAuthn / CSRF 必需） |
| `UNIX_SOCK` | `/run/aivpn/api.sock` | aivpn 管理套接字路径 |
| `PORT` | `8080` | HTTP 监听端口 |

**Makefile 构建目标：**
```bash
make web           # 安装依赖 + 构建前端
make web-docker    # 构建 Docker 镜像 aivpn-web:latest
make web-dev       # 启动开发服务器（热重载）
```

nginx 反向代理配置示例见 `deploy/nginx/aivpn-web.conf`。

**默认凭据（首次运行）：**

首次启动时，如果数据库为空，系统会自动生成一个随机管理员密码，并**仅一次**输出到服务器控制台：

```
╔══════════════════════════════════════════════════╗
║         FIRST-TIME SETUP — SAVE THESE NOW        ║
╠══════════════════════════════════════════════════╣
║  Username : admin                                 ║
║  Password : <约22位随机 base64url 字符串>          ║
╚══════════════════════════════════════════════════╝
```

请立即保存此密码——它仅显示一次。登录后，请在 **Settings → Security** 中修改密码或注册 Passkey。

**OIDC / SSO（可选）：**

| 变量 | 描述 |
|------|------|
| `OIDC_ISSUER` | IdP 基础 URL（例如 `https://accounts.google.com`） |
| `OIDC_CLIENT_ID` | OAuth2 Client ID |
| `OIDC_CLIENT_SECRET` | 客户端密钥（公开 PKCE 客户端可省略） |
| `OIDC_MODE` | `disabled`（默认）· `enabled`（添加 SSO 按钮）· `exclusive`（仅 SSO） |
| `OIDC_ROLE_CLAIM` | ID Token 中用于读取角色的 Claim 名称（例如 `role`） |
| `OIDC_ADMIN_VALUE` | 授予 `admin` 角色的 Claim 值（默认：`admin`） |

OIDC 角色仅在**首次** SSO 登录时应用；管理员之后可通过 Web 面板随时修改。

---

## 快速入门

### 服务器（Linux）

#### Docker（推荐）

```
mkdir -p config
docker compose up -d aivpn-server
```

容器首次启动时自动生成 `server.key` 和 `server.json`，以 `network_mode: host` 运行，挂载 `./config` → `/etc/aivpn`。

开放防火墙 UDP 443 端口：

```
# UFW
sudo ufw allow 443/udp
# firewalld
sudo firewall-cmd --add-port=443/udp --permanent && sudo firewall-cmd --reload
```

#### 裸机

```
sudo mkdir -p /etc/aivpn
openssl rand 32 | sudo tee /etc/aivpn/server.key > /dev/null
sudo chmod 600 /etc/aivpn/server.key
sudo ./aivpn-server --listen 0.0.0.0:443 --key-file /etc/aivpn/server.key
```

服务器自动启用 IPv4 转发并安装 NAT 伪装规则（优先 nftables，回退 iptables）。隧道本身无需手动配置防火墙。

#### 添加客户端

```
# Docker
docker compose exec aivpn-server aivpn-server \
    --add-client "Alice Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip 您的公网IP:443

# 裸机
aivpn-server \
    --add-client "Alice Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip 您的公网IP:443
```

输出包含连接密钥（`aivpn://…`）— 分发给客户端。

其他管理命令：`--list-clients`、`--show-client`、`--remove-client`。

---

### 客户端 — Linux

```
sudo ./aivpn-client -k "aivpn://..."
# 全隧道（所有流量通过 VPN）
sudo ./aivpn-client -k "aivpn://..." --full-tunnel
```

### 客户端 — macOS

从 [Releases](https://github.com/infosave2007/aivpn/releases) 下载 `aivpn-macos.dmg`，将 **Aivpn.app** 拖入 Applications，启动 — 出现在菜单栏。粘贴连接密钥并点击 **Connect**。

命令行：
```
sudo ./aivpn-client -k "aivpn://..."
```

> 应用通过 `sudo` 请求密码以创建 `utun` 接口。

### 客户端 — Windows

**安装程序（推荐）：** 下载 `aivpn-windows-installer.exe`，以管理员身份运行，从开始菜单启动 **AIVPN**。

**便携版：** 解压 `aivpn-windows-package.zip`（包含 `aivpn.exe`、`aivpn-client.exe`、`wintun.dll`），以管理员身份运行 `aivpn.exe`。

命令行（PowerShell，管理员权限）：
```
.\aivpn-client.exe -k "aivpn://..."
```

> 创建 Wintun 网络适配器需要管理员权限。

### 客户端 — Android

1. 安装 `aivpn-client.apk`
2. 粘贴连接密钥（`aivpn://…`）
3. 点击 **Connect**

### 客户端 — iOS

在 macOS 上构建（需要 Xcode 15+）：

```
make ios TEAM_ID=您的TEAM_ID
```

安装 `releases/aivpn-ios.ipa`：
```
xcrun devicectl device install app --device <UDID> releases/aivpn-ios.ipa
```

> 免费 Apple 开发者账户即可。侧载构建 7 天后过期。

### 客户端 — Entware 路由器（ARMv7 / MIPSel）

```
scp aivpn-client-linux-armv7-musleabihf root@router:/opt/bin/aivpn-client
ssh root@router 'chmod +x /opt/bin/aivpn-client && /opt/bin/aivpn-client -k "aivpn://..."'
```

### 客户端 — MikroTik RouterOS 7.6+

```
/system/device-mode/update container=yes
/interface/veth/add name=veth-aivpn address=172.31.0.2/30 gateway=172.31.0.1
/ip/address/add address=172.31.0.1/30 interface=veth-aivpn
/container/mounts/add name=aivpn-tun src=/dev/net/tun dst=/dev/net/tun type=bind
/container/envs/add list=aivpn-env name=AIVPN_KEY value="aivpn://..."
/container/add remote-image=infosave2007/aivpn-mikrotik:latest interface=veth-aivpn start-on-boot=yes envlist=aivpn-env mounts=aivpn-tun
/container/start [find remote-image~"aivpn-mikrotik"]
/ip/route/add dst-address=0.0.0.0/0 gateway=172.31.0.2
```

详见 [platforms/mikrotik/README.md](platforms/mikrotik/README.md)。

### SOCKS5 代理模式（无需 root）

```
aivpn-client -k "aivpn://..." --proxy-listen 127.0.0.1:1080
```

配置 Firefox / Chrome / curl 使用 `SOCKS5 127.0.0.1:1080`，无需 TUN 设备或管理员权限。

---

## 连接密钥格式

连接密钥将所有服务器和客户端参数编码为单个可移植字符串：

```
aivpn://<base64url(JSON)>
```

JSON 字段：

| 字段 | 类型 | 描述 |
|------|------|------|
| `s` | `string` | 服务器地址，如 `"1.2.3.4:443"` |
| `k` | `string` | 服务器 X25519 公钥（base64） |
| `p` | `string` | 客户端预共享密钥 / PSK（base64） |
| `i` | `string` | 客户端静态 VPN IP，如 `"10.0.0.2"` |
| `n` | `object` | *（可选）* 引导 `network_config`（见下文） |

`network_config` 对象（`n`）：

| 字段 | 描述 |
|------|------|
| `client_ip` | 客户端 TUN IP |
| `server_vpn_ip` | 服务器 TUN IP |
| `prefix_len` | 子网前缀长度 |
| `mtu` | 内部 MTU |

连接时的优先级：

1. `ServerHello` 确认的设置（权威）
2. 密钥中的引导 `network_config`
3. 传统回退 `10.0.0.0/24`

不含 `network_config` 的密钥完全兼容。

生成密钥：
```
aivpn-server --add-client "姓名" --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json --server-ip IP:PORT
```

重新打印现有密钥：
```
aivpn-server --show-client "姓名" --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json --server-ip IP:PORT
```

---

## 服务器配置参考

默认配置路径：`config/server.json`（本地）或 `/etc/aivpn/server.json`。CLI 标志覆盖文件值。

```json
{
  "listen_addr": "0.0.0.0:443",
  "tun_name": "aivpn0",
  "tun_mtu": "auto",
  "mask_dir": "/var/lib/aivpn/masks",
  "bootstrap_mask_files": [],
  "session_timeout_secs": 0,
  "idle_timeout_secs": 300,
  "allow_peer_routing": false,
  "network_config": {
    "server_vpn_ip": "10.0.0.1",
    "prefix_len": 24,
    "mtu": 1346,
    "keepalive_secs": 8,
    "ipv6_enabled": false,
    "ipv6_prefix": "fd10:cafe::/48"
  },
  "pool": {
    "peers": [],
    "sync_key": ""
  }
}
```

| 字段 | 默认值 | 描述 |
|------|--------|------|
| `listen_addr` | `0.0.0.0:443` | UDP 绑定地址，端口自动嵌入连接密钥 |
| `tun_name` | 随机 | TUN 接口名称 |
| `tun_mtu` | _（未设置）_ | `"auto"` = 物理 MTU 减去 64 字节开销（回退 1346）；或固定整数 |
| `mask_dir` | `/var/lib/aivpn/masks` | 扫描 `.json` 掩码配置文件的目录 |
| `bootstrap_mask_files` | `[]` | 启动时预加载的掩码文件，降低首次连接延迟 |
| `session_timeout_secs` | `0` | 会话硬性上限；`0` = 无限制 |
| `idle_timeout_secs` | `300` | 断开静默超时（秒） |
| `allow_peer_routing` | `false` | 在子网内路由 VPN 客户端间的数据包 |
| `network_config.server_vpn_ip` | `10.0.0.1` | 服务器 TUN IP |
| `network_config.prefix_len` | `24` | VPN 子网前缀 |
| `network_config.mtu` | `1346` | 通过 `ServerHello` 发送给客户端的内部 MTU |
| `network_config.keepalive_secs` | `8` | 与客户端协商的心跳间隔 |
| `network_config.ipv6_enabled` | `false` | 启用 IPv6 NAT66 |
| `network_config.ipv6_prefix` | `fd10:cafe::/48` | 客户端 IPv6 地址的 ULA /48 前缀 |
| `pool.peers` | `[]` | 数据库同步的对等服务器地址 |
| `pool.sync_key` | `""` | 共享 32 字节 BLAKE3 密钥（base64）。生成：`openssl rand -base64 32` |

### 可选功能（Cargo）

| 功能 | 启用内容 |
|------|---------|
| `neural` | 神经共振模块（基于 MSE 的掩码轮换） |
| `management-api` | Unix 套接字 HTTP API，位于 `/run/aivpn/api.sock` |
| `metrics` | Prometheus 导出器，以及通过 `/web/events` SSE 提供的实时运行时指标（活跃会话、带宽、掩码/密钥轮换、已检测 DPI 攻击、数据包处理延迟），用于 [Web 面板的实时图表](#web-管理面板) |
| `passive-distribution` | 引导描述符分发渠道 |
| `bootstrap-publish` | 将轮换后的引导描述符自动发布到 S3/GitHub/Telegram（参见 [引导描述符分发](#引导描述符分发)） |

```
cargo build --release --bin aivpn-server --features "management-api,metrics,neural"
```

---

## 从源码构建

要求：Rust 1.75+、`cargo`、`make`。

```
git clone https://github.com/infosave2007/aivpn
cd aivpn
make help          # 显示所有可用目标
```

### 服务器构建（Linux）

```
make server        # x86_64 → releases/aivpn-server-linux-x86_64
make server-arm64  # ARM64  → releases/aivpn-server-linux-arm64
make server-docker # 通过 Docker 构建（主机依赖最少）
```

### 客户端构建

```
make client        # Linux x86_64
```

### 静态 musl 构建（用于路由器）

```
make server-musl-armv7    # ARMv7
make server-musl-mipsel   # MIPSel
make server-musl-aarch64  # AArch64
```

### 各平台构建

```
make windows              # Windows GUI + zip（从 Linux 交叉编译）
make windows-docker       # Windows GUI 通过 Docker（无需 mingw-w64）
make ios TEAM_ID=XX       # iOS IPA（仅限 macOS + Xcode 15+）
make macos                # macOS .app + .pkg + .dmg（仅限 macOS）
make linux                 # Linux GUI 二进制（无需额外工具）
make linux-appimage        # Linux GUI AppImage（需要 appimagetool）
```

### 部署

```
make deploy               # VPS：下载二进制文件 + 启动 docker compose
make server-deploy HOST=vps.example.com  # SSH：上传本地二进制文件到 VPS
```

### 测试与开发

```
make test           # cargo test --workspace
make clippy         # cargo clippy
make check          # cargo check（快速检查）
make test-docker    # 集成测试：服务器 + 客户端在 Docker 中
```

### Android

```
export ANDROID_SDK_ROOT=/opt/android-sdk
export ANDROID_NDK_ROOT=/opt/android-ndk
echo "sdk.dir=$ANDROID_SDK_ROOT" > platforms/android/local.properties

make android
```

签名构建：运行脚本前创建 `platforms/android/keystore.properties`。

### 从 crates.io 安装

```
cargo install aivpn-client
cargo install aivpn-server
```

---

## 高级功能

### 设备绑定（JIT 注册）

连接密钥可指定为*一次性*：第一个连接的设备绑定其 X25519 静态密钥，来自不同设备的后续连接将被拒绝。

```
# 创建注册槽位
aivpn-server --add-client-one-time "Alice-Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip IP:PORT

# 重置绑定（重新启用注册）
aivpn-server --reset-device "Alice-Phone" \
    --clients-db /etc/aivpn/clients.json
```

各平台设备密钥存储位置：

| 平台 | 位置 |
|------|------|
| Linux / macOS | `~/.config/aivpn/device.key`（权限 600，自动生成） |
| Windows | `%APPDATA%\aivpn\device.key` |
| Android | 通过 `EncryptedSharedPreferences` 使用 Android Keystore |
| iOS | Keychain，`kSecAttrAccessibleAfterFirstUnlock` |

### 连接质量评分与自适应模式

AIVPN 持续计算 **0–100 质量评分**，来源：RTT（40 分）、抖动（20 分）、丢包（30 分）、Neural MSE（10 分）。自适应模式自动调整心跳间隔和 FEC 组大小：

| 评分 | 自适应级别 | 心跳 | FEC 组 |
|------|-----------|------|--------|
| 80–100 | 关闭 | 8 秒 | 禁用 |
| 50–79 | 轻度 | 6 秒 | 1/16 |
| 20–49 | 积极 | 4 秒 | 1/8 |
| 0–19 | 卫星 | 15 秒 | 1/4 |

```
aivpn-client -k "aivpn://..." --adaptive
```

### 前向纠错（FEC）

每 N 个上行数据包发送一个 XOR 修复包。如果一组中恰好丢失一个包，服务器立即重建 — 无需重传往返。N 由自适应模式控制。清洁链路上 FEC 禁用。

### 多服务器节点池同步

```json
{
  "pool": {
    "peers": ["node2.example.com:443"],
    "sync_key": "<base64-32字节密钥>"
  }
}
```

### 多跳链式转发

客户端流量通过两个 AIVPN 节点路由。客户端仅连接入口节点；互联网看到出口节点的 IP。

**入口节点：**
```json
{ "pool": { "sync_key": "<密钥>", "exit_node": "exit.example.com:443" } }
```
**出口节点：**
```json
{ "pool": { "sync_key": "<相同密钥>", "exit_node_enabled": true } }
```

### 引导描述符分发

已签名（ed25519）的引导描述符让全新客户端——尚未拥有可用 `aivpn://` 密钥的客户端——能够通过与客户端 `bootstrap_loader.rs` 已支持的相同多重后备渠道（CDN/GitHub/Telegram）发现可用的掩码配置。服务器每 24 小时自动生成、签名并轮换这些描述符，并在现有会话中向已连接客户端推送最新副本。

**CLI 导出** — 打印或保存当前上一个/当前/下一个纪元的已签名描述符（JSON 格式），供手动上传到任意托管服务：
```bash
aivpn-server --export-bootstrap-descriptor --key-file /etc/aivpn/server.key
aivpn-server --export-bootstrap-descriptor --key-file /etc/aivpn/server.key --bootstrap-output /path/to/bootstrap.json
```
需要提供真实的 `--key-file`——临时（随机生成）的服务器密钥会被拒绝，因为没有客户端会信任由一次性密钥签名的描述符。

**管理 API 导出** — 相同的 JSON 数组可通过 `GET /api/v1/bootstrap/export` 获取（需启用 `management-api` 功能，使用与 API 其余部分相同的 Unix 套接字认证模型）。在 Web 面板的任何代理层中，都应将其视为仅限管理员访问的端点，与 `/config`、`/backup/*` 一致。

**轮换时自动发布** — 使用 `--features bootstrap-publish` 构建服务器，并在 `server.json` 中添加 `bootstrap_publish` 配置段，即可在每次 24 小时纪元真正推进时自动推送最新轮换的描述符：
```json
{
  "bootstrap_publish": {
    "enabled": true,
    "channels": [
      { "type": "s3", "endpoint": "https://s3.us-east-1.amazonaws.com", "region": "us-east-1", "bucket": "my-aivpn-bootstrap", "key": "bootstrap.json", "access_key": "...", "secret_key": "..." },
      { "type": "github", "repo": "owner/repo", "asset_name": "bootstrap-descriptors.json", "tag_name": "bootstrap", "token": "..." },
      { "type": "telegram", "bot_token": "...", "chat_id": "..." }
    ]
  }
}
```

- **S3** — 支持任意 S3 兼容存储服务（AWS S3、Cloudflare R2、MinIO），采用路径风格寻址（`{endpoint}/{bucket}/{key}`），使用 AWS SigV4 签名。
- **GitHub** — 以固定 `tag_name` 的 release 资源形式发布（每次轮换都会更新，因为客户端始终请求 `/releases/latest`）。建议使用仅限该单一仓库权限的细粒度个人访问令牌。
- **Telegram** — 通过 Bot 以文档形式发送（`sendDocument`）。建议将 Bot 权限限制在单个聊天/频道内。

每个渠道相互独立（一个渠道失败不会阻塞其他渠道），失败后会按退避策略重试 3 次（5 秒 / 30 秒 / 120 秒），之后才记录失败日志。若未启用 `bootstrap-publish` 功能，`enabled: true` 只会记录一条警告并且不执行任何操作——配置段本身始终是合法的 JSON，因此配置文件可在不同构建之间通用。

**安全提示：** 如果服务器私钥被泄露，攻击者本就能够伪造有效的引导描述符（签名密钥是由私钥确定性派生的）。自动发布所用的凭据本身并不会增加这种伪造能力，但会让被攻破的服务器通过运营者真实、受信任的分发渠道将伪造描述符推送出去，从而波及全新用户，而不仅仅是已连接的用户——因此应对 `server.json` 中的这些凭据给予与其他任何机密同等的保护（文件权限 `0600`，仅运行 `aivpn-server` 的用户可读）。

### 本地 DNS 代理

```
aivpn-client -k "aivpn://..." --dns-proxy 127.0.0.1:5300 --dns-upstream 1.1.1.1:53
```

### 流量录制 — 自定义掩码创建

```
aivpn-client record start --service myapp
# ... 使用应用程序 60+ 秒 ...
aivpn-client record stop
```

服务器分析数据包大小直方图和到达间隔时间，生成 `MaskProfile`，通过自测验证，并分发到活跃会话。

### 多态掩码

每个会话都可以使用基础掩码的一个专属、经过唯一扰动的变体，这样单一的静态掩码档案就无法被跨用户、跨会话地指纹识别。服务器会根据会话自身的密钥材料确定性地推导出该变体，并通过现有的 `MaskUpdate` 通道推送给客户端——客户端只需应用它，不涉及任何新的客户端侧加密逻辑。扰动被限制在每个掩码安全的边界内（IAT 抖动幅度、填充偏移、报文头间隙字节数、FSM 停留时间缩放），从而使流量仍然与被模仿的协议保持可信的一致性；FSM 状态图、被模仿的协议以及临时密钥长度永远不会改变。初始握手始终使用备用的 bootstrap 掩码（而非具名预设），因此在该会话的变体被推送之前无法被指纹识别。

```
aivpn-client -k "aivpn://..." --polymorphic-base webrtc_yandex_telemost_v1
```

Linux、Windows、macOS、iOS 和 Android 的 GUI 中，掩码选择器旁都提供了对应的“Polymorphic”复选框。

掩码档案可以选择性地声明 `perturbation_bounds`，用来控制多态变体相对基础档案可以偏离的幅度：

```json
{
  "mask_id": "webrtc_yandex_telemost_v1",
  "perturbation_bounds": {
    "iat_jitter_scale": 0.15,
    "padding_shift_bytes": 8,
    "header_gap_bytes": 4,
    "fsm_dwell_scale": 0.2
  }
}
```

### 众包掩码反馈（可选启用）

客户端可以选择启用（默认关闭）分享哪些掩码对自己有效，并接收服务器提供的、关于所在地区哪些掩码效果良好的提示。上报数据按照用户自行设置的粗粒度双字母 ISO-3166 国家代码进行聚合——更精确的位置信息永远不会离开客户端。服务器只有在为某个掩码/地区累积到至少 K=20 个不同上报者时才会聚合数据（通过不存储任何上报者身份信息的 HyperLogLog 草图进行跟踪），并在同一大洲的邻近国家越过 k-匿名阈值后，对样本稀少的国家按大洲汇总；聚合数据占用的内存受硬性上限约束，并配有淘汰机制和周期性清理。单一上报者的投票上限还会限制单个上报者对某地区排名的影响程度。

桌面客户端会同时记录掩码的*成功和失败*情况：握手前的连接失败会被批量记录并归因到当时使用的掩码，持久化保存在 `~/.config/aivpn/mask_feedback.json` 中，重启后依然保留，并在下一次连接成功时聚合上报。启用 `--receive-mask-hints` 后，客户端会将初始掩码选择柔性偏向本地区评分最高的预设——该机制绝不会覆盖显式设置的 `--preferred-mask`/`--polymorphic-base`，也绝不会在初始掩码必须保持为已签名的 bootstrap 描述符时生效（例如 `--no-fallback`/production-secure 构建），因此不会削弱 bootstrap 的安全性。`--share-mask-feedback` 与 `--receive-mask-hints` 是完全独立的开关——客户端可以只接收地区提示而从不分享自己的反馈。

服务器通过 `FeedbackConfig` 控制消息向已启用该功能的客户端下发上报节奏参数，可通过 `server.json` 中可选的 `"feedback"` 块进行配置：

```json
{
  "feedback": {
    "report_failure_threshold": 3,
    "report_interval_secs": 3600
  }
}
```

`report_failure_threshold` 是某个掩码被标记为失败前所需的最小连续失败次数；`report_interval_secs` 是客户端两次上报之间的最小间隔（秒）。两者均为可选项，若省略该块（或某个键），默认值分别为 `3` 和 `3600`。

```
aivpn-client -k "aivpn://..." --share-mask-feedback --receive-mask-hints --country-code DE
```

Linux、Windows、macOS、iOS 和 Android 的 GUI 设置界面中同样提供这两个开关和国家代码字段。

### 基准测试

```
aivpn-client bench -k "aivpn://..."
# P50: 12ms  P95: 28ms  Up: 47 Mbps  Down: 52 Mbps  Score: 94/100
aivpn-client bench -k "aivpn://..." --json
```

---

### 掩码签名与验证（来源可信）

掩码定义了流量如何被整形，更关键的是*数据包如何被解析*（`tag_offset`、头部布局、
`spoof_protocol`）。因此，一个恶意或损坏的掩码到达服务器或客户端就是一个真实的攻击面。
aivpn 的掩码对**整个**配置携带 ed25519 签名；服务器可用运营者密钥对其分发的掩码签名，
服务器和客户端都可在加载时验证该签名。

验证有三种模式（`mask_verify_mode`，或 `--mask-verify-mode`，环境变量
`AIVPN_MASK_VERIFY_MODE`）：

| 模式 | 行为 |
|------|------|
| `off` | 不做签名校验。 |
| `warn` | **默认。** 校验并在失败时记录警告，但仍加载掩码——若掩码库尚未签名也不会中断。 |
| `enforce` | 拒绝任何签名无法用运营者公钥验证的掩码。需先对整个掩码库签名。 |

启用 `enforce` 的运营者流程：

```bash
# 1. 生成运营者签名密钥（打印用于分发的公钥）。
aivpn-server --gen-mask-signing-key /etc/aivpn/mask-signing.key

# 2. 就地对整个掩码库签名（运行一次；新增掩码后再次运行）。
aivpn-server --sign-mask-dir /var/lib/aivpn/masks --mask-signing-key /etc/aivpn/mask-signing.key

# 3. 服务器：指定签名密钥（自动为新生成的掩码签名）并启用 enforce。
#    server.json:  "mask_signing_key": "/etc/aivpn/mask-signing.key", "mask_verify_mode": "enforce"

# 4. 客户端：向其分发运营者公钥并启用 enforce。
#    client:  --mask-operator-pubkey <BASE64_PUBKEY> --mask-verify-mode enforce
```

公钥也会对下行的 `reverse_profile` 独立验证。由于 `enforce` 会拒绝未签名的掩码，
请分阶段推出——在每台服务器的掩码目录都已签名、且客户端都已携带公钥之前，保持 `warn`。
签名密钥是机密：以 `0600` 存储，仅运营者可读。

## 安全模型

| 属性 | 机制 |
|------|------|
| 加密 | ChaCha20-Poly1305 AEAD |
| 密钥交换 | X25519 ECDH |
| 会话认证 | 每客户端 PSK（可选设备绑定） |
| 前向保密 | 飞行中 X25519 密钥棘轮 |
| 重放保护 | 每会话 256 条目滑动窗口 |
| 会话匿名性 | 8 字节 BLAKE3 派生共振标签；明文中无会话 ID |
| 流量拟态 | `MaskProfile` FSM：头部注入、IAT 整形 |
| 掩码完整性 | 神经共振 MSE 阈值（0.35）；自动轮换 |
| NAT 穿透 | 服务器端 nftables/iptables，客户端 `SO_REUSEPORT` |

详细对手模型和威胁分析：[THREAT_MODEL.md](THREAT_MODEL.md)。

---

## 项目结构

```
aivpn/
├── crates/aivpn-common/src/
│   ├── crypto.rs
│   ├── mask.rs
│   ├── protocol.rs
│   └── fec.rs
├── crates/aivpn-client/src/
│   ├── client.rs
│   ├── tunnel.rs
│   ├── kill_switch.rs
│   └── mimicry.rs
├── crates/aivpn-server/src/
│   ├── gateway.rs
│   ├── neural.rs
│   ├── nat.rs
│   ├── client_db.rs
│   └── pool_sync.rs
├── platforms/android/
├── platforms/ios/
├── crates/aivpn-windows/
├── platforms/macos/
├── assets/masks/          # 捆绑的流量拟态配置文件（JSON）
├── deploy/ci/             # 由 Makefile 调用的 CI 门禁
├── deploy/docker/
├── Dockerfile
├── docker-compose.yml
└── THREAT_MODEL.md
```

---

## 许可证

MIT — 见 [LICENSE](LICENSE)。
