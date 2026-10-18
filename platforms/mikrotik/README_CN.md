# aivpn-mikrotik

在 MikroTik RouterOS 7 容器中运行 AIVPN 客户端。只需一个连接密钥即可完成配置，无需 VPN 专业知识。

## 支持的设备

| 架构 | RouterOS 设备 |
|---|---|
| **arm64** (aarch64) | RB5009、CCR2004、hAP ax²、RBD53iG 及大多数现代 RouterBOARD |
| **armv7** | hAP ac²、RB3011、RB2011、RB951、RBD52G |
| **amd64** | CHR（云托管路由器）、x86 RouterOS |

需要 RouterOS **7.6+** 并支持容器功能。

## 前提条件

在 MikroTik 设备上启用容器功能（仅需一次）：

```routeros
/system/device-mode/update container=yes
```

执行此命令后重启设备。

## 快速安装

### 第 1 步 — 创建 veth 接口

```routeros
/interface/veth/add name=veth-aivpn address=172.31.0.2/30 gateway=172.31.0.1
/ip/address/add address=172.31.0.1/30 interface=veth-aivpn
```

### 第 2 步 — 配置环境变量

```routeros
/container/envs/add list=aivpn-env name=AIVPN_KEY value="aivpn://您的连接密钥"
```

可选：禁用全隧道模式（仅路由 VPN 子网流量）：
```routeros
/container/envs/add list=aivpn-env name=AIVPN_FULL_TUNNEL value="false"
```

### 第 3 步 — 挂载 /dev/net/tun

```routeros
/container/mounts/add name=aivpn-tun src=/dev/net/tun dst=/dev/net/tun type=bind
```

### 第 4 步 — 创建并启动容器

按照下方说明构建镜像，使用 `docker save` 导出，然后通过 WinBox 将 `aivpn-mikrotik.tar` 上传到 `disk1/`。从文件导入不需要 Docker Hub 上已发布的镜像。[RouterOS 镜像导入说明](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container#Container-OptionB:ImportimagefromPC)。

```routeros
/container/add \
    file=disk1/aivpn-mikrotik.tar \
    interface=veth-aivpn \
    start-on-boot=yes \
    envlist=aivpn-env \
    mounts=aivpn-tun \
    dns=8.8.8.8 \
    logging=yes \
    cap=net-admin \
    comment="AIVPN client"

/container/start [find comment="AIVPN client"]
```

### 第 5 步 — 配置路由

将所有流量路由到 VPN 容器：

```routeros
/ip/route/add dst-address=0.0.0.0/0 gateway=172.31.0.2 routing-table=main distance=5 comment="AIVPN 默认路由"
```

或使用策略路由（仅针对特定主机）：

```routeros
/routing/rule/add src-address=192.168.1.50/32 action=lookup-only-in-table table=aivpn-rt
/ip/route/add dst-address=0.0.0.0/0 gateway=172.31.0.2 routing-table=aivpn-rt
```

## 环境变量

| 变量 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `AIVPN_KEY` | **是** | — | 来自 `aivpn-server --show-client` 的连接密钥 |
| `AIVPN_FULL_TUNNEL` | 否 | `true` | 是否全流量 VPN（`true`/`false`） |

## 检查状态

```routeros
/container/print detail where comment="AIVPN client"
/log/print where topics~"container"
```

## 获取连接密钥

在 AIVPN 服务器上执行：

```bash
aivpn-server --show-client "my-mikrotik" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip 您的服务器IP
```

## 从源码构建

```bash
# 单架构（arm64）
docker build \
    --platform linux/arm64 \
    --build-arg MUSL_IMAGE_TAG=aarch64-musl \
    --build-arg TARGET_TRIPLE=aarch64-unknown-linux-musl \
    -t aivpn-mikrotik:arm64 \
    -f platforms/mikrotik/Dockerfile .

# 导出镜像以供路由器导入
docker save --output aivpn-mikrotik.tar aivpn-mikrotik:arm64

# 多架构推送到 Docker Hub
./platforms/mikrotik/build-mikrotik.sh infosave2007/aivpn-mikrotik:latest
```

## 故障排除

**容器报错 "TUN not found"**  
RouterOS 需要为 TUN 设备显式设置 bind 挂载：
```routeros
/container/mounts/add name=aivpn-tun src=/dev/net/tun dst=/dev/net/tun type=bind
```
添加挂载后重新创建容器。

**RouterOS 7.22+ 连接后无法上网**  
RouterOS 7.22 引入了容器内 TUN 网关路由的回归问题。
请降级至 7.21 或等待修复版本，此问题影响所有基于 TUN 的容器。

**流量未通过 VPN 路由**  
检查默认路由或策略路由规则是否指向 172.31.0.2。
查看日志：`/log/print where topics~"container"`。
