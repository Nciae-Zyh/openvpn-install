# 使用 Docker 部署 OpenVPN（host 网络）

本目录提供基于 **host 网络模式** 的 OpenVPN 部署方式：构建一个镜像，容器内通过 [openvpn-install.sh](../openvpn-install.sh) 安装并运行 OpenVPN，**所有安装与管理操作由用户进入容器终端执行**。

## 前置要求

- 宿主机已安装 Docker 与 Docker Compose
- 宿主机内核支持 TUN/TAP（`/dev/net/tun`）
- 使用 `network_mode: host` 时，容器直接使用宿主机网络（无需端口映射）

## 一、构建镜像

在项目根目录执行（compose 的 build context 为上级目录）：

```bash
cd /path/to/openvpn-install
docker compose -f deploy/docker-compose.yml build
```

可选：指定基础镜像

```bash
BASE_IMAGE=debian:12 docker compose -f deploy/docker-compose.yml build
```

## 二、启动容器

后台启动并保持运行（用于 systemd 与 OpenVPN 服务）：

```bash
docker compose -f deploy/docker-compose.yml up -d
```

确认容器在跑：

```bash
docker ps
# 应看到容器名 openvpn，状态 Up
```

## 三、进入容器终端执行操作

所有安装、添加客户端、查看状态等均在容器内完成：

```bash
docker exec -it openvpn /bin/bash
```

进入后即可执行安装脚本（见下文）。退出终端不影响容器与 OpenVPN 服务运行。

## 四、首次安装 OpenVPN

在容器内执行（任选一种）：

### 方式 A：非交互安装（推荐，适合脚本化）

```bash
/opt/openvpn-install.sh install \
  --endpoint YOUR_PUBLIC_IP_OR_DOMAIN \
  --port 1194 \
  --protocol udp \
  --dns adguard \
  --client myclient
```

将 `YOUR_PUBLIC_IP_OR_DOMAIN` 换成宿主机公网 IP 或域名。更多参数见：

```bash
/opt/openvpn-install.sh install --help
```

### 方式 B：交互安装

```bash
/opt/openvpn-install.sh
# 无参数会进入交互菜单，按提示选择安装或管理
```

安装完成后，脚本会配置并启动 OpenVPN 服务（通过 systemd），并生成首个客户端配置。默认会为首次客户端生成随机密码并在终端显示，请妥善保存。

## 五、常用管理命令（均在容器内执行）

在 `docker exec -it openvpn /bin/bash` 进入后：

```bash
# 添加客户端
/opt/openvpn-install.sh client add 客户端名

# 为客户端设置密码
/opt/openvpn-install.sh client add 客户端名 --password '你的密码'

# 列出客户端
/opt/openvpn-install.sh client list

# 吊销客户端
/opt/openvpn-install.sh client revoke 客户端名

# 查看服务端状态
/opt/openvpn-install.sh server status
```

## 六、获取客户端 .ovpn 文件

生成的 `.ovpn` 默认在容器内 `/root/` 下（如 `/root/myclient.ovpn`）。复制到宿主机示例：

```bash
# 在宿主机执行
docker cp openvpn:/root/myclient.ovpn ./
```

若在添加客户端时指定了 `--output`，则从该路径复制即可。

## 七、数据持久化与重启

- OpenVPN 配置与证书保存在 volume `openvpn-data`，对应容器内 `/etc/openvpn`。
- 重启容器或宿主机后，直接 `docker compose -f deploy/docker-compose.yml up -d` 即可，无需重新安装。
- 若需完全重置，删除 volume 后重新安装：

```bash
docker compose -f deploy/docker-compose.yml down -v
docker compose -f deploy/docker-compose.yml up -d
# 再进入容器执行首次安装
```

## 八、停止与清理

```bash
# 停止并删除容器（保留 volume 中的配置）
docker compose -f deploy/docker-compose.yml down

# 停止并删除容器与 volume（会删除所有配置与证书）
docker compose -f deploy/docker-compose.yml down -v
```

---

**说明**：本部署方式仅提供运行环境与脚本入口，防火墙规则、端口等需在宿主机或容器内根据实际情况自行配置；使用 host 网络时，OpenVPN 监听在宿主机的端口上。
