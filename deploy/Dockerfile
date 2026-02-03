# OpenVPN 部署镜像：在容器内运行 openvpn-install 脚本，使用 host 网络
# 用户通过进入容器终端执行安装与管理操作
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

# 安装脚本依赖与 systemd（脚本通过 systemd 启动 OpenVPN 服务）
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iptables curl procps systemd systemd-sysv \
    && rm -rf /var/lib/apt/lists/*

# 脚本会在安装 OpenVPN 时安装 easy-rsa、openvpn、socat 等
RUN mkdir -p /dev/net

# 安装脚本置于 /opt，便于在容器内执行
COPY openvpn-install.sh /opt/openvpn-install.sh
RUN chmod +x /opt/openvpn-install.sh

# 创建软链便于直接执行（可选）
RUN ln -sf /opt/openvpn-install.sh /usr/local/bin/openvpn-install.sh

WORKDIR /opt

# 使用 systemd 作为 PID 1，以便脚本中的 systemctl 生效
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
