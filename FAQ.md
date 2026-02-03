# FAQ

**Q:** The script has been updated since I installed OpenVPN. How do I update?

**A:** You can't. Managing updates and new features from the script would require way too much work. Your only solution is to uninstall OpenVPN and reinstall with the updated script.

You can, of course, it's even recommended, update the `openvpn` package with your package manager.

---

**Q:** How do I renew certificates before they expire?

**A:** Use the CLI commands to renew certificates:

```bash
# Renew a client certificate
./openvpn-install.sh client renew alice

# Renew with custom validity period (365 days)
./openvpn-install.sh client renew alice --cert-days 365

# Renew the server certificate
./openvpn-install.sh server renew
```

For client renewals, a new `.ovpn` file will be generated that you need to distribute to the client. For server renewals, the OpenVPN service will need to be restarted (the script will prompt you).

---

**Q:** 如何备份和恢复 OpenVPN 配置？

**A:** 在管理菜单中：
- **备份配置（压缩包）**（选项 13）：将 `/etc/openvpn` 打包为 `openvpn-backup-YYYYMMDD-HHMMSS.tar.gz`，可指定保存路径。卸载前也会提示是否先备份。
- **导入配置**（选项 14）：从本脚本生成的 `.tar.gz` 或 `.tgz`、`.tar` 备份恢复，会先停止服务、覆盖 `/etc/openvpn` 后解压并启动服务。建议导入后执行一次「修复 OpenVPN systemd 服务」以确认 systemd 单元正确。

---

**Q:** How do I check for DNS leaks?

**A:** Go to [browserleaks.com](https://browserleaks.com/dns) or [ipleak.net](https://ipleak.net/) (both perform IPv4 and IPv6 check) with your browser. Your IP should not show up (test without and without the VPN). The DNS servers should be the ones you selected during the setup, not your IP address nor your ISP's DNS servers' addresses.

---

**Q:** How do I fix DNS leaks?

**A:** On Windows 10 DNS leaks are blocked by default with the `block-outside-dns` option.
On Linux you need to add these lines to your `.ovpn` file based on your Distribution.

Debian 9, 10 and Ubuntu 16.04, 18.04

```
script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
```

CentOS 6, 7

```
script-security 2
up /usr/share/doc/openvpn-2.4.8/contrib/pull-resolv-conf/client.up
down /usr/share/doc/openvpn-2.4.8/contrib/pull-resolv-conf/client.down
```

CentOS 8, Fedora 30, 31

```
script-security 2
up /usr/share/doc/openvpn/contrib/pull-resolv-conf/client.up
down /usr/share/doc/openvpn/contrib/pull-resolv-conf/client.down
```

Arch Linux

```
script-security 2
up /usr/share/openvpn/contrib/pull-resolv-conf/client.up
down /usr/share/openvpn/contrib/pull-resolv-conf/client.down
```

---

**Q:** IPv6 is not working on my Hetzner VM

**A:** This an issue on their side. See <https://angristan.xyz/fix-ipv6-hetzner-cloud/>

---

**Q:** 如何启用数据通道卸载 (DCO)？安装时提示「DCO 不可用」。

**A:** DCO（Data Channel Offload）可将加解密卸载到内核，提升吞吐与延迟。需同时满足：

1. **OpenVPN 2.6 及以上**  
   使用脚本配置的官方源一般已是 2.6+；若为 2.5 及以下，请升级 OpenVPN。

2. **内核支持**（二选一）  
   - **方式一：内核 6.16 及以上**  
     DCO 已并入主线内核，升级到 6.16+ 即可（需发行版提供该内核，如主线/backport）。  
   - **方式二：安装 ovpn-dco 内核模块（推荐，适用于当前常见内核）**  
     - **Debian / Ubuntu**：DKMS 需先安装**当前内核的头文件**才能编译模块，再安装 DCO 并加载：
       ```bash
       sudo apt update
       sudo apt install -y linux-headers-$(uname -r)   # 或 linux-headers-amd64
       sudo apt install -y openvpn-dco-dkms
       sudo modprobe ovpn-dco
       ```
       若出现 `Module ovpn-dco not found in directory /lib/modules/...`，说明未装对应内核的 headers，按上顺序先装 `linux-headers-$(uname -r)` 再装 `openvpn-dco-dkms` 即可。重启 OpenVPN 服务后，脚本会检测到 DCO 可用。  
     - **Fedora / RHEL 等**：若仓库提供 `openvpn-dco` 或 `kmod-ovpn-dco`，安装后执行 `modprobe ovpn-dco`。

3. **协议与加密**  
   DCO 仅在 **UDP**（或 udp6）且 **AEAD 加密**（如 AES-128-GCM、AES-256-GCM、CHACHA20-POLY1305）时启用。若当前为 TCP 或 CBC 加密，脚本会提示「DCO 可用但未启用」。

安装好模块后无需改配置，只要协议为 UDP、加密为 GCM/ChaCha20，OpenVPN 2.6+ 会自动使用 DCO。详见 [OpenVPN DCO 文档](https://openvpn.net/as-docs/openvpn-dco.html)。

---

**Q:** I'm running OpenVPN in a VM. Will I get full performance?

**A:** Virtualization adds some overhead (CPU, network I/O), so you may not reach the same throughput as on bare metal. To get the best performance in a VM:

- Use **virtio** (or equivalent paravirtual) network and disk drivers.
- If the hypervisor supports it, use **host** or **passthrough** CPU mode so the guest can use the host’s CPU features (e.g. AES-NI for encryption).
- Allocate enough vCPUs and RAM; single-threaded OpenVPN benefits from a fast CPU.
- During install, choose **性能优化 → 高吞吐** (or “Performance optimization → High throughput”) to use larger socket buffers (sndbuf/rcvbuf 393216), which can help on high-bandwidth links.

For most use cases (a few dozen Mbps to a few hundred Mbps), a well-configured VM is sufficient. For maximum throughput (e.g. multi-Gbps), bare metal or a dedicated VPN appliance is better.

---

**Q:** DNS is not working on my Linux client

**A:** See "How do I fix DNS leaks?" question

---

**Q:** What sysctl and firewall changes are made by the script?

**A:** If firewalld is active, the script uses `firewall-cmd --permanent` to configure port, masquerade, and rich rules. Otherwise, iptables rules are saved at `/etc/iptables/add-openvpn-rules.sh` and `/etc/iptables/rm-openvpn-rules.sh`, managed by `/etc/systemd/system/iptables-openvpn.service`.

Sysctl options are at `/etc/sysctl.d/99-openvpn.conf`

---

**Q:** How can I access other clients connected to the same OpenVPN server?

**A:** Add `client-to-client` to your `server.conf`

---

**Q:** My router can't connect

**A:**

- `Options error: No closing quotation (") in config.ovpn:46` :

  type `yes` when asked to customize encryption settings and choose `tls-auth`

---

**Q:** How can I access computers on the OpenVPN server's LAN?

**A:** Two steps are required:

1. **Push a route to clients** - Add the LAN subnet to `/etc/openvpn/server/server.conf`:

   ```
   push "route 192.168.1.0 255.255.255.0"
   ```

   Replace `192.168.1.0/24` with your actual LAN subnet.

2. **Enable routing back to VPN clients** - Choose one of these options:
   - **Option A: Add a static route on your router** (recommended when you can configure your router)

     On your LAN router, add a route for the VPN subnet (default `10.8.0.0/24`) pointing to the OpenVPN server's LAN IP. This allows LAN devices to reply to VPN clients without NAT.

   - **Option B: Masquerade VPN traffic to LAN**

     If you can't modify your router, add a masquerade rule so VPN traffic appears to come from the server:

     ```bash
     # iptables
     iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -d 192.168.1.0/24 -j MASQUERADE

     # or nftables
     nft add rule ip nat postrouting ip saddr 10.8.0.0/24 ip daddr 192.168.1.0/24 masquerade
     ```

     Make this persistent by adding it to your firewall scripts.

Restart OpenVPN after making changes: `systemctl restart openvpn-server@server`

---

**Q:** How can I add multiple users in one go?

**A:** Here is a sample Bash script to achieve this:

```bash
#!/bin/bash
userlist=(user1 user2 user3)

for user in "${userlist[@]}"; do
  ./openvpn-install.sh client add "$user"
done
```

From a list in a text file:

```bash
#!/bin/bash
while read -r user; do
  ./openvpn-install.sh client add "$user"
done < users.txt
```

To add password-protected clients:

```bash
#!/bin/bash
./openvpn-install.sh client add alice --password "secretpass123"
```

---

**Q:** How do I change the default `.ovpn` file created for future clients?

**A:** You can edit the template out of which `.ovpn` files are created by editing `/etc/openvpn/server/client-template.txt`

---

**Q:** For my clients - I want to set my internal network to pass through the VPN and the rest to go through my internet?

**A:** You would need to edit the `.ovpn` file. You can edit the template out of which those files are created by editing `/etc/openvpn/server/client-template.txt` file and adding

```sh
route-nopull
route 10.0.0.0 255.0.0.0
```

So for example - here it would route all traffic of `10.0.0.0/8` to the VPN. And the rest through the internet.

---

**Q:** How do I configure split-tunnel mode on the server (route only specific networks through VPN for all clients)?

**A:** By default, the script configures full-tunnel mode where all client traffic goes through the VPN. To configure split-tunnel (only specific networks routed through VPN), edit `/etc/openvpn/server/server.conf`:

1. Remove or comment out the redirect-gateway line:

   ```
   #push "redirect-gateway def1 bypass-dhcp"
   ```

2. Add routes for the networks you want to tunnel:

   ```
   push "route 10.0.0.0 255.0.0.0"
   push "route 192.168.1.0 255.255.255.0"
   ```

3. Optionally remove DNS push directives if you don't want VPN DNS:

   ```
   #push "dhcp-option DNS 1.1.1.1"
   ```

4. For IPv6, remove or comment out:

   ```
   #push "route-ipv6 2000::/3"
   #push "redirect-gateway ipv6"
   ```

   Or add specific IPv6 routes:

   ```
   push "route-ipv6 2001:db8::/32"
   ```

5. Restart OpenVPN: `systemctl restart openvpn-server@server`

---

**Q:** I have enabled IPv6 and my VPN client gets an IPv6 address. Why do I reach the sites or other dual-stacked destinations via IPv4 only?

**A:** This is because inside the tunnel you don't get a publicly routable IPv6 address, instead you get an ULA (Unlique Local Lan) address. Operating systems don't prefer this all the time. You can fix this in your operating system policies as it's unrelated to the VPN itself:

Windows (commands needs to run cmd.exe as Administrator):

```
netsh interface ipv6 add prefixpolicy fd00::/8 3 1
```

Linux:

edit `/etc/gai.conf` and uncomment the following line and also change its value to `1`:

```
label fc00::/7      1
```

This will not work properly unless you add you your VPN server `server.conf` one or two lines to push at least 1 (one) IPv6 DNS server. Most providers have IPv6 servers as well, add two more lines of `push "dhcp-option DNS <IPv6>"`

---

**Q:** How can I run OpenVPN on port 443 alongside a web server?

**A:** Use OpenVPN's `port-share` feature to multiplex both services on the same port. When OpenVPN receives non-VPN traffic, it forwards it to your web server.

1. During installation, select **TCP** and port **443**
2. Configure your web server to listen on a different port (e.g., 8443)
3. Add to `/etc/openvpn/server/server.conf`:

   ```
   port-share 127.0.0.1 8443
   ```

4. Restart OpenVPN: `systemctl restart openvpn-server@server`

This is useful when your network only allows outbound connections on port 443. Note that TCP has worse performance than UDP for VPN traffic due to head-of-line blocking, so only use this when necessary.
