# 第 21 章 - Nmap 作業系統偵測

## 標籤

- #cpts
- #chapter
- #nmap
- #os-detection

## 學習目標

- 理解 TCP/IP stack fingerprinting 的基本概念。
- 掌握 `-O`、`--osscan-guess`、`--osscan-limit` 的用途與限制。
- 理解 TTL、Window Size、TCP Options、ICMP 行為對指紋的影響。
- 知道 NAT、Firewall、虛擬化與中間設備如何干擾判讀。
- 能把 OS detection 結果與 banner、SMB、SNMP 等其他線索交叉驗證。

---

## 理論基礎

```text
OS Detection 的工作原理：TCP/IP Stack Fingerprinting

Nmap 不是讀目標自報的作業系統，而是：
  1. 送出一系列精心設計的探測封包（ISN 取樣、Flag 異常封包等）
  2. 觀察目標 TCP/IP 協定棧的回應特徵
  3. 與 nmap-os-db 資料庫比對，輸出最接近的 OS 族群

被觀測的特徵包括：
  TTL（Time To Live）初始值
    Windows 預設 TTL 128；Linux 預設 64；網路設備通常 255
  TCP Window Size（初始視窗大小）
  TCP Options 組合（SACK/Timestamp/NOP 等）
  IP ID 序列行為
  ICMP 對異常封包的回應方式

限制：
  NAT → 改寫 IP 層，可能看到 NAT 設備的 stack
  Firewall / SYN Proxy → 遮蔽或模擬 TCP 行為
  Load Balancer → 前端有自己的 TCP stack
  虛擬化 → 虛擬網卡可能模仿特定 TTL / Window Size

結論：OS detection 是指紋推測，不是已確認事實
```

---

## 基本 OS 偵測

```bash
# 基本 OS 偵測
sudo nmap -O 192.168.1.1
# -O → OS detection，需要 root/sudo
# 需要至少一個 open 埠 + 一個 closed 埠，否則無法完整指紋
# 輸出範例：
#   OS details: Linux 4.15 - 5.6
#   Network Distance: 1 hop

# 加 -sV 同時做服務版本（一起蒐集更多資訊）
sudo nmap -sV -O -p 22,80,443 192.168.1.1
# 兩者可同時跑，但 OS detection 需要封包行為觀測，不只依賴 banner

# 積極猜測模式（結果更不確定但更完整）
sudo nmap -O --osscan-guess 192.168.1.1
# --osscan-guess → 若找不到精確符合，強制給出最接近的猜測
# 注意：猜測可信度更低，應標記為「需交叉驗證」

# 限制只在適合條件下做 OS 偵測（節省時間）
sudo nmap -O --osscan-limit 192.168.1.1
# --osscan-limit → 只對同時有 open 和 closed 埠的主機做 OS detection
# 對沒有 closed 埠的主機跳過（否則結果不可靠）
# 適合掃描大量主機時節省時間

# 搭配 --reason 看判定依據
sudo nmap -O --reason 192.168.1.1
```

---

## 輸出解讀

```text
Nmap OS Detection 輸出範例解讀：

OS CPE: cpe:/o:linux:linux_kernel:4
OS details: Linux 4.15 - 5.6

解讀三層：

1. 觀測層：
   - Nmap 成功取得足夠的封包行為資料
   - 看到的 TTL、Window Size 等與 Linux 族群一致

2. Nmap 推測層：
   - 「Linux 4.15 - 5.6」是資料庫比對結果
   - 不是主機自報，是工具推測的核心版本範圍

3. 你的推論層（需驗證）：
   - 是 Linux 主機 → 後續測試走 Linux 方向
   - 版本範圍 → 不要直接找這個範圍的 CVE，需更多驗證

常見誤判情境：
  中間有 NAT → 看到路由器的 stack 而非目標
  Docker / 容器 → 可能看到容器宿主的 TCP stack
  Windows 開了 NPCAP 或 WSL → 行為混合
  CDN 前端 → 看到 CDN 伺服器的 stack
```

---

## 交叉驗證方法

```bash
# 1. SMB OS 資訊（Windows 主機最有效）
nmap --script smb-os-discovery -p 445 192.168.1.1
# smb-os-discovery → 從 SMB 協定讀 OS 版本（Windows 自報）
# 比 TCP stack 更精確（但只適用 Windows）
# 輸出：OS: Windows Server 2019 Standard / Computer name / Domain

# 2. SNMP 系統資訊（若 161/udp 開放）
snmpwalk -v2c -c public 192.168.1.1 sysDescr
# sysDescr → SNMP 系統描述（常含 OS 版本與硬體資訊）
# 比 TCP 指紋更明確且是系統自報

# 3. SSH Banner（Linux 主機）
nc 192.168.1.1 22
# SSH 歡迎 banner 通常含 OS 類型（Ubuntu/Debian/CentOS 等）
# 範例：SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4

# 4. HTTP Server Header 推斷
curl -I http://192.168.1.1
# Apache/nginx 版本常與特定 OS 版本組合對應
# 範例：Server: Apache/2.4.51 (Ubuntu)

# 5. RDP（Windows 主機 3389/tcp）
nmap --script rdp-enum-encryption -p 3389 192.168.1.1
# 對 RDP 服務探測加密方式，佐證為 Windows 系統
```

---

## 決策流程

```
目標主機（有開放埠）
    ↓
sudo nmap -O --osscan-limit <目標>
    ↓
結果分析
  OS 結果明確（例如 Linux 4.x / Windows Server 201x）
    → 標記為「Nmap 推測」
    → 交叉驗證（SMB/SNMP/SSH Banner）
    → 若一致 → 確認 OS 族群，決定後續測試路線
    → 若不一致 → 可能有中間設備，標記需人工確認
  OS 結果不明確 / 多個候選 / 信心低
    → 加 --osscan-guess 得到最佳猜測
    → 用其他協定線索交叉驗證
  完全無法判定
    → 標記「OS 未確認」；從服務類型推斷平台（445=Windows / 22=Unix-like）
```

---

## 速查表

```bash
# OS 偵測
sudo nmap -O 192.168.1.1                       # 基本 OS detection
sudo nmap -O --osscan-guess 192.168.1.1        # 積極猜測
sudo nmap -O --osscan-limit 192.168.1.1        # 限制條件（節省時間）
sudo nmap -sV -O -p 22,80,443 192.168.1.1      # OS + 服務版本

# 交叉驗證
nmap --script smb-os-discovery -p 445 <IP>     # SMB OS 資訊
snmpwalk -v2c -c public <IP> sysDescr          # SNMP 系統描述
nc <IP> 22                                      # SSH Banner
curl -I http://<IP>                             # HTTP Server Header
```

---

## 常見錯誤與排查

- 把 OS guess 直接寫進報告當確認事實 → 一定要交叉驗證（SMB/Banner/SNMP）。
- 忽略中間設備（NAT/LB/Firewall）干擾 → 結果反映的是最靠近 Nmap 的設備 stack。
- 沒有 closed 埠還強行做 OS detection → 結果不可靠；加 `--osscan-limit` 自動跳過。
- 只靠 OS detection 決定整條測試路線 → 服務類型（445/3389/22/80）才是更可靠的平台線索。

---

## 關聯筆記

- [[20-Nmap服務與版本偵測|第 20 章 - Nmap 服務與版本偵測]]
- [[22-Nmap指令碼引擎NSE|第 22 章 - Nmap 指令碼引擎 NSE]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
