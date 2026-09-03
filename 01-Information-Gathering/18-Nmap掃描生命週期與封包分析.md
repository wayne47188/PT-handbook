# 第 18 章 - Nmap 掃描生命週期與封包分析

## 標籤

- #cpts
- #chapter
- #nmap
- #packets

## 學習目標

- 理解 Nmap 掃描從目標解析到結果判讀的基本生命週期。
- 掌握 Host Discovery、SYN Scan、Connect Scan 與常用發現旗標的定位。
- 能用 `--reason`、`--packet-trace` 與封包視角理解結果。
- 理解 Firewall、NAT、SYN Proxy、Load Balancer 對掃描判讀的影響。
- 避免把 Nmap 狀態字樣機械化地解讀成已驗證真相。

---

## 理論基礎

```text
Nmap 掃描生命週期（五個階段）：

1. Target Resolution（目標解析）
   → 把主機名稱解析為 IP（DNS 查詢）
   → 解析失敗 ≠ 主機不存在；可能是 DNS 問題

2. Host Discovery（主機發現）
   → 判斷目標主機是否「看起來在線」
   → 常見探測：ICMP Echo / TCP SYN / TCP ACK / ARP
   → 沒回應 ≠ 主機不存在；防火牆常封鎖 ICMP

3. Port Scan（埠掃描）
   → 對已發現主機掃描埠狀態
   → 結果是觀測，不是事實：open/closed/filtered
   → 中間設備（Firewall/NAT/SYN Proxy）會影響結果

4. Service / Version / Script（服務偵測）
   → -sV 做 banner 抓取與版本推測
   → NSE 腳本可做更深入枚舉
   → 服務推測仍可能受前端代理影響

5. Result Interpretation（結果判讀）
   → 把觀測結果放回掃描生命週期理解
   → 要問：這個狀態基於哪種封包回應？中間有什麼設備？

關鍵原則：
  不同階段的問題不能混在一起
  Host discovery 失敗 ≠ Port scan 無效
  Port 顯示 filtered ≠ 服務不存在
  必要時用 --reason 和 --packet-trace 追溯原因
```

---

## Host Discovery（主機發現）

```bash
# 只做主機發現（不掃埠）
nmap -sn 192.168.1.0/24
# -sn → Ping scan，只做主機發現，不進行埠掃描
# 在本地網路：會發 ARP；跨路由器：用 ICMP+TCP SYN+TCP ACK
# 注意：沒回應不代表主機不存在，防火牆可能封鎖 ICMP

# 跳過主機發現，直接掃埠（已知目標存在）
nmap -Pn 192.168.1.1
# -Pn → 跳過 Host Discovery，假設目標在線
# 適合：已確認 IP 存在，但主機不回 ICMP/其他發現探測
# 代價：每個 IP 都會被當作目標掃描，大範圍時會很慢

# 用 TCP SYN 做主機發現
nmap -PS80,443 192.168.1.0/24
# -PS → 用 TCP SYN 封包做主機發現
# -PS80,443 → 對 80 和 443 送 SYN（有回應 SYN/ACK 或 RST = 在線）
# 比 ICMP 更容易穿透某些防火牆

# 用 TCP ACK 做主機發現
nmap -PA80,443 192.168.1.0/24
# -PA → 用 TCP ACK 封包做主機發現
# 有些防火牆允許 ACK 通過（ACK 看起來像回應已建立連線）
# 如果收到 RST → 主機在線；如果沒回應 → 可能被 stateful firewall 擋

# 用 ICMP Echo 做主機發現
nmap -PE 192.168.1.0/24
# -PE → 用 ICMP Echo Request（傳統 ping）
# 常在企業網路被封鎖；適合對已知允許 ICMP 的環境

# 組合多種探測方式（提高發現率）
nmap -PS22,80,443 -PA80 -PE 192.168.1.0/24
```

---

## Port Scan（埠掃描）

```bash
# SYN Scan（預設，需要 root/sudo）
nmap -sS 192.168.1.1
# -sS → 半開放掃描（Half-Open / Stealth Scan）
# 送 SYN → 收 SYN/ACK 則視為 open（立即送 RST，不完成三向交握）
# 收 RST → closed；無回應 / ICMP Unreachable → filtered
# 需要 root 權限；速度快；比 -sT 更難被應用層日誌記錄

# Connect Scan（不需要 root）
nmap -sT 192.168.1.1
# -sT → 完整 TCP 三向交握
# 不需要特殊權限，但速度較慢
# 更接近真實連線，目標端應用層可能記錄連線
# 適合：沒有 root 權限，或需要模擬真實用戶連線的情境

# 指定掃描埠範圍
nmap -sS -p 1-1000 192.168.1.1       # 掃前 1000 個埠
nmap -sS -p 80,443,8080,8443 192.168.1.1  # 指定特定埠
nmap -sS -p- 192.168.1.1             # 全部 65535 個埠（慢）
nmap -sS --top-ports 100 192.168.1.1 # 最常見的 100 個埠
```

---

## 封包分析與結果驗證

```bash
# 顯示每個埠狀態的判定原因
nmap -sS -p 80,443 --reason 192.168.1.1
# --reason → 顯示 Nmap 給出該狀態的封包層級原因
# 範例輸出：
#   80/tcp  open   syn-ack ttl 64   ← 收到 SYN/ACK 回應
#   443/tcp closed rst ttl 64       ← 收到 RST 回應
#   22/tcp  filtered no-response    ← 沒收到任何回應
# 高價值：能解釋「為何這個埠是 filtered」

# 顯示完整封包追蹤（最詳細，用於排錯）
nmap -sS -p 80 --packet-trace 192.168.1.1
# --packet-trace → 顯示每個送出與收到的封包
# 輸出量大，但可以看清楚：送了什麼、收到什麼、Nmap 如何判讀
# 適合：懷疑中間設備干擾、結果不穩、需要向報告附上技術證據

# 同時使用 --reason 和 --packet-trace（最完整排錯）
nmap -sS -p 80,443 --reason --packet-trace 192.168.1.1
```

---

## 埠狀態解讀

```text
Nmap 埠狀態（不是業務語意，是封包觀測結果）：

open     → 收到 SYN/ACK（SYN Scan）或連線成功（Connect Scan）
           表示有服務在監聽；但可能是 SYN Proxy 或 Load Balancer

closed   → 收到 RST
           表示埠可達但沒有服務；RST 可由主機或中間設備送出

filtered → 沒有回應 或 收到 ICMP Unreachable
           通常是防火牆 DROP 規則；無法判斷後面是否有服務
           注意：有時是速率限制或封包遺失造成

open|filtered → 沒有回應，且掃描方式無法區分 open 和 filtered
               常見於 UDP Scan（-sU）

關鍵原則：
  filtered ≠ 服務不存在（可能被防火牆擋住）
  open ≠ 服務是你看到的那個（可能是代理層）
  要用 --reason 確認判定依據
```

---

## 實戰排查流程

```bash
# 情境：某主機在 Naabu 中顯示 443 開放，但 Nmap 結果不穩

# 步驟 1：確認目標解析正確
nmap -sL 192.168.1.1
# -sL → List scan，只做解析不探測，確認 Nmap 認識這個目標

# 步驟 2：獨立做主機發現，觀察在線訊號
nmap -sn -PS443 192.168.1.1
# 看主機是否對 TCP SYN 443 有反應

# 步驟 3：直接對已知埠做 SYN Scan
nmap -Pn -sS -p 443 192.168.1.1
# -Pn 跳過主機發現（已知 IP 存在）

# 步驟 4：加 --reason 確認判定依據
nmap -Pn -sS -p 443 --reason 192.168.1.1

# 步驟 5：如果仍有疑義，用 --packet-trace 追查
nmap -Pn -sS -p 443 --packet-trace 192.168.1.1
# 看封包層：送了什麼、收到什麼、Nmap 如何歸類
```

---

## 中間設備對結果的影響

```text
防火牆（Stateless / Stateful）：
  Stateless DROP → port 顯示 filtered（無回應）
  Stateless REJECT → port 顯示 closed（收到 ICMP Unreachable）
  Stateful DROP → TCP SYN 被丟棄，port 顯示 filtered

SYN Proxy / Load Balancer：
  SYN Proxy 代理回應 SYN/ACK → port 顯示 open
  但後端服務可能不存在或不同
  現象：port open，但 -sV 連不上服務或 banner 奇怪

NAT：
  多台主機共用同一外部 IP
  掃描結果是 NAT 設備的回應，不一定代表特定後端主機

CDN：
  Web 埠（80/443）通常顯示 open（CDN 自己回應）
  Server Header 可能是 CDN（Cloudflare/Akamai）
  真正後端在 CDN 後面，無法直接 Nmap

應對原則：
  對 filtered 結果不要直接放棄：試 -Pn / 換探測類型 / 換時間
  對 open 結果不要直接信任：用 -sV 確認服務 / 看 --reason
  使用 --packet-trace 記錄真實封包交互當報告證據
```

---

## 決策流程

```
目標 IP / 主機名稱
    ↓
Host Discovery 階段
  -sn 預設組合 → 有回應：直接進入埠掃描
  無回應 → 換探測方式 (-PS/-PA/-PE) 或用 -Pn 強制跳過
    ↓
Port Scan 階段
  -sS（有 root）/ -sT（無 root）
  埠範圍：先 top-ports 100 → 有需要再擴大 / -p-
    ↓
結果判讀
  open → 加 --reason 確認；再用 -sV 做服務版本
  filtered → 換方法再試；記錄為「可能受防火牆影響」
  closed → 通常可跳過（除非需確認服務不存在）
    ↓
不確定 → --packet-trace 追查封包層細節
```

---

## 速查表

```bash
# Host Discovery
nmap -sn 192.168.1.0/24              # 只做主機發現
nmap -Pn 192.168.1.1                 # 跳過主機發現直接掃
nmap -PS80,443 192.168.1.0/24        # TCP SYN 發現
nmap -PA80,443 192.168.1.0/24        # TCP ACK 發現
nmap -PE 192.168.1.0/24              # ICMP Echo 發現

# Port Scan
nmap -sS 192.168.1.1                 # SYN Scan（需 root）
nmap -sT 192.168.1.1                 # Connect Scan（不需 root）
nmap -sS -p 80,443 192.168.1.1       # 指定埠
nmap -sS --top-ports 100 192.168.1.1 # top 100

# 封包分析
nmap -sS -p 80,443 --reason 192.168.1.1              # 判定原因
nmap -sS -p 80 --packet-trace 192.168.1.1            # 封包追蹤
nmap -Pn -sS -p 443 --reason --packet-trace 192.168.1.1  # 完整排錯
```

---

## 常見錯誤與排查

- 把 `-sn` 沒回應解讀為主機不存在 → ICMP 常被封鎖；改用 `-PS/-PA` 或 `-Pn`。
- 混淆 Host Discovery 失敗與 Port Scan 無結果 → 兩個問題要分別排查。
- 忽略中間設備（Firewall/SYN Proxy/CDN）造成的假陽性或假陰性。
- 不使用 `--reason` 就對結果過度自信 → 加 `--reason` 是基本動作。
- 把 `filtered` 直接當沒有服務 → 應記錄為「無法判斷」並附 --reason 說明。

---

## 關聯筆記

- [[17-Naabu與Nmap掃描分工|第 17 章 - Naabu 與 Nmap 掃描分工]]
- [[19-UDP掃描深度解析|第 19 章 - UDP 掃描深度解析]]
- [[20-Nmap服務與版本偵測|第 20 章 - Nmap 服務與版本偵測]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
