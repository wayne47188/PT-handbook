# 第 19 章 - UDP 掃描深度解析

## 標籤

- #cpts
- #chapter
- #udp
- #nmap

## 學習目標

- 理解 UDP 無連線特性如何影響掃描與判讀。
- 掌握 `-sU` 的基本探測流程與常見狀態意義。
- 能解釋 `open`、`closed`、`filtered`、`open|filtered` 的由來。
- 理解 ICMP Unreachable 與 Rate Limiting 對結果的影響。
- 知道何時用 `-sU -sV`、協定特定 probe 與人工驗證補足結果。

---

## 理論基礎

```text
為什麼 UDP 掃描比 TCP 難判讀？

TCP（有連線）：
  SYN → SYN/ACK（open）/ RST（closed）/ 無回應（filtered）
  有明確的三向交握語意，狀態清晰

UDP（無連線）：
  送出 UDP Probe → 不保證對方一定回應
  「沒回應」有三種可能意義：
    1. 服務存在但不回應目前的 probe payload
    2. 封包被過濾（防火牆 DROP）
    3. 主機根本沒這個服務（但沒回 ICMP）
  → 這就是 open|filtered 的來源

Nmap UDP 狀態判斷邏輯：
  收到應用層回應         → open（可信度較高）
  收到 ICMP Type3 Code3  → closed（Port Unreachable）
  收到其他 ICMP         → filtered
  完全無回應            → open|filtered（無法區分）

常見高價值 UDP 埠：
  53  → DNS（可做 zone transfer / 遞迴查詢驗證）
  67  → DHCP
  69  → TFTP（常配置不當）
  123 → NTP（放大攻擊 / 設定資訊洩漏）
  161 → SNMP（community string / MIB 遍歷）
  500 → IKE/ISAKMP（VPN）
  5353→ mDNS（內網服務廣播）
```

---

## 基本 UDP 掃描

```bash
# 基本 UDP 掃描（預設 top 1000 埠）
sudo nmap -sU 192.168.1.1
# -sU → UDP Scan，需要 root/sudo 才能送原始 UDP 封包
# 速度遠慢於 TCP Scan；系統 ICMP 回應有速率限制（預設 1/s）
# 建議：不要對大量主機做全 UDP 掃描，先鎖定高價值埠

# 只掃常見高價值 UDP 埠
sudo nmap -sU -p 53,67,69,123,161,500,5353 192.168.1.1
# -p → 指定要掃的 UDP 埠清單
# 對已知可能有 DNS/SNMP/NTP/VPN 的目標非常有效

# 加 --reason 確認每個埠的判定依據
sudo nmap -sU -p 53,123,161 --reason 192.168.1.1
# --reason → 顯示 Nmap 做出狀態判斷的原因
# 範例輸出：
#   53/udp  open          udp-response ttl 64   ← 收到 DNS 應用回應
#   161/udp open|filtered no-response           ← 沒回應，無法確認
#   9999/udp closed       port-unreach ttl 64   ← ICMP Port Unreachable

# 全部 UDP 埠掃描（謹慎使用）
sudo nmap -sU -p- 192.168.1.1
# 65535 個 UDP 埠，速度極慢（可能數小時）
# 只對特定已知目標才值得

# 搭配版本探測（提升識別準確度）
sudo nmap -sU -sV -p 53,123,161 192.168.1.1
# -sV → 送出協定特定 probe，嘗試識別應用層服務版本
# 結合 -sU 時：對 open 或 open|filtered 的埠嘗試版本識別
# 更慢，但能把 open|filtered 中部分確認為 open
```

---

## 封包層分析

```bash
# 封包追蹤（排查 ICMP 與無回應問題）
sudo nmap -sU -p 161 --packet-trace 192.168.1.1
# --packet-trace → 顯示每個送出與收到的封包
# 可以看清楚：送了什麼 UDP probe、收到什麼（ICMP 或應用回應或無）
# 用途：確認是真的無回應，還是 ICMP 被 rate limiting 吃掉

# 完整排錯組合
sudo nmap -sU -sV -p 161 --reason --packet-trace 192.168.1.1
```

---

## 協定特定驗證

```bash
# DNS（UDP 53）驗證
dig @192.168.1.1 example.com A
# 直接用 dig 對目標 IP 做 DNS 查詢
# 如果有回應 → 確認 DNS 服務存在（比 Nmap 狀態更可信）

# SNMP（UDP 161）驗證
snmpwalk -v2c -c public 192.168.1.1
# -v2c → 使用 SNMPv2c 協定
# -c public → 嘗試 community string "public"（預設常見值）
# 有回應 → 確認 SNMP 開放且 community string 正確

# NTP（UDP 123）驗證
ntpdate -q 192.168.1.1
# -q → Query only，不同步時間，只查詢
# 有回應 → 確認 NTP 服務存在

# TFTP（UDP 69）驗證
tftp 192.168.1.1
# 連上後嘗試 get 一個常見檔名
# 有回應 → 確認 TFTP 服務存在（且通常沒有認證）
```

---

## 狀態判讀指南

```text
UDP 掃描狀態解讀（必須理解，不能機械化使用）：

open：
  收到明確應用層回應
  通常是 DNS query 回答、SNMP response 等
  可信度最高；仍需協定驗證確認功能

closed：
  收到 ICMP Type 3 Code 3（Port Unreachable）
  表示主機存在且可達，但 UDP 埠沒服務
  可信度高；但也可能是 ICMP 由中間設備代為回送

filtered：
  收到其他 ICMP unreachable（Code 1/2/9/10/13）
  防火牆 / 過濾設備阻止封包到達目標
  後端服務可能存在也可能不存在

open|filtered：
  完全無回應
  最常見的 UDP 狀態（尤其在複雜網路環境）
  意義模糊：需要協定特定驗證才能進一步確認
  絕對不能直接報成 open！

Rate Limiting 影響：
  Linux 系統預設 ICMP Port Unreachable 速率 1/秒
  大量 UDP 掃描時，大多數 closed 的埠可能顯示 open|filtered
  → 導致大量假 open|filtered
  對策：-p 只掃高價值埠、等待時間加長或協定驗證
```

---

## 決策流程

```
目標主機
    ↓
是否懷疑特定 UDP 服務？
  是 → nmap -sU -p <特定埠> --reason
  否 → nmap -sU --top-ports 200 --reason（掃常見高價值埠）
    ↓
結果判讀
  open → 協定工具驗證（dig/snmpwalk/ntpdate）
  closed → 跳過（確認無服務）
  open|filtered → 加 -sV 嘗試版本識別 → 仍不確定 → 協定工具驗證
  filtered → 記錄「可能受防火牆影響」，不直接結論
    ↓
驗證確認 → 報告中清楚標示觀測依據
```

---

## 速查表

```bash
# 基本 UDP 掃描
sudo nmap -sU 192.168.1.1                             # 預設掃描
sudo nmap -sU -p 53,123,161,500 192.168.1.1           # 高價值埠
sudo nmap -sU -p 53,123,161 --reason 192.168.1.1      # 附判定原因
sudo nmap -sU -sV -p 53,123,161 192.168.1.1           # 加版本識別
sudo nmap -sU -p 161 --packet-trace 192.168.1.1       # 封包追蹤

# 協定驗證
dig @<IP> example.com A                # DNS 驗證
snmpwalk -v2c -c public <IP>           # SNMP 驗證
ntpdate -q <IP>                        # NTP 驗證
```

---

## 常見錯誤與排查

- 把 `open|filtered` 直接報成 open → 必須用協定工具二次驗證後才能確認。
- 對大量主機盲目全 UDP 掃描 → 速度極慢且 rate limiting 造成大量假 open|filtered，先鎖定高價值埠。
- 忽略 ICMP rate limiting 的影響 → 大量 closed 埠會因此顯示 open|filtered。
- 不做協定特定驗證就下服務存在結論 → Nmap UDP 狀態只是起點，不是終點。

---

## 關聯筆記

- [[18-Nmap掃描生命週期與封包分析|第 18 章 - Nmap 掃描生命週期與封包分析]]
- [[20-Nmap服務與版本偵測|第 20 章 - Nmap 服務與版本偵測]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
