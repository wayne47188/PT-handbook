# 第 7 章 - dig 深度解析

## 標籤

- #cpts
- #chapter
- #dig
- #dns

## 學習目標

- 熟悉 `dig` 在 DNS 偵察、驗證與排錯中的定位。
- 理解查詢語法、輸出區塊與常見旗標的意義。
- 能使用 `+short`、`+trace`、`+tcp`、`@server`、特定 Record Type 做精準驗證。
- 正確判讀 `SERVFAIL`、`NXDOMAIN`、`REFUSED` 與 Timeout 類問題。
- 把 `dig` 結果轉換為後續枚舉、證據保存與人工驗證流程。

---

## 理論基礎

```text
dig 的定位：
  - 主要的 DNS 人工驗證工具，適合精確排查
  - 完整輸出：包含 status、flags、ANSWER/AUTHORITY/ADDITIONAL 區塊
  - 與 host/nslookup 的關鍵差異：dig 保留完整協定上下文

何時用 +short（管線導向）：
  - 批次資產蒐集、腳本處理、快速確認
  - 輸出 IP 或 CNAME 目標供其他工具使用

何時看完整輸出（人工判讀）：
  - 自動化結果不一致 / 可疑 Wildcard
  - CNAME 鏈追蹤（需看 ANSWER 每一條）
  - 排查 SERVFAIL / REFUSED / Timeout
  - 委派路徑分析（AUTHORITY SECTION）
  - 證據保留（截圖或 tee 存檔需要完整上下文）

Status Code 意義：
  NOERROR  → 查詢成功（但 ANSWER 可能仍為空，代表記錄不存在）
  NXDOMAIN → 名稱不存在（Non-Existent Domain）
  SERVFAIL → 伺服器無法完成查詢（設定錯誤、上游問題、DNSSEC 驗證失敗）
  REFUSED  → 伺服器拒絕查詢（政策限制，常見於限制遞迴查詢的權威 NS）
  NOERROR + 空 ANSWER → 記錄類型在 Zone 中不存在（正常），不等於主機不存在
```

---

## 基本語法與輸出結構

```bash
# 標準完整查詢（預設查 A 記錄）
dig example.com
# 輸出區塊說明：
#   ;; ->>HEADER<<-   → status, opcode, flags
#   ;; QUESTION SECTION  → 你查的問題（確認 query 是否正確）
#   ;; ANSWER SECTION    → 真正的答案與 TTL
#   ;; AUTHORITY SECTION → 這個 Zone 的 NS（委派資訊）
#   ;; ADDITIONAL SECTION → NS 對應的 IP（膠水記錄）
#   ;; Query time / SERVER / WHEN → 查詢來源與時間（用於排錯）

# 只看簡短答案（適合腳本與批次處理）
dig example.com +short
# +short → 只輸出答案行，移除所有標頭與區塊資訊
# 輸出單純 IP 或 CNAME，可直接 pipe 給其他工具

# 組合：指定記錄類型 + short
dig example.com mx +short
# mx → 指定查詢 MX 記錄
# 輸出格式：優先級 主機名稱
```

---

## 指定 Resolver 與比較來源差異

```bash
# 指定公共 DNS 查詢（繞過本地 resolver）
dig @8.8.8.8 example.com +short
# @8.8.8.8 → 指定用 Google Public DNS 作為查詢伺服器
# 用於比對本地 resolver 與公共 resolver 是否一致

dig @1.1.1.1 example.com +short
# @1.1.1.1 → Cloudflare Public DNS
# 不同公共 DNS 快取策略不同，可能回傳不同 TTL 或結果

# 直接查詢目標的權威名稱伺服器（最接近源頭的答案）
dig ns example.com +short
# 先取得 NS 清單（例如：ns1.example.com.）

dig @ns1.example.com example.com +short
# @ns1.example.com → 直接向該權威 NS 查詢
# 這才是「真正的」Zone 資料，不受快取污染
# REFUSED → 這台 NS 不回答遞迴查詢（正常，改用遞迴 resolver）

# 用途：比較 resolver 與權威 NS 回傳結果是否一致
# 不一致 → 可能是快取未更新、Split-horizon、TTL 尚未過期
```

---

## Wildcard 偵測技術

```bash
# 核心方法：用隨機不存在的名稱比對回應

# Step 1：查一個隨機字串
dig @ns1.example.com asdf1234-notreal.example.com +short
# asdf1234-notreal → 幾乎不可能存在的名稱
# 預期：空輸出（NXDOMAIN）

# Step 2：再查一個不同隨機字串
dig @ns1.example.com xyzrandom9999.example.com +short
# 若兩個隨機字串都回傳相同 IP → 幾乎確認有 Wildcard DNS

# Step 3：對比目標名稱
dig @ns1.example.com staging.example.com +short
# 若回傳 IP 與上面隨機字串相同 → staging.example.com 可能是 Wildcard 誤判
# 若回傳不同 IP → 可能是真實獨立主機

# 完整輸出比較（看 TTL 與 AUTHORITY）
dig @ns1.example.com asdf1234-notreal.example.com
dig @ns1.example.com staging.example.com
# 比對 TTL 與 ANSWER 結構
# Wildcard 通常 TTL 相同，ANSWER 只有一條，指向同一 IP
```

---

## 追蹤完整委派路徑

```bash
# 從 Root DNS 逐步追蹤到權威 NS
dig example.com +trace
# +trace → dig 自行模擬遞迴查詢，從 . → TLD → 目標 Zone
# 輸出格式：每一步顯示「哪台伺服器」回傳「哪些記錄」
# 用途：
#   確認委派路徑是否正常
#   發現 Zone 委派異常（NS 不一致、鑰匙遺失）
#   驗證 DNSSEC 鏈是否完整

# 注意：+trace 使用遞迴查詢模擬，不完全等同真實網路路徑
# 若目標 NS 有 rate limiting，+trace 可能部分失敗

# 查詢 SOA 確認 Zone 序號（與委派配合判讀）
dig soa example.com
# SOA 格式：主NS 管理員郵件 序號 刷新間隔 重試 過期 最小 TTL
# 序號變化 → Zone 有更新，可用於偵察更新頻率
```

---

## TCP 強制查詢

```bash
# 強制使用 TCP 而非 UDP 查詢
dig example.com +tcp
# +tcp → 強制 TCP/53（DNS 預設走 UDP/53）
# 使用時機：
#   回應被截斷（Truncated flag 出現）→ 切換 TCP 取得完整回應
#   測試防火牆是否允許 DNS over TCP
#   某些特殊環境（VPN、Proxy）UDP 封包被過濾

# 結合 +tcp 查大型回應（如 DNSKEY、大型 TXT）
dig example.com dnskey +tcp
# dnskey → DNSSEC 公鑰，常超過 UDP 512 bytes 限制
# +tcp → 確保取得完整記錄

# 檢查截斷旗標
dig example.com any
# 看 flags 行是否出現 tc（Truncated）→ 需改用 TCP
```

---

## 反向解析

```bash
# PTR 反向查詢（IP → 主機名稱）
dig -x 203.0.113.10 +short
# -x → 自動建構 .in-addr.arpa 反向查詢
# 等同於：dig 10.113.0.203.in-addr.arpa ptr +short

# IPv6 反向查詢
dig -x 2001:db8::1 +short
# -x → 自動建構 .ip6.arpa 反向查詢

# 反向解析的判讀限制：
#   PTR 記錄由 IP 擁有者（ISP / 雲端供應商）維護
#   回傳 mail.example.com → 命名線索，但不代表就是目標的郵件伺服器
#   回傳 ec2-xx-xx-xx-xx.compute.amazonaws.com → 確認 AWS EC2 代管
#   回傳 static.xxx.isp.com → ISP 客戶 IP，命名線索有限
#   無回應 → PTR 未設定（很常見），不代表主機不存在
```

---

## 狀態碼判讀與排查

```bash
# 查看完整 status（不用 +short）
dig example.com
# ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
#   NOERROR → 查詢成功
#   NXDOMAIN → 名稱不存在
#   SERVFAIL → 伺服器錯誤
#   REFUSED  → 查詢被拒絕

# NXDOMAIN 排查
dig nxdomain-test.example.com
# status: NXDOMAIN → 名稱確實不存在（或 Wildcard 未涵蓋）
# 注意：NOERROR + 空 ANSWER ≠ NXDOMAIN
#   NOERROR + 空 ANSWER → 名稱存在，但該記錄類型不存在

# SERVFAIL 排查
dig @ns1.example.com example.com
# status: SERVFAIL → 可能原因：
#   DNSSEC 驗證失敗（簽名不匹配）
#   NS 設定錯誤（forwarder 問題）
#   上游 resolver 不可達
#   改用其他 resolver 比較：dig @8.8.8.8 example.com

# REFUSED 排查
dig @ns1.example.com otherdomain.com
# status: REFUSED → NS 拒絕回答不在自己 Zone 內的遞迴查詢（正常行為）
# REFUSED 不等於主機不存在，只是查詢被策略拒絕
```

---

## 決策流程

```
需要 DNS 查詢
    ↓
目標是批次處理 / 腳本管線？
  是 → dig example.com RECORD_TYPE +short
        輸出直接 pipe 給 sort / dnsx / httpx
  否 → 需要人工判讀 / 排錯？
        ↓
        先查本地 resolver（不加 @）
          ↓
        結果可疑 / 不一致？
          是 → 加 @公共DNS（@8.8.8.8 / @1.1.1.1）比對
                仍有疑問 → @ns1.example.com 直查權威 NS
          否 → 記錄結果
        ↓
        結果有 CNAME 鏈？
          是 → 看完整輸出（追蹤每條 ANSWER）
               確認最終落點（自有 IP / CDN / SaaS）
        ↓
        懷疑 Wildcard？
          是 → dig @ns asdf1234-notreal.example.com +short
               比對目標名稱回應是否相同
        ↓
        SERVFAIL？
          是 → 換 @8.8.8.8 再查；仍失敗 → 考慮 +tcp
        ↓
        回應截斷（tc flag）？
          是 → dig example.com RECORD_TYPE +tcp
```

---

## 速查表

```bash
# 基本查詢
dig example.com                        # 完整輸出（A 記錄）
dig example.com +short                 # 只看答案（管線用）
dig example.com mx +short              # 指定類型 + 簡短
dig example.com txt +short             # TXT 記錄

# 指定 Resolver
dig @8.8.8.8 example.com +short       # Google DNS
dig @1.1.1.1 example.com +short       # Cloudflare DNS
dig @ns1.example.com example.com      # 直查權威 NS（完整輸出）

# 追蹤與診斷
dig example.com +trace                 # 從 Root 追蹤委派路徑
dig example.com +tcp                   # 強制 TCP（截斷時使用）

# 反向解析
dig -x 203.0.113.10 +short            # IPv4 PTR 查詢

# Wildcard 偵測
dig @ns1.example.com asdf1234-notreal.example.com +short
dig @ns1.example.com target.example.com +short
# 比對回傳 IP 是否相同
```

---

## 常見錯誤與排查

- 只用 `+short` 做所有查詢，遇到問題不知道看哪裡 → 要排查時必須回到完整輸出看 status、flags 與區塊內容。
- 看到 `SERVFAIL` 就認定主機不存在 → SERVFAIL 是伺服器錯誤，不是名稱不存在；改換 resolver 或加 `+tcp` 再確認。
- 不加 `@server` 就假設結果代表權威資料 → 本地 resolver 可能有快取；重要資產要直查權威 NS 確認。
- 把 `NOERROR + 空 ANSWER` 當成 `NXDOMAIN` → 兩者意義不同，前者只是該記錄類型不存在，名稱本身可能有其他記錄。
- 看 PTR 有值就過度信任命名線索 → PTR 由 IP 擁有者維護，可能是 ISP 或雲端供應商的通用命名，不代表目標控制的主機名稱。

---

## 關聯筆記

- [[04-DNS架構與解析流程|第 4 章 - DNS 架構與解析流程]]
- [[06-DNS記錄深度解析|第 6 章 - DNS 記錄深度解析]]
- [[08-host與nslookup|第 8 章 - host 與 nslookup]]
- [[09-DNS列舉方法論|第 9 章 - DNS 列舉方法論]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
