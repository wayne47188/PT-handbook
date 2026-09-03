# 第 4 章 - DNS 架構與解析流程

## 標籤

- #cpts
- #chapter
- #dns
- #resolution

## 學習目標

- 理解 Stub Resolver、Recursive Resolver 與 Authoritative Server 的分工。
- 掌握 Root、TLD、Delegation 與權威回答的解析流程。
- 區分 Recursive Query 與 Iterative Query 在實務上的角色。
- 理解 TTL、快取、Negative Cache、UDP/TCP 53 與 EDNS 的影響。
- 能將 DNS 解析行為轉換為偵察、驗證與排錯決策。

---

## 理論基礎

```text
DNS 查詢流程（完整路徑）：

Client → Stub Resolver → Recursive Resolver → Root NS → TLD NS → Auth NS

各角色分工：
  Stub Resolver   → 終端主機上的簡化解析端，把查詢轉給 Recursive Resolver
  Recursive Resolver → 代替 Client 完成整個查詢流程，快取結果（如 8.8.8.8、1.1.1.1）
  Authoritative NS → 持有某 Zone 的權威資料，給出最終答案（如 ns1.example.com）

TTL（Time To Live）對偵察的影響：
  TTL 高（如 86400 秒）→ 快取久，遞迴解析器的結果可能不是最新
  TTL 低（如 300 秒）→ 常更新，可能代表動態基礎設施或 CDN 輪換
  Negative Cache → NXDOMAIN 的快取（有 SOA 記錄中的 Minimum TTL）

UDP vs TCP/53：
  UDP → 一般 DNS 查詢（延遲低，封包小）
  TCP → 大型回應、Zone Transfer、EDNS truncation 時才用
  TC 旗標（Truncated）→ UDP 回應被截斷，客戶端應改用 TCP 重試

偵察關鍵：
  看到不一致結果 → 先懷疑快取/TTL，再懷疑 wildcard
  取得權威回答比遞迴快取更可靠
  aa 旗標（Authoritative Answer）→ 確認來源是權威伺服器
```

---

## 方法一：基本 dig 查詢與結果解讀

```bash
# 標準查詢（A record）
dig app.example.com
# 輸出五個區塊：
#   ;; QUESTION SECTION    → 你查什麼
#   ;; ANSWER SECTION      → 回答（A record + TTL）
#   ;; AUTHORITY SECTION   → 哪個 NS 負責這個 Zone
#   ;; ADDITIONAL SECTION  → 額外資訊（通常是 NS 的 glue record）
#   ;; Query time          → 查詢延遲（高延遲 → 可能是 EDNS 問題）

# 簡短輸出（只看 IP）
dig app.example.com +short
# +short → 省略所有 header，只輸出 ANSWER（方便腳本解析）

# 指定遞迴解析器查詢（比對不同 resolver 的快取差異）
dig @8.8.8.8 app.example.com
# @8.8.8.8 → 指定用 Google Public DNS（而非系統預設 resolver）
dig @1.1.1.1 app.example.com
# @1.1.1.1 → 指定用 Cloudflare DNS
# 不同 resolver 回傳不同 IP → 可能是 CDN anycast 或 resolver 快取不同

# 直接查權威名稱伺服器（取得最即時的權威資料）
dig @ns1.example.com app.example.com
# @ns1.example.com → 繞過遞迴解析器，直接問權威 NS
# 輸出帶 aa 旗標 → 確認是權威答案（Authoritative Answer）
```

---

## 方法二：追蹤委派路徑

```bash
# 追蹤完整委派路徑（Root → TLD → Auth NS）
dig app.example.com +trace
# +trace → dig 自己模擬遞迴解析，從 Root 開始逐步往下追
# 輸出：Root NS → .com TLD NS → example.com Auth NS → 最終答案
# 用途：確認委派是否正確、找出真正負責的 Auth NS

# 只查 NS 記錄（找出所有權威名稱伺服器）
dig ns example.com +short
# 可能有多台（ns1、ns2），AXFR 時要逐一測試

# 查 SOA 記錄（確認 Zone 的主要 NS 與序號）
dig soa example.com +short
# SOA 格式：主要NS  郵件  序號  刷新間隔  重試間隔  過期時間  Minimum TTL
# Minimum TTL → Negative Cache 的 TTL

# 強制 TCP 查詢
dig app.example.com +tcp
# +tcp → 強制使用 TCP/53（一般 UDP/53 正常不需要）
# 用途：排查 UDP 路徑問題、大型回應被截斷時
```

---

## 方法三：驗證 Wildcard DNS（避免假陽性）

```bash
# 對隨機不存在的主機名稱做查詢
dig randomxyz12345.example.com +short
# 若回傳一個 IP → 可能是 wildcard DNS（*.example.com → IP）
# 若回傳 NXDOMAIN → 無 wildcard，子網域列舉結果更可信

# 確認是否 wildcard（比對兩個不存在的名稱是否回相同 IP）
dig aaabbbccc.example.com +short
dig zzzyyy999.example.com +short
# 兩個都回相同 IP → 確認是 wildcard
# wildcard 下要過濾：把和 wildcard 相同 IP 的結果排除

# 查詢時確認 status
dig nonexistent.example.com
# status: NXDOMAIN → 明確不存在（確認子網域列舉結果有效）
# status: NOERROR + 有 A record → wildcard 或真實存在
# status: SERVFAIL → 解析失敗（可能是 Auth NS 問題）
# status: REFUSED  → DNS 伺服器拒絕回答（可能是 ACL 限制）
```

---

## 決策流程

```
需要查詢 DNS 資訊
    ↓
先找權威 NS：dig ns example.com +short
    ↓
直接問權威（最可靠）：dig @ns1.example.com HOST
  回應有 aa 旗標？
    是 → 權威答案，可信
    否 → 遞迴快取，加上 TTL 考量
    ↓
不同 resolver 回傳不一致？
  先看 TTL → 是否剛更新（TTL 快歸零）
  查是否 wildcard → dig randomXXXXX.example.com +short
    是 wildcard → 子網域列舉結果需過濾
    否 → 結果可信
    ↓
需要完整委派路徑？
  dig +trace → 找出真正負責的 Auth NS
UDP 回應截斷（TC 旗標）？
  dig +tcp → 改用 TCP 重試
```

---

## 速查表

```bash
# 標準 A record 查詢
dig app.example.com +short

# 指定 resolver 比對
dig @8.8.8.8 app.example.com +short
dig @1.1.1.1 app.example.com +short

# 直接問權威 NS（最可靠）
dig @ns1.example.com app.example.com

# 找所有 Auth NS
dig ns example.com +short

# 追蹤委派路徑
dig app.example.com +trace

# 查 SOA（序號、Minimum TTL）
dig soa example.com +short

# 強制 TCP
dig app.example.com +tcp

# Wildcard 驗證
dig randomXXX.example.com +short
```

---

## 常見錯誤與排查

- 把遞迴解析器快取結果當成權威事實 → 加 `@ns1.example.com` 直接問權威，確認 aa 旗標。
- 忽略 TTL 導致對剛更新的記錄做錯誤推論 → 查詢時注意 ANSWER SECTION 中的 TTL 值。
- 沒檢查 wildcard 就直接把大量「成功解析」的主機納入資產 → 先對隨機不存在名稱做對照查詢。
- 把 SERVFAIL 與 NXDOMAIN 混為一談 → SERVFAIL 是解析失敗，NXDOMAIN 是明確不存在。
- 只看 `+short` 輸出，忽略 status、AUTHORITY 與旗標 → 完整 dig 輸出比 +short 提供更多判讀依據。

---

## 關聯筆記

- [[01-資訊蒐集總覽|第 1 章 - 資訊蒐集總覽]]
- [[05-DNS區域傳送AXFR與IXFR|第 5 章 - DNS 區域傳送]]
- [[07-dig深度解析|第 7 章 - dig 深度解析]]
- [[09-DNS列舉方法論|第 9 章 - DNS 列舉方法論]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
