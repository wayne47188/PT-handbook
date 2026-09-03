# 第 2 章 - WHOIS 深度解析

## 標籤

- #cpts
- #chapter
- #whois
- #rdap

## 學習目標

- 理解 WHOIS、RDAP、Registrar、Registry 之間的角色分工。
- 從網域、IP 與 ASN 註冊資料中萃取可用的偵察線索。
- 正確判讀 Name Server、Status、日期欄位與聯絡資訊的偵察價值。
- 分辨隱私代理、代管服務與歷史資料造成的誤判。
- 將 WHOIS/RDAP 結果轉換為後續 DNS、ASN 與資產驗證流程。

---

## 理論基礎

```text
WHOIS vs RDAP：
  WHOIS：傳統查詢協定（TCP/43），格式依註冊局不一致，自動化解析困難
  RDAP：WHOIS 的結構化替代方案，回傳 JSON，適合程式處理
  → 偵察時兩者都查，結果可交叉比對

角色分工：
  Registry  → 頂層網域（.com/.org）的管理機構（Verisign 管 .com）
  Registrar → 幫客戶註冊和管理網域的公司（GoDaddy、Namecheap）
  RIR       → 區域 IP/ASN 的管理機構
    ARIN（北美）、RIPE（歐洲/中東）、APNIC（亞太）
    LACNIC（拉美）、AFRINIC（非洲）

偵察價值分析：
  Name Server  → 誰在管 DNS 控制平面（自有 NS or 第三方如 Cloudflare）
  Creation Date → 網域建立時間（愈舊愈可能有更多歷史洩漏）
  Updated Date  → 近期異動線索（值得驗證最近的服務變更）
  Registrant Org → 可能是真組織名稱 or 隱私代理（Privacy Guard）
  Status        → clientTransferProhibited 等是正常保護措施，非弱點
```

---

## 方法一：網域 WHOIS 查詢

```bash
# 標準網域 WHOIS
whois example.com
# 輸出重點欄位：
#   Registrar: GoDaddy LLC        → 委託的註冊商
#   Name Server: ns1.cloudflare.com → DNS 管理者（可能是 CDN/第三方）
#   Creation Date: 2010-01-15     → 網域建立時間
#   Updated Date: 2024-03-01      → 最近異動時間
#   Registry Expiry Date: 2026-01-15 → 到期時間（快到期可能有管理漏洞）
#   Registrant Organization: REDACTED → 隱私保護，無法直接取得組織名

# 指定 WHOIS 伺服器（當預設伺服器轉介不正確時）
whois -h whois.verisign-grs.com example.com
# -h → 指定要查詢的 WHOIS 伺服器（不走自動選擇）
# .com 的權威 WHOIS 是 whois.verisign-grs.com

# 查網域在另一個 TLD 的狀況（找品牌相關資產）
whois example.net
whois example.org
# 同一組織可能持有多個 TLD，Name Server 相同就是線索
```

---

## 方法二：IP 與 ASN WHOIS

```bash
# 查 IP 的 RIR 歸屬（確認 IP 屬於哪個組織）
whois 203.0.113.10
# 輸出重點欄位：
#   NetRange: 203.0.113.0 - 203.0.113.255  → 整個網段範圍
#   CIDR: 203.0.113.0/24                   → CIDR 表示法
#   OrgName: Example Corp                  → 組織名稱
#   OrgId: EXMP-123                        → 組織識別碼（可關聯查其他資產）
#   NetName: EXMPCORP-NET                  → 網路名稱線索

# 查 ASN 的管理資訊
whois AS64500
# 或
whois -h whois.arin.net AS64500
# -h whois.arin.net → 北美 RIR，強制指定（若預設轉介失敗）
# 輸出：AutName、OrgId、Prefix 清單等資料

# 查 IP 時看到的只是上游（常見雲端 ASN）
whois 104.21.80.10    # 可能回傳 Cloudflare 的 ASN，不是目標組織
# → 這種情況需要回頭用 TLS 憑證、HTTP 標頭等驗證真正的目標
```

---

## 方法三：RDAP 結構化查詢（自動化友善）

```bash
# 用 RDAP 查網域（JSON 格式，適合 jq 解析）
curl -s https://rdap.org/domain/example.com
# rdap.org → 公共 RDAP 聚合器，自動轉到正確的 Registry
# 回傳 JSON，包含 nameservers、events、entities 等欄位

# 取出 Name Server 清單
curl -s https://rdap.org/domain/example.com | \
  jq -r '.nameservers[].ldhName'
# jq -r '.nameservers[].ldhName' → 從 JSON 取 Name Server 清單

# 取出事件時間軸（建立/更新/到期）
curl -s https://rdap.org/domain/example.com | \
  jq -r '.events[] | "\(.eventAction): \(.eventDate)"'
# .events[] → 遍歷事件陣列
# eventAction/eventDate → 取得事件類型與時間

# 用 RDAP 查 IP
curl -s https://rdap.org/ip/203.0.113.10
# 回傳 JSON，含 name、country、cidr0_cidrs（CIDR 範圍）等
curl -s https://rdap.org/ip/203.0.113.10 | jq -r '.name, .country'
# 快速確認網段名稱與國家
```

---

## 決策流程

```
已知目標網域/IP/組織名
    ↓
查網域 WHOIS → whois example.com
  找到真實組織名稱？
    是 → 記錄，搜尋相關網域 / CT Logs
    否（隱私代理）→ 嘗試 RDAP、舊 WHOIS 歷史或其他被動來源
    ↓
看 Name Server 供應商
  自有 NS（ns1.example.com）？
    是 → 值得嘗試 Zone Transfer（第 5 章）
    否（第三方如 Cloudflare/Route53）→ 記錄供應商，繼續 DNS 層偵察
    ↓
查 IP WHOIS → whois TARGET_IP
  回傳目標自有 ASN/OrgName？
    是 → 用 ASN 擴圖（第 3 章）
    否（雲端/CDN ASN）→ 標記為代管前端，用 TLS/HTTP 另行驗證
```

---

## 速查表

```bash
# 網域 WHOIS
whois example.com
whois -h whois.verisign-grs.com example.com   # 指定 .com Registry

# IP / ASN WHOIS
whois 203.0.113.10
whois AS64500

# RDAP（JSON 格式）
curl -s https://rdap.org/domain/example.com | jq -r '.nameservers[].ldhName'
curl -s https://rdap.org/ip/203.0.113.10 | jq -r '.name, .country'

# 取出建立/更新日期
curl -s https://rdap.org/domain/example.com | \
  jq -r '.events[] | "\(.eventAction): \(.eventDate)"'
```

---

## 常見錯誤與排查

- 把 Registrar（GoDaddy）或 RIR（ARIN）誤認成目標組織 → 看 `OrgName` 欄位，不是 `Registrar`。
- 看到隱私代理就放棄 → 嘗試 RDAP 歷史、搜尋引擎、CT Logs 或 GitHub 找組織線索。
- 把 Name Server 供應商當服務主機 → NS 只代表 DNS 管理位置，不代表 Web/Mail 服務在那台主機。
- 把 `Updated Date` 當成服務上線時間 → 可能只是 DNS 或聯絡資料異動。
- 對單一 WHOIS 來源過度信任 → 用 RDAP 交叉驗證，並比對 DNS 層資料。

---

## 關聯筆記

- [[01-資訊蒐集總覽|第 1 章 - 資訊蒐集總覽]]
- [[03-ASN與BGP資產發現|第 3 章 - ASN 與 BGP 資產發現]]
- [[04-DNS架構與解析流程|第 4 章 - DNS 架構與解析流程]]
- [[10-憑證透明度|第 10 章 - 憑證透明度]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
