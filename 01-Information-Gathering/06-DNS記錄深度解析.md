# 第 6 章 - DNS 記錄深度解析

## 標籤

- #cpts
- #chapter
- #dns
- #records

## 學習目標

- 理解常見 DNS Record 的用途與偵察價值。
- 能從 A、AAAA、CNAME、MX、NS、TXT、SOA、PTR、SRV、CAA 萃取攻擊面線索。
- 分辨郵件、身分、服務探索與雲端代管在 DNS 中的表現方式。
- 辨識 Wildcard、Split-horizon、Dangling Record 等實務風險。
- 將 DNS 記錄轉換為後續驗證、優先排序與防禦建議。

---

## 理論基礎

```text
各記錄類型的偵察價值：

A / AAAA  → IPv4/IPv6 主機位址，最基本的主機發現入口
CNAME     → 別名指向：可能指向 CDN、SaaS 平台、雲端代管
            Dangling CNAME：指向已停用的第三方平台 → 資產接管風險
MX        → 郵件基礎設施：自管或第三方（Exchange/Google/SendGrid）
NS        → 委派的權威名稱伺服器（DNS 管理邊界）
TXT       → SPF、DKIM、DMARC 驗證策略 + 第三方整合 token
SOA       → Zone 的管理資訊：主要 NS、序號、Negative Cache TTL
PTR       → 反向解析：命名線索，但可信度保守（常由供應商維護）
SRV       → 服務探索記錄：AD Kerberos/_ldap/_sip/協作服務
CAA       → 允許簽發憑證的 CA 白名單（揭露憑證治理）

重要：
  記錄存在 ≠ 服務可達 → 仍需服務層驗證
  CNAME 指向第三方 ≠ 目標自有 → 需標記為供應商代管
  TXT + MX 組合 → 判斷郵件安全成熟度（SPF/DKIM/DMARC 是否齊全）
```

---

## 方法一：查詢主機與別名記錄

```bash
# A record（IPv4 位址）
dig example.com a +short
# a    → 指定查詢 A 記錄（IPv4）
# +short → 只輸出 IP，方便腳本處理

# AAAA record（IPv6 位址）
dig example.com aaaa +short
# aaaa → 查 IPv6 地址
# 很多團隊忽略 IPv6，但對外服務可能仍走 IPv6

# CNAME record（別名）
dig app.example.com cname +short
# cname → 查別名指向（末尾通常有點：app.example.azurefd.net.）
# 重要判斷：
#   指向 *.cloudfront.net → AWS CloudFront CDN
#   指向 *.azurefd.net   → Azure Front Door
#   指向 *.s3.amazonaws.com → S3 bucket（可能有接管風險）
#   指向 *.github.io     → GitHub Pages（可能有接管風險）

# 追蹤完整 CNAME 鏈到最終 A record
dig app.example.com +short
# 不加記錄類型 → dig 自動追蹤 CNAME 鏈，最終回傳 A record IP
```

---

## 方法二：查詢郵件與驗證記錄

```bash
# MX record（郵件路由）
dig example.com mx +short
# mx → Mail Exchange 記錄
# 輸出格式：優先級 郵件主機（數字越小優先級越高）
# 常見判讀：
#   mail.example.com → 自有郵件伺服器
#   *.mail.protection.outlook.com → Microsoft 365
#   aspmx.l.google.com → Google Workspace
#   mxa.mailgun.org → Mailgun（發送服務）

# TXT record（SPF/DKIM/DMARC 與其他）
dig example.com txt +short
# txt → 文字記錄（內容多種）
# 高價值項目：
#   v=spf1 include:... → SPF 策略（看第三方發送服務）
#   v=DMARC1 p=... → DMARC 策略（p=none/quarantine/reject）
#   google-site-verification=... → Google 站點驗證 token
#   MS=ms... → Microsoft 驗證 token（暗示使用 M365）

# 查 DMARC 記錄
dig _dmarc.example.com txt +short
# _dmarc. 是固定前綴
# p=none → 沒有強制執行，郵件仿冒風險較高
# p=reject → 最嚴格，假冒郵件會被拒絕

# 查 DKIM（需要知道選擇器名稱）
dig default._domainkey.example.com txt +short
# default → DKIM 選擇器（常見：default、mail、google、dkim）
# _domainkey. 是固定前綴
```

---

## 方法三：查詢服務與管理記錄

```bash
# SOA record（Zone 管理資訊）
dig soa example.com +short
# SOA 格式：
#   主要NS  管理員郵件(點替換@)  序號  刷新  重試  過期  MinTTL
# MinTTL → NXDOMAIN 的 Negative Cache TTL

# SRV record（服務探索）
dig _kerberos._tcp.example.com srv +short
# _kerberos._tcp → 服務._協定（SRV 命名格式）
# 常見高價值 SRV：
#   _ldap._tcp.example.com → LDAP（Active Directory）
#   _kerberos._tcp.example.com → Kerberos
#   _sip._tcp.example.com → SIP/VoIP
#   _xmpp-server._tcp.example.com → XMPP（協作）

dig _ldap._tcp.example.com srv +short
# 若有回應 → 幾乎確認有 AD 環境

# CAA record（CA 授權）
dig example.com caa +short
# 輸出：0 issue "letsencrypt.org" → 只允許 Let's Encrypt 簽發
# 0 issuewild "..." → 允許簽發 wildcard 憑證的 CA
# 無記錄 → 任何 CA 都可簽發（管控較寬鬆）

# PTR record（反向解析）
dig -x 203.0.113.10 +short
# -x → 自動建構反向查詢（.in-addr.arpa）
# 回傳 mail.example.com → 命名規則線索
# 回傳 ec2-*.compute.amazonaws.com → 雲端代管前端
```

---

## 決策流程

```
對目標做 DNS 記錄全面收集
    ↓
Step 1：查主機記錄（A/AAAA/CNAME）
  CNAME 指向第三方平台？
    是 → 記錄供應商（CDN/SaaS）；判斷是否有接管風險
    否 → 記錄自有 IP，進入埠掃描清單
    ↓
Step 2：查郵件記錄（MX/TXT/_dmarc）
  第三方郵件（Exchange/Google）？
    是 → 記錄，不列入直接掃描，用於社工/釣魚分析
    自有郵件 → 加入掃描清單（SMTP/IMAP/POP3）
  DMARC p=none？→ 郵件仿冒風險較高
    ↓
Step 3：查服務記錄（SRV/_ldap/_kerberos）
  有 SRV 記錄？
    _ldap._kerberos → 幾乎確認 AD 環境，進入 AD 偵察
    _sip → VoIP 環境，備用
    ↓
Step 4：用 dnsx/httpx 驗證存活（進入下一章）
```

---

## 速查表

```bash
# 主機記錄
dig example.com a +short        # IPv4
dig example.com aaaa +short     # IPv6
dig app.example.com cname +short # 別名

# 郵件記錄
dig example.com mx +short       # 郵件路由
dig example.com txt +short      # SPF/DKIM/其他
dig _dmarc.example.com txt +short # DMARC 策略

# 服務探索
dig _ldap._tcp.example.com srv +short     # AD/LDAP
dig _kerberos._tcp.example.com srv +short # Kerberos

# 管理記錄
dig soa example.com +short      # Zone 序號/MinTTL
dig example.com caa +short      # CA 授權
dig -x 203.0.113.10 +short      # 反向解析
```

---

## 常見錯誤與排查

- 只查 A 記錄，忽略郵件與服務探索資訊 → 完整偵察要查所有記錄類型。
- 把 CNAME 指向的供應商網域直接當成目標主機掃描 → 先確認是否在授權範圍內，再決定是否掃描。
- 忽略 IPv6 → 某些服務只開 IPv6 對外，`dig aaaa` 才能發現。
- 沒有查 SRV 就下結論「沒有 AD 環境」 → `_ldap._tcp` 查詢是最直接的 AD 確認方式之一。
- 把 DMARC `p=none` 當成弱點直接報告 → 應描述為「郵件仿冒防護不完整」，不是可直接利用的漏洞。

---

## 關聯筆記

- [[04-DNS架構與解析流程|第 4 章 - DNS 架構與解析流程]]
- [[05-DNS區域傳送AXFR與IXFR|第 5 章 - DNS 區域傳送]]
- [[07-dig深度解析|第 7 章 - dig 深度解析]]
- [[09-DNS列舉方法論|第 9 章 - DNS 列舉方法論]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
