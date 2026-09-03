# 第 3 章 - ASN 與 BGP 資產發現

## 標籤

- #cpts
- #chapter
- #asn
- #bgp

## 學習目標

- 理解 ASN、BGP、Prefix、Route Origin 與 RIR 資料之間的關係。
- 從組織名稱、ASN 與網段映射出外部可見的網路資產範圍。
- 分辨自有資產、雲端代管、CDN 與第三方網路造成的歸屬誤判。
- 將 ASN 資訊轉換為後續埠掃描、DNS 驗證與資產優先級排序。
- 了解 BGP 視角的限制，避免把可路由前綴直接當成可攻擊主機清單。

---

## 理論基礎

```text
核心概念：

ASN（Autonomous System Number）
  → 識別在 BGP 中宣告路由政策的自治系統
  → 一個 ASN 通常代表一個組織管理的 IP 路由邊界

BGP Prefix（路由前綴）
  → 某個 ASN 對外宣告的 IP 網段（如 203.0.113.0/24）
  → 可以從公開 BGP 觀測資料（BGPView、bgp.he.net）取得

偵察用途：
  知道 ASN → 找到所有關聯 Prefix → 縮小候選 IP 範圍
  知道 IP → 查到 ASN → 找到同組織其他網段

重要限制：
  1. Prefix 屬於某 ASN ≠ 整段都有活躍主機
  2. 雲端/CDN 前端的 IP → Origin ASN 是供應商（AWS/Cloudflare），非目標
  3. 歷史路由資料可能已不反映現況
  → 任何 ASN 推論都要用 DNS/HTTP/TLS 服務層驗證
```

---

## 方法一：從 IP 找 ASN（反向查找）

```bash
# 從已知 IP 查 ASN 歸屬（whois）
whois 203.0.113.10
# 輸出重點：
#   OriginAS: AS64500         → 宣告這個 IP 的 ASN
#   OrgName: Example Corp     → 組織名稱
#   CIDR: 203.0.113.0/24      → 所屬網段

# 用 dig 反查命名（輔助判斷是否目標自有）
dig -x 203.0.113.10 +short
# -x → 反向查詢，自動建構 .in-addr.arpa 查詢
# +short → 只回傳 PTR 記錄

# 若 PTR 回傳 mail.example.com → 很可能是目標自有 IP
# 若 PTR 回傳 ec2-203-0-113-10.compute.amazonaws.com → 雲端代管前端
```

---

## 方法二：從 ASN 找網段（BGPView API）

```bash
# 用 BGPView API 查 ASN 的所有 Prefix（JSON 格式）
curl -s "https://api.bgpview.io/asn/64500/prefixes" | \
  jq -r '.data.ipv4_prefixes[].prefix'
# .data.ipv4_prefixes[].prefix → 取出所有 IPv4 CIDR
# 輸出：203.0.113.0/24, 198.51.100.0/23 等網段列表

# 取 IPv6 Prefix（若目標有 IPv6 空間）
curl -s "https://api.bgpview.io/asn/64500/prefixes" | \
  jq -r '.data.ipv6_prefixes[].prefix'

# 查 ASN 基本資訊（確認是否真的是目標組織）
curl -s "https://api.bgpview.io/asn/64500" | \
  jq -r '.data | "\(.name) - \(.description_short)"'
# .name/.description_short → 組織名稱與簡介（確認 ASN 歸屬是否正確）
```

---

## 方法三：從組織名稱搜尋 ASN

```bash
# 用 BGPView 搜尋組織名稱對應的 ASN
curl -s "https://api.bgpview.io/search?query_term=Example+Corp" | \
  jq -r '.data.asns[] | "\(.asn) \(.name)"'
# query_term → 組織名稱關鍵字（空格用 + 替換）
# .data.asns[] → 遍歷所有匹配的 ASN 結果

# 用 he.net BGP toolkit（瀏覽器或 curl）
curl -s "https://bgp.he.net/search?search%5Bsearch%5D=Example+Corp&commit=Search" | \
  grep -oP 'AS\d+' | sort -u
# grep -oP 'AS\d+' → 用 Perl regex 提取所有 ASN 字串
# sort -u → 排序去重

# 用 whois 直接搜尋 ARIN（適合美國/北美）
whois -h whois.arin.net "o Example Corp"
# o → ARIN 搜尋組織名稱的前綴
```

---

## 方法四：驗證 ASN/Prefix 是否屬於目標

```bash
# 對 Prefix 中的代表性 IP 做 DNS 反向解析
dig -x 203.0.113.1 +short    # 確認 PTR 指向目標命名規則
dig -x 203.0.113.100 +short  # 抽樣多個 IP 驗證

# 低互動 Web 驗證（確認服務屬於目標）
curl -I http://203.0.113.10
# 看 Server 標頭、Location 重定向、Set-Cookie domain 等
# 若指向 example.com → 確認屬於目標
# 若指向 404.aws.amazon.com → CDN/雲端代管前端

# 確認 TLS 憑證的 CN/SAN
openssl s_client -connect 203.0.113.10:443 -servername example.com </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
# openssl s_client -connect → 建立 TLS 連線
# -servername → 送出 SNI（Server Name Indication）
# openssl x509 -noout -text → 解析憑證文字格式
# grep "Subject Alternative Name" → 取出 SAN 欄位
# SAN 中有 *.example.com → 確認屬於目標
```

---

## 決策流程

```
已知目標 IP / 組織名
    ↓
whois TARGET_IP → 找 OriginAS
  找到目標自有 ASN？
    是 → BGPView API 取所有 Prefix → 建立候選網段清單
    否（雲端 ASN）→ 標記為代管前端，用 TLS/PTR 驗證真實目標
    ↓
對候選 Prefix 抽樣驗證：
  dig -x IP（PTR 命名規則一致？）
  curl -I IP（Service 標頭 / 憑證 SAN 指向目標？）
    一致 → 納入主動掃描清單
    不一致 → 標記為供應商/共享基礎設施，暫不列入
    ↓
確認後的自有網段 → Nmap / Naabu 埠掃描（主動偵察階段）
```

---

## 速查表

```bash
# 從 IP 找 ASN
whois 203.0.113.10
dig -x 203.0.113.10 +short     # 反向解析輔助判斷

# 從 ASN 找 Prefix
curl -s "https://api.bgpview.io/asn/64500/prefixes" | \
  jq -r '.data.ipv4_prefixes[].prefix'

# 從組織名稱搜 ASN
curl -s "https://api.bgpview.io/search?query_term=Example+Corp" | \
  jq -r '.data.asns[] | "\(.asn) \(.name)"'

# 驗證 IP 是否屬於目標（TLS SAN）
openssl s_client -connect IP:443 -servername example.com </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep "DNS:"
```

---

## 常見錯誤與排查

- 把雲端供應商 ASN（AWS AS16509、Cloudflare AS13335）當成目標自有 ASN → 看 OrgName 確認，再用 TLS 憑證交叉驗證。
- 看到相鄰網段就假設都在授權範圍內 → ASN 資料只是偵察線索，需回 RoE 確認授權範圍。
- 忽略歷史路由資料可能已不同步 → BGP 觀測資料有延遲，用 DNS/HTTP 即時驗證才算確認。
- 缺乏服務層交叉驗證 → PTR 回傳目標命名、TLS 憑證 SAN 包含目標網域，才是強確認。

---

## 關聯筆記

- [[01-資訊蒐集總覽|第 1 章 - 資訊蒐集總覽]]
- [[02-WHOIS深度解析|第 2 章 - WHOIS 深度解析]]
- [[04-DNS架構與解析流程|第 4 章 - DNS 架構與解析流程]]
- [[17-Naabu與Nmap掃描分工|第 17 章 - Naabu 與 Nmap 掃描分工]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
