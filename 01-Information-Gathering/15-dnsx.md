# 第 15 章 - dnsx

## 標籤

- #cpts
- #chapter
- #dnsx
- #projectdiscovery

## 學習目標

- 理解 `dnsx` 在 DNS Resolution 與驗證流程中的定位。
- 掌握 A、AAAA、CNAME、MX、TXT 查詢與解析驗證用途。
- 理解 Resolver Pool、Rate、Retry 與 Wildcard Detection 的影響。
- 能把 `dnsx` 作為 Subfinder/Amass 與 `httpx`/`naabu` 之間的中繼層。
- 避免把解析成功結果直接當成高價值可利用資產。

---

## 理論基礎

```text
dnsx 的定位：DNS 解析與驗證層（不是名稱發現工具）

在 ProjectDiscovery 管線中的位置：
  Subfinder / Amass / Assetfinder → 候選名稱（未驗證）
  dnsx → 解析驗證 + Wildcard 過濾（收斂成可解析清單）
  httpx / naabu / Nmap → 服務探測

核心價值：
  批次驗證大量候選名稱
  Wildcard 偵測與過濾（-wd）
  多種記錄類型查詢（A/AAAA/CNAME/MX/TXT）
  輸出含 IP（-resp）便於後續 IP 層分析

Resolver 品質的重要性：
  公共 resolver（8.8.8.8 等）→ 受快取與速率影響
  自訂 resolver list（-r）→ 控制查詢路徑，提高穩定性
  Resolver 不穩 → 假陰性（真實主機被標為不可解析）
```

---

## 基本解析驗證

```bash
# 對候選名稱清單做批次 A 記錄查詢
dnsx -l candidates.txt -a -resp -silent
# -l → 從檔案讀取候選名稱清單（每行一個）
# -a → 查詢 A 記錄（IPv4）
# -resp → 顯示解析結果（IP），輸出格式：host [IP]
# -silent → 不輸出 banner，只輸出結果

# 儲存到檔案
dnsx -l candidates.txt -a -resp -silent -o resolved.txt
# -o → 輸出結果到檔案（追加用 >>，覆蓋用 -o）

# 同時查多種記錄類型
dnsx -l candidates.txt -a -aaaa -cname -resp -silent -o resolved_multi.txt
# -aaaa → 同時查 IPv6 記錄
# -cname → 同時查 CNAME（識別第三方代管）

# 包含 MX 與 TXT（郵件相關資產）
dnsx -l candidates.txt -mx -txt -resp -silent
# -mx → 查 MX 記錄
# -txt → 查 TXT 記錄（SPF/DKIM/DMARC）
```

---

## Wildcard 偵測與過濾

```bash
# 方法一：dnsx 內建 Wildcard 偵測
dnsx -l candidates.txt -a -resp -silent -wd example.com -o resolved.txt
# -wd example.com → 告訴 dnsx 針對這個網域做 Wildcard 偵測
# dnsx 會自動查詢隨機名稱確認是否有 Wildcard
# 偵測到 Wildcard 的結果會被標記或過濾

# 方法二：手動過濾（先確認 Wildcard IP）
WILDCARD_IP=$(dig @ns1.example.com "randxyz12345.example.com" +short)
dnsx -l candidates.txt -a -resp -silent | grep -v "\[${WILDCARD_IP}\]" > resolved_clean.txt
# grep -v → 排除包含 Wildcard IP 的行
# 結合 dig 手動偵測 + grep 過濾是最常用的實戰做法

# 確認過濾結果
wc -l resolved.txt resolved_clean.txt
# 比較過濾前後行數，評估 Wildcard 假陽性數量
```

---

## 指定 Resolver

```bash
# 使用自訂 Resolver 清單（提高穩定性）
dnsx -l candidates.txt -a -resp -silent -r resolvers.txt
# -r resolvers.txt → 從檔案讀取 Resolver IP 清單（每行一個）
# 範例 resolvers.txt：
#   8.8.8.8
#   1.1.1.1
#   9.9.9.9
#   8.8.4.4

# 控制速率與重試（大量清單時）
dnsx -l candidates.txt -a -resp -silent -rate-limit 100 -retry 3
# -rate-limit 100 → 每秒最多 100 個查詢
# -retry 3 → 失敗時重試最多 3 次
# 較低速率 → 較穩定，但花費時間更長

# 指定單一 Resolver（測試用）
dnsx -d sub.example.com -a -resp -r 8.8.8.8
# -d → 直接指定單一域名（不用 -l 清單）
```

---

## JSON 輸出與後處理

```bash
# JSON 格式輸出（含完整欄位）
dnsx -l candidates.txt -a -cname -resp -silent -json -o resolved.json
# -json → JSON 格式輸出
# 每筆記錄含：host、a（IP 陣列）、cname（別名）等欄位

# 從 JSON 萃取主機名稱
jq -r '.host' resolved.json | sort -u
# .host → 萃取 host 欄位

# 從 JSON 萃取含 CNAME 的記錄（識別第三方代管）
jq -r 'select(.cname != null) | "\(.host) → \(.cname[])"' resolved.json
# select(.cname != null) → 過濾有 CNAME 的記錄
# 輸出：host → cname（識別 CDN / SaaS）

# 只取主機名稱（供後續工具使用）
awk '{print $1}' resolved.txt > hosts_live.txt
# 從純文字輸出取第一欄（主機名稱）
```

---

## 整合管線

```bash
# 完整標準管線
subfinder -d example.com -silent | \
  dnsx -a -resp -silent | \
  grep -v "\[${WILDCARD_IP}\]" | \
  awk '{print $1}' | \
  httpx -silent -status-code -title
# 每個工具只做自己的事：
#   subfinder → 被動蒐集候選名稱
#   dnsx → DNS 驗證（含 IP）
#   grep -v → 過濾 Wildcard
#   awk → 取主機名稱
#   httpx → Web 服務驗證

# 多工具合併 + dnsx 驗證
cat subfinder_out.txt amass_out.txt ct_out.txt | sort -u | \
  dnsx -a -resp -silent -wd example.com -o resolved.txt
```

---

## 決策流程

```
候選名稱清單（來自 Subfinder / Amass / CT / Brute Force）
    ↓
Wildcard 偵測
  有 Wildcard → 記錄 IP；選擇 -wd 或手動 grep -v
  無 Wildcard → 直接進入驗證
    ↓
dnsx -l candidates.txt -a -resp -silent -o resolved.txt
    ↓
結果評估
  解析失敗（無輸出）→ 丟棄（歷史資料或名稱不存在）
  解析成功但 IP = Wildcard IP → 過濾（假陽性）
  解析成功 → 追蹤 CNAME（識別第三方代管）
    ↓
輸出高品質主機清單（hosts_live.txt）
    ↓
httpx（Web）/ naabu（埠）/ Nmap（服務）
```

---

## 速查表

```bash
# 基本驗證
dnsx -l candidates.txt -a -resp -silent -o resolved.txt
dnsx -l candidates.txt -a -aaaa -cname -resp -silent        # 多記錄類型
dnsx -l candidates.txt -a -resp -silent -wd example.com     # Wildcard 偵測

# Resolver 控制
dnsx -l candidates.txt -a -resp -silent -r resolvers.txt
dnsx -l candidates.txt -a -resp -silent -rate-limit 100 -retry 3

# JSON 輸出
dnsx -l candidates.txt -a -cname -resp -silent -json -o out.json
jq -r '.host' out.json | sort -u

# 管線
subfinder -d example.com -silent | dnsx -a -resp -silent
awk '{print $1}' resolved.txt > hosts_live.txt
```

---

## 常見錯誤與排查

- 不做 Wildcard 過濾就輸出結果 → Wildcard 環境中大量假陽性進入後續管線，掃描器浪費時間在不存在的主機上。
- 使用預設 Resolver 但結果不穩 → 加 `-r resolvers.txt` 指定可靠的 resolver 集合，加 `-retry 3` 降低假陰性。
- 把 CNAME 結果直接視為同等掃描目標 → 先確認 CNAME 是自有 IP 還是 CDN/SaaS（第三方代管應標記但不直接掃描）。
- 沒保留 `-resp` 輸出的 IP 欄位 → 後續 Nmap 需要 IP，只有主機名稱時要再解析一次，浪費時間。

---

## 關聯筆記

- [[11-子網域列舉|第 11 章 - 子網域列舉]]
- [[13-Subfinder|第 13 章 - Subfinder]]
- [[14-Assetfinder|第 14 章 - Assetfinder]]
- [[16-httpx|第 16 章 - httpx]]
- [[17-Naabu與Nmap掃描分工|第 17 章 - Naabu 與 Nmap 掃描分工]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
