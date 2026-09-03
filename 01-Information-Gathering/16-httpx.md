# 第 16 章 - httpx

## 標籤

- #cpts
- #chapter
- #httpx
- #web

## 學習目標

- 理解 `httpx` 在 Web 資產探測與 Profiling 中的定位。
- 熟悉狀態碼、標題、Server、長度、Redirect、TLS 與技術指紋的用途。
- 理解 SNI、Host Header、CDN/WAF 與共享前端對判讀的影響。
- 能使用 JSON 輸出建立 Web 資產 inventory。
- 避免把 `httpx` 指紋與回應直接當成漏洞證據。

---

## 理論基礎

```text
httpx 的定位：HTTP 探測器 + Web 資產畫像工具（不是漏洞掃描器）

核心功能：
  確認主機是否有 HTTP/HTTPS 服務
  取得狀態碼、標題、Server Header、回應長度
  追蹤重導（-follow-redirects）
  技術指紋（-tech-detect）
  TLS 憑證資訊（-tls-probe）

輸出用途：
  分群：哪些主機有 Web、哪些沒有
  優先排序：登入頁 / 管理後台 / API 優先
  技術方向：框架、版本、CDN 線索

注意事項：
  httpx 直接接觸目標 HTTP/HTTPS 服務（主動探測）
  技術指紋是推測，不是已驗證事實
  共享前端（CDN/WAF）的回應可能不代表後端實際技術
  SNI 與 Host Header 在多租戶環境中影響結果
```

---

## 基本探測

```bash
# 對主機清單做基本 HTTP 探測
httpx -l hosts.txt -silent
# -l → 從檔案讀取主機名稱清單
# -silent → 只輸出有回應的主機（URL 格式）
# 輸出：http://host 或 https://host（依照自動探測結果）

# 顯示狀態碼與標題（快速分群）
httpx -l hosts.txt -sc -title -silent
# -sc → 顯示 HTTP 狀態碼（Status Code）
# -title → 顯示頁面 <title> 標籤內容
# 輸出：https://host [200] [Page Title]

# 完整資訊：狀態碼 + 標題 + Server + 回應長度
httpx -l hosts.txt -sc -title -server -cl -silent
# -server → 顯示 Server Header（Apache/nginx/IIS 等）
# -cl → 顯示回應 Content-Length
# 相近長度 → 可能是同一模板或錯誤頁

# 指定探測埠
httpx -l hosts.txt -ports 80,443,8080,8443 -sc -title -silent
# -ports → 指定要嘗試的埠（不只是預設 80/443）
# 適合已知有非標準 Web 埠的環境
```

---

## 進階探測

```bash
# 追蹤重導（找最終目的地）
httpx -l hosts.txt -follow-redirects -sc -title -silent
# -follow-redirects → 追蹤 HTTP 301/302 等重導到最終 URL
# 重要：重導目的地可能是第三方（登入頁、CDN）
# 需注意跨站跳轉，不要把第三方站點誤計為目標資產

# 技術指紋辨識
httpx -l hosts.txt -tech-detect -silent
# -tech-detect → 嘗試識別 Web 技術（框架、CMS、伺服器）
# 輸出：https://host [技術名稱]
# 注意：這是工具推測，非已驗證事實
# 用途：決定後續研究方向（Wordpress → 查外掛；Nginx → 確認版本）

# TLS 憑證資訊
httpx -l hosts.txt -tls-probe -silent
# -tls-probe → 提取 TLS 憑證資訊（CN、SAN、過期日）
# 有助於：識別 CDN/WAF 憑證、發現新的主機名稱（SAN）
# 結合 CT Log 查詢（第 10 章）交叉驗證

# 顯示回應 Header（尋找特殊標頭）
httpx -l hosts.txt -include-response-header -silent
# 找：X-Powered-By、X-Frame-Options、Set-Cookie（含 Domain）
# 這些 Header 常洩露框架、版本或後端架構資訊
```

---

## JSON 輸出與後處理

```bash
# JSON 格式輸出（完整資訊，適合自動化）
httpx -l hosts.txt -sc -title -server -tech-detect -json -silent -o web_inventory.json
# -json → JSON 格式，每筆記錄含完整欄位
# 欄位包含：url、status-code、title、server、technologies、tls 等

# 從 JSON 萃取高價值目標（狀態碼 200 的 URL）
jq -r 'select(."status-code" == 200) | .url' web_inventory.json
# select → 過濾條件（只取 200 OK）
# .url → URL 欄位

# 找登入頁（標題含 login/sign in）
jq -r 'select(.title | ascii_downcase | contains("login")) | .url' web_inventory.json
# ascii_downcase → 轉小寫（不分大小寫比對）
# contains("login") → 標題含 login 的記錄

# 找管理後台
jq -r 'select(.title | ascii_downcase | contains("admin")) | .url' web_inventory.json

# 統計技術分佈
jq -r '.technologies[]?' web_inventory.json | sort | uniq -c | sort -rn | head -20
# technologies[] → 展開技術陣列
# sort + uniq -c → 計算各技術出現次數
```

---

## 整合管線

```bash
# 完整 ProjectDiscovery 管線
subfinder -d example.com -silent | \
  dnsx -a -resp -silent | \
  awk '{print $1}' | \
  httpx -sc -title -server -silent -o web_alive.txt
# 每步都只輸出需要的欄位
# 最終輸出：有 Web 服務的主機列表（含狀態碼、標題）

# 對已知開放埠做 Web 探測
# 先有 naabu 輸出（格式：host:port）
cat naabu_out.txt | httpx -sc -title -silent
# httpx 接受 host:port 格式直接探測

# 高價值命名優先探測
grep -iE "vpn|sso|git|admin|api|portal|mgmt" hosts_live.txt | \
  httpx -sc -title -tech-detect -silent
```

---

## 結果分群與優先排序

```bash
# 從 httpx 輸出快速分群

# 找 HTTP 200（正常回應）
grep " \[200\]" web_alive.txt

# 找重導（301/302）
grep -E "\[30[12]\]" web_alive.txt

# 找 401/403（需要認證 / 禁止存取）
grep -E "\[40[13]\]" web_alive.txt
# 401 → 可能有 Basic Auth；403 → 有服務但需繞過

# 找特殊標題關鍵字
grep -i "login\|signin\|admin\|dashboard\|console" web_alive.txt
```

---

## 決策流程

```
hosts_live.txt（dnsx 輸出的可解析主機）
    ↓
httpx -l hosts_live.txt -sc -title -server -silent -o web_alive.txt
    ↓
分析結果
  200 + 登入頁標題 → 優先：身份驗證測試
  200 + 管理後台標題 → 優先：後台存取測試
  200 + API 特徵（JSON/XML 回應）→ 優先：API 測試
  301/302 → 確認重導目的地是否仍在範圍內
  401/403 → 有服務，考慮認證繞過
  無回應 → 跳過 Web；交給 naabu 做全埠掃描
    ↓
高價值 Web 目標 → 深入內容列舉 / 漏洞測試
非 Web 主機 → naabu / Nmap 埠掃描
```

---

## 速查表

```bash
# 基本探測
httpx -l hosts.txt -silent                              # 只確認有 Web
httpx -l hosts.txt -sc -title -silent                   # 狀態碼 + 標題
httpx -l hosts.txt -sc -title -server -cl -silent       # 加 Server + 長度
httpx -l hosts.txt -ports 80,443,8080,8443 -sc -silent  # 指定埠

# 進階
httpx -l hosts.txt -follow-redirects -sc -title -silent # 追蹤重導
httpx -l hosts.txt -tech-detect -silent                 # 技術指紋
httpx -l hosts.txt -tls-probe -silent                   # TLS 憑證

# 輸出
httpx -l hosts.txt -sc -title -json -silent -o out.json # JSON 輸出
jq -r 'select(."status-code" == 200) | .url' out.json  # 篩選 200
```

---

## 常見錯誤與排查

- 把技術指紋當成已確認技術棧 → `-tech-detect` 是工具推測，常有誤判；用作研究方向而非事實。
- 忽略重導目的地 → 跳轉到第三方（SSO/CDN）時，目的地不應計為目標資產。
- 把 CDN/WAF 的回應當後端事實 → Server Header 顯示 nginx 可能是 CDN 前端，不一定是真正後端。
- 沒分群直接做大量手動分析 → 先用 jq 或 grep 分群（200 / 登入頁 / 管理後台），再決定哪些優先。

---

## 關聯筆記

- [[15-dnsx|第 15 章 - dnsx]]
- [[17-Naabu與Nmap掃描分工|第 17 章 - Naabu 與 Nmap 掃描分工]]
- [[24-Recon流程管線整合|第 24 章 - Recon 流程管線整合]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
