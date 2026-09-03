# 第 28 章 - 搜尋引擎與 OSINT

## 標籤

- #cpts
- #chapter
- #osint
- #search

## 學習目標

- 理解搜尋引擎與公開 OSINT 來源在 footprinting 中的價值。
- 能用搜尋結果建立候選資產、技術棧與歷史線索。
- 分辨搜尋結果中的現役、歷史、第三方與噪音資料。
- 將搜尋引擎發現轉換為後續 DNS、Web 或服務驗證行動。
- 避免把搜尋結果直接當成現況事實。

---

## 理論基礎

```text
Search Engine and OSINT 的核心問題：

不是「從搜尋引擎找到什麼」
而是「這些公開索引的資訊是否仍然有效，以及如何轉換為可驗證行動」

三個關鍵認知：
  1. 搜尋引擎看到的是「曾被公開看到的表面」，不是即時現況
       某個子網域被索引 ≠ 現在仍在線
       某份 PDF 提到某平台 ≠ 該系統仍存在
  2. 結果需要分層（而不是直接當清單使用）
       現役可能性高 → 立即驗證
       歷史線索     → 降權保留，不直接當攻擊面
       技術方向     → 整合進第 27 章技術假說
       第三方引用   → 排除或單獨確認
  3. 真正的價值是「觸發後續驗證」，不是「替代驗證」
       從文件找到 intranet.example.com → 下一步 dig + curl，不是直接假設可外部存取
```

---

## Google Dork 技術（搜尋引擎進階查詢）

```bash
# 語法說明：Google Dork 是利用搜尋引擎進階運算子縮小結果範圍的技術

# 基本運算子：
site:example.com              # 限定搜尋範圍為該網域（含所有子域）
site:*.example.com            # 明確限定子網域（部分搜尋引擎支援）
-site:www.example.com         # 排除主站，找其他子域索引
inurl:admin                   # URL 中含 admin
inurl:login                   # URL 中含 login（找登入頁）
intitle:"index of"            # 頁面標題含 "index of"（找目錄列表）
filetype:pdf                  # 只找 PDF 文件
filetype:xlsx OR filetype:xls # 找試算表（常含內部資料）
filetype:env OR filetype:cfg  # 找設定檔（可能有敏感資訊）

# 常用組合：

# 找子網域（未被機器人阻擋的）
site:example.com -www
# -www → 排除主站結果，讓其他子域浮現

# 找登入頁與管理介面
site:example.com inurl:admin OR inurl:login OR inurl:portal OR inurl:dashboard
# 找可能的管理入口，後續用 httpx 驗證

# 找公開文件中的敏感資訊
site:example.com filetype:pdf OR filetype:pptx OR filetype:xlsx
# PDF/投影片常含架構圖、平台名稱、內部主機名稱

# 找設定檔與 .env（資訊洩漏）
site:example.com filetype:env OR filetype:cfg OR filetype:conf
# 若存在，常有 API Key、DB 連線字串

# 找錯誤頁面（技術線索）
site:example.com "500 Internal Server Error" OR "PHP Fatal error" OR "ORA-"
# 錯誤訊息暴露後端技術：PHP / Oracle / 框架版本

# 找快取（原始頁面已下線，但 Google 仍有快取）
cache:intranet.example.com
# 若原站已關，快取可能還有內容（歷史線索）
```

---

## 特定 OSINT 來源

```bash
# Shodan（網路掃描資料庫）
# https://www.shodan.io/
# 搜尋語法：
org:"Example Corp"            # 用組織名搜尋已知 IP 與服務
hostname:example.com          # 用主機名搜尋
ssl.cert.subject.cn:example.com # 用 TLS 憑證 CN 搜尋
net:203.0.113.0/24            # 搜尋特定網段
port:8080,8443,9200           # 特定埠（常見非標準埠）
# 輸出：IP / 埠 / 服務 Banner / OS / 地理位置
# 注意：Shodan 資料通常幾天到幾週前的快照，不是即時

# Censys（另一個網路掃描資料庫）
# https://search.censys.io/
# 語法：
services.tls.certificates.leaf_data.subject.common_name: example.com
# 找 TLS 憑證 CN 為目標域名的服務（常發現雲端子域）
autonomous_system.name: "Example Corp"
# 找對應 ASN 的資產

# GreyNoise（惡意流量資料庫，也可查特定 IP 行為）
# https://viz.greynoise.io/
# 用途：確認某 IP 是否屬於已知掃描器 / 真實服務

# Pastebin / GitHub Gist / OSINT 洩漏平台
site:pastebin.com "example.com"
site:github.com "example.com" password OR secret OR api_key
# 找可能的憑證洩漏或設定片段（非常高價值）
# 注意：這些結果可能已過期，找到後需驗證是否仍有效

# The Wayback Machine（網際網路檔案館）
# https://web.archive.org/web/*/example.com/*
# 用途：
#   找舊版頁面（歷史子域、舊技術、舊 HTML 注釋）
#   確認某個路徑歷史上是否存在
#   比較當前與過去的變化（找被移除但未清理的入口）
curl -s "https://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey" | \
  sort -u | head -100
# 從 Wayback Machine CDX API 抓取所有曾被索引的 URL
# fl=original → 只顯示原始 URL（去重複）
# *.example.com/* → 包含所有子域
```

---

## 搜尋結果分層

```text
每條搜尋結果應歸類到以下其中一層，才能決定後續行動：

Layer 1：現役可能性高
  判斷條件：
    - 索引時間在 6 個月內
    - 頁面功能性正常（有實際內容，非錯誤頁）
    - 與當前 DNS / httpx 結果交叉確認
  後續行動：立即列入驗證清單

Layer 2：歷史線索
  判斷條件：
    - 索引時間超過 1 年
    - Wayback Machine 才有，現在無法直接存取
    - 頁面已顯示 404 或無回應
  後續行動：降權保留，作為命名猜測與技術歷史參考

Layer 3：技術與供應商方向
  判斷條件：
    - 文件 / 投影片 / 職缺中提到的平台名稱
    - 非直接資產，而是技術假說的來源
  後續行動：整合進第 27 章組織偵察的技術假說

Layer 4：第三方引用
  判斷條件：
    - 結果出現在第三方部落格 / 新聞 / 合作廠商頁面
    - 只是引用目標名稱，不代表資產屬目標
  後續行動：排除或單獨追蹤確認
```

---

## 從 OSINT 到驗證行動

```bash
# 範例流程：從搜尋發現子域線索

# Step 1：Google Dork 找到 intranet.example.com 的快取頁面
#   → 不要直接假設可存取，先做 DNS 驗證

# Step 2：DNS 驗證
dig intranet.example.com a +short
# 若有 IP → 繼續 HTTP 驗證
# 若 NXDOMAIN → 已不存在 DNS，歸為歷史線索

# Step 3：HTTP 驗證
curl -I -k https://intranet.example.com
# 200 → 目前可存取，列入 httpx 詳細 profiling
# 401/403 → 存在但需認證，記錄為受保護入口
# 301/302 → 重導向，追蹤目的地
# 連線拒絕 / timeout → 可能防火牆限制，非公開

# Step 4：更新資產地圖
# 欄位：來源（Google Cache）/ 發現名稱 / DNS 狀態 / HTTP 狀態 / 分類 / 下一步
```

---

## 決策流程

```
開始搜尋
    ↓
Google Dork 查詢（目標網域 + 技術關鍵字）
    ↓
結果分類（現役 / 歷史 / 技術方向 / 第三方）
    ↓
現役可能性高？
  是 → dig 驗證 DNS → curl 驗證 HTTP → 加入資產清單
  否 → 繼續下一步
    ↓
歷史線索？
  是 → Wayback Machine 確認歷史快照 → 降權記錄 → 提取命名規則與技術線索
    ↓
技術方向？
  是 → 整合進技術假說（見第 27 章）→ 推導子域候選
    ↓
第三方引用？
  是 → 確認是引用還是資產 → 通常排除
    ↓
檢查 Shodan / Censys（確認是否有未在 DNS 中發現的服務）
    ↓
整合輸出（候選資產清單，標記來源與可信度層級）
```

---

## 速查表

```bash
# Google Dork
site:example.com -www                      # 找子域
site:example.com inurl:admin OR inurl:login # 找管理介面
site:example.com filetype:pdf              # 找文件
site:github.com "example.com" password    # 找程式碼洩漏

# Shodan
org:"Example Corp"                          # 組織 IP 清單
ssl.cert.subject.cn:example.com            # TLS 憑證 CN

# Wayback Machine CDX API
curl -s "https://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey"

# 驗證流程
dig <found-host> a +short                  # DNS 是否仍存在
curl -I -k https://<found-host>            # HTTP 回應確認
```

---

## 常見錯誤與排查

- 把 Google 快取或 Wayback Machine 結果當成現況 → 索引資料必須經 DNS + HTTP 驗證才能確認為現役資產。
- 收集大量搜尋結果但沒有分層整理 → 未分層的 OSINT 混淆了攻擊面真實範圍。
- 忽略第三方引用（第三方部落格提到目標的服務）→ 這只是引用，不代表資產屬於目標授權範圍。
- 沒把 OSINT 結果連接到 DNS / HTTP 驗證流程 → OSINT 的最終價值在「觸發驗證」，而不是「替代驗證」。

---

## 關聯筆記

- [[10-憑證透明度|第 10 章 - 憑證透明度]]
- [[11-子網域列舉|第 11 章 - 子網域列舉]]
- [[27-人員與組織偵察|第 27 章 - 人員與組織偵察]]
- [[02-Volume-2-Footprinting-Index|Vol.2 - Footprinting]]
