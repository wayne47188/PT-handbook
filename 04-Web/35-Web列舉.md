# 第 35 章 - Web 列舉

## 標籤

- #cpts
- #chapter
- #web
- #enumeration

## 學習目標

- 能用 ffuf / feroxbuster / gobuster 做目錄與檔案爆破，並有效降噪。
- 知道如何從 JS 原始碼提取隱藏端點與 API 路由。
- 能依回應長度、狀態碼、標題過濾假陽性。
- 建立從爆破結果到測試清單的完整流程。

---

## 理論基礎：Web 列舉的噪音問題

Web 列舉最大的問題是假陽性：SPA 對所有路徑回 200、WAF 統一回 403、應用對不存在頁面回一致長度的 404 頁面。不處理噪音就無法找到真正有價值的端點。

| 噪音來源 | 特徵 | 處理方式 |
|----------|------|----------|
| SPA 前端路由 | 所有路徑 200，body 相同 | 過濾特定長度或關鍵字 |
| 統一錯誤頁 | 404 但 body 很長（自訂頁面）| 用 `-fc 404` 或過濾長度 |
| WAF 封鎖 | 所有請求 403 | 嘗試繞過或換 wordlist |
| 重定向 | 301/302 指向同一頁面 | `-fc 301,302` 或追蹤重定向 |

---

## 方法一：目錄爆破（ffuf）

```bash
# 基本目錄爆破
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://TARGET/FUZZ
# -w → wordlist 路徑
# -u → 目標 URL（FUZZ 是佔位符，替換每個字典詞）
# common.txt → 常見路徑（4700 個）

# 常用 wordlist 選擇
# common.txt        → 快速（約 5000）
# directory-list-2.3-medium.txt → 中等（約 22 萬，慢）
# raft-medium-directories.txt   → 目錄爆破推薦
# /usr/share/seclists/Discovery/Web-Content/

# 加入副檔名
ffuf -w common.txt -u http://TARGET/FUZZ -e .php,.html,.txt,.bak,.zip
# -e → 副檔名列表（逗號分隔）
# 每個字典詞會產生多個請求（word、word.php、word.html...）

# 調整執行緒與速率（避免觸發 WAF）
ffuf -w common.txt -u http://TARGET/FUZZ -t 50 -rate 100
# -t 50     → 50 個並發執行緒（預設 40）
# -rate 100 → 每秒最多 100 個請求

# 降噪：過濾狀態碼
ffuf -w common.txt -u http://TARGET/FUZZ -fc 404,403
# -fc → filter code（過濾這些狀態碼的結果）

# 降噪：過濾回應大小
ffuf -w common.txt -u http://TARGET/FUZZ -fs 1234
# -fs → filter size（過濾回應 body 大小剛好等於 1234 bytes 的結果）
# 先不加 -fs 跑一次，觀察 404 頁面的固定大小，再加入過濾

# 降噪：過濾回應字數或行數
ffuf -w common.txt -u http://TARGET/FUZZ -fw 10
# -fw → filter words（過濾回應字數等於 10 的結果）
ffuf -w common.txt -u http://TARGET/FUZZ -fl 5
# -fl → filter lines（過濾回應行數等於 5 的結果）

# 只顯示特定狀態碼（白名單模式）
ffuf -w common.txt -u http://TARGET/FUZZ -mc 200,301,302,401
# -mc → match code（只顯示這些狀態碼的結果）

# 輸出到檔案
ffuf -w common.txt -u http://TARGET/FUZZ -o ffuf_results.json -of json
# -o  → 輸出路徑
# -of → 輸出格式（json/csv/html）

# 遞迴爆破（發現目錄後繼續向下）
ffuf -w common.txt -u http://TARGET/FUZZ -recursion -recursion-depth 2
# -recursion       → 發現目錄時自動遞迴
# -recursion-depth → 最大遞迴深度（2 層）
```

---

## 方法二：目錄爆破（feroxbuster）

```bash
# 基本爆破（feroxbuster 預設就會遞迴）
feroxbuster -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
# -u → 目標 URL
# -w → wordlist

# 加副檔名
feroxbuster -u http://TARGET -w common.txt -x php,html,txt
# -x → 副檔名（逗號分隔，不加點）

# 調整執行緒
feroxbuster -u http://TARGET -w common.txt -t 50
# -t → 執行緒數（預設 50）

# 過濾狀態碼
feroxbuster -u http://TARGET -w common.txt --filter-status 404,403
# --filter-status → 過濾這些狀態碼

# 過濾回應大小
feroxbuster -u http://TARGET -w common.txt --filter-size 1234
# --filter-size → 過濾特定大小的回應

# 限制遞迴深度
feroxbuster -u http://TARGET -w common.txt --depth 2
# --depth → 最大遞迴深度
```

---

## 方法三：gobuster

```bash
# 目錄模式
gobuster dir -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/common.txt
# dir → 目錄列舉模式

# 加副檔名
gobuster dir -u http://TARGET -w common.txt -x php,html,txt,bak
# -x → 副檔名

# 忽略 TLS 錯誤
gobuster dir -u https://TARGET -w common.txt -k
# -k → 忽略 TLS 憑證驗證

# 過濾狀態碼
gobuster dir -u http://TARGET -w common.txt -b 404,403
# -b → blacklist（過濾這些狀態碼）

# 子網域列舉模式
gobuster dns -d TARGET_DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
# dns → DNS 子網域模式
# -d → 目標網域
```

---

## 方法四：JS 分析（找隱藏端點）

```bash
# 手動提取 JS 中的 URL
curl http://TARGET/app.js | grep -oE '"/[a-zA-Z0-9/_-]+"' | sort -u
# grep -oE → 只輸出匹配部分，使用 extended regex
# 匹配 "/api/..." 格式的路徑

# LinkFinder（自動從 JS 提取端點）
python3 linkfinder.py -i http://TARGET/app.js -o cli
# -i → 輸入（URL 或本機檔案）
# -o cli → 輸出到終端

# 對整個域名掃描
python3 linkfinder.py -i https://TARGET -d -o cli
# -d → 域名模式（爬取頁面上所有 JS）

# subjs（批次提取 JS URL）
echo http://TARGET | subjs
# 自動找到所有 JS 檔案並提取 URL

# gau（從多個來源抓歷史 URL）
gau TARGET_DOMAIN
# 從 Wayback Machine、Common Crawl 等抓歷史端點

# 瀏覽器開發者工具（最可靠）
# F12 → Network → 篩選 XHR/Fetch → 看實際 API 請求
# Sources → 找 bundle.js 或 main.js → 搜尋 /api/ 或 fetch(
```

---

## 方法五：參數枚舉

```bash
# 用 ffuf 枚舉 GET 參數名稱
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "http://TARGET/page?FUZZ=test" -fs BASELINE_SIZE
# 先不加 -fs 跑一次，找到正常回應的大小，再設 -fs 過濾

# POST 參數枚舉
ffuf -w burp-parameter-names.txt \
  -u http://TARGET/login \
  -X POST \
  -d "FUZZ=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fs BASELINE_SIZE
# -X POST → 使用 POST 方法
# -d → POST body（FUZZ 是佔位符）
# -H → 設定 header

# 用已知參數做值的枚舉
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt \
  -u "http://TARGET/page?file=FUZZ" -fs BASELINE_SIZE
```

---

## 降噪策略決策流程

```
開始爆破，先不加過濾
    ↓
觀察結果：大量結果都一樣大小/狀態？
    ├─ 是 → 加 -fs 或 -fc 過濾統一回應
    ├─ 全 200 相同大小 → SPA，改用 -fw 或關鍵字 -fr
    └─ 否（各種回應大小）→ 結果可信，繼續分析
    ↓
整理有效端點
    ├─ 200 → 可訪問的頁面/功能
    ├─ 301/302 → 追蹤重定向目標
    ├─ 401/403 → 需要認證的端點（有價值！）
    └─ 500 → 服務器錯誤（可能觸發漏洞）
```

---

## 速查表

```bash
# 快速目錄爆破（ffuf）
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://TARGET/FUZZ -mc 200,301,302,401

# 加副檔名
ffuf -w common.txt -u http://TARGET/FUZZ -e .php,.html,.txt,.bak -fc 404

# 過濾固定大小的假陽性
ffuf -w common.txt -u http://TARGET/FUZZ -fs 1234

# feroxbuster 遞迴爆破
feroxbuster -u http://TARGET -w raft-medium-directories.txt -x php,html

# JS 端點提取
python3 linkfinder.py -i http://TARGET -d -o cli

# robots.txt / sitemap
curl http://TARGET/robots.txt
curl http://TARGET/sitemap.xml

# 常用 wordlist 路徑
# /usr/share/seclists/Discovery/Web-Content/common.txt
# /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
# /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

---

## 關聯筆記

- [[34-Web架構基礎|第 34 章 - Web 架構基礎]]
- [[35A-應用程式探索與CMS列舉|第 35A 章 - 應用程式探索與 CMS 列舉]]
- [[36-Web請求分析|第 36 章 - Web 請求分析]]
- [[04-Volume-4-Web-Index|Vol.4 - Web Information Gathering and Attacks]]
