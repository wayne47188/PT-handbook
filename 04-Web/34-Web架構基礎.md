# 第 34 章 - Web 架構基礎

## 標籤

- #cpts
- #chapter
- #web
- #architecture

## 學習目標

- 能快速識別目標 Web 架構的分層（代理/應用/API/身份）。
- 知道如何用 curl、whatweb、httpx 收集技術指紋。
- 理解 HTTP header 對攻擊測試的指示意義。
- 能從架構判斷後續重點測試方向。

---

## 理論基礎：Web 分層架構

```
Browser → CDN/WAF/Load Balancer → Reverse Proxy (nginx/Apache) → App Server → DB/Cache
                                                                ↕
                                                          Identity/SSO
```

| 層次 | 識別線索 | 攻擊測試意義 |
|------|----------|-------------|
| CDN/WAF | Cloudflare/Akamai header、HTTP 回應延遲異常 | Payload 可能被過濾，需繞過或測真實 IP |
| Reverse Proxy | `Via`、`X-Forwarded-For`、`Server: nginx` | 注意路由差異、Header 注入 |
| App Server | `X-Powered-By`、Cookie 格式、錯誤訊息 | 決定漏洞類型（PHP/Java/Node） |
| API Layer | `/api/`、`/v1/`、JSON 回應、Swagger | API 端點、授權機制是重點 |
| 身份系統 | OAuth redirect、SAML、JWT cookie | Token 流、session 管理漏洞 |

---

## 方法一：HTTP Header 分析

```bash
# 取得 HTTP Header（快速指紋）
curl -I http://TARGET
# -I → 只顯示 response header（HEAD 請求）

curl -i http://TARGET
# -i → 顯示 header + body（GET 請求）

# HTTPS 忽略憑證錯誤
curl -sk https://TARGET -I
# -s → silent（不顯示進度）
# -k → 忽略 TLS 憑證驗證

# 分析關鍵 header
# Server: Apache/2.4.51 → 版本（查 CVE）
# X-Powered-By: PHP/7.4.3 → 語言/框架
# Set-Cookie: PHPSESSID=... → PHP 應用
# Set-Cookie: JSESSIONID=... → Java/Tomcat
# X-Forwarded-For: ... → 反向代理
# Via: ... → CDN/Proxy 層
# CF-RAY: ... → Cloudflare
# X-AspNet-Version: ... → ASP.NET
```

---

## 方法二：技術指紋識別

```bash
# whatweb - 自動識別技術棧
whatweb http://TARGET
# 輸出：CMS、框架、伺服器、jQuery 版本、語言等
# 範例輸出：WordPress[5.8], PHP[7.4.3], Apache[2.4.51]

# 詳細輸出（加 -v）
whatweb -v http://TARGET
# -v → verbose，顯示每個插件的詳細結果

# 掃描多個目標
whatweb -i targets.txt --log-brief=results.txt
# -i targets.txt → 從檔案讀取目標列表
# --log-brief=results.txt → 輸出到檔案

# httpx - 批次探測（適合大量主機）
echo "http://TARGET" | httpx -title -tech-detect -status-code
# -title       → 顯示頁面 title
# -tech-detect → 技術棧識別（類似 whatweb）
# -status-code → 顯示 HTTP 狀態碼

# 從列表批次處理
httpx -l targets.txt -title -tech-detect -status-code -o httpx_results.txt
# -l → 輸入列表
# -o → 輸出到檔案
```

---

## 方法三：架構探測

```bash
# 找真實 IP（繞過 CDN）
# 查 DNS history
host TARGET
nslookup TARGET
# 若有 CDN，真實 IP 可能在 SecurityTrails/Shodan/Censys 歷史記錄

# 測試直接 IP 存取
curl -H "Host: TARGET_DOMAIN" http://REAL_IP
# -H "Host: ..." → 手動設定 Host header
# 若 CDN 後方伺服器接受直接 IP 存取，代表繞過 CDN

# 判斷 WAF（觀察異常 payload 回應）
curl -I "http://TARGET/?q=<script>alert(1)</script>"
# 若返回 403/406/444 且 body 有 WAF 廠商訊息 → 有 WAF

# CORS 設定探測
curl -H "Origin: https://evil.com" -I http://TARGET/api/
# 看回應是否有：
# Access-Control-Allow-Origin: * → 全開（注意 CORS 漏洞）
# Access-Control-Allow-Credentials: true → 帶 cookie 跨域（高風險）

# 測試 HTTP 方法支援
curl -X OPTIONS http://TARGET -I
# 看 Allow header：允許哪些方法（PUT/DELETE 可能有漏洞）
```

---

## 方法四：架構判斷與測試方向

```bash
# 判斷應用類型
# 看 URL 格式
# /index.php?page=   → PHP 傳統應用（可能有 LFI/SQLi）
# /api/v1/users      → REST API（測授權、IDOR）
# /app/#/dashboard   → SPA（注意 JS 分析、API 端點）
# /?redirect_to=     → 可能有 Open Redirect

# 找 API 端點線索
curl http://TARGET/api/ -I
curl http://TARGET/swagger.json 2>/dev/null | jq .
curl http://TARGET/openapi.json 2>/dev/null | jq .
# swagger.json / openapi.json → API 文件（直接列出所有端點）

# 看 Robots.txt
curl http://TARGET/robots.txt
# Disallow 的路徑通常是管理面或敏感目錄

# 看 sitemap
curl http://TARGET/sitemap.xml
# 列出網站所有頁面（有時包含管理路徑）
```

---

## 架構 → 測試方向對照

| 發現 | 後續重點 |
|------|----------|
| PHP + 參數化 URL | SQLi、LFI/RFI、命令注入 |
| Java/Tomcat | 反序列化、管理面（/manager）、Ghostcat |
| Node.js | Prototype Pollution、SSRF、NoSQLi |
| WordPress | WPScan、外掛漏洞、XML-RPC |
| SPA + `/api/` | JWT 分析、IDOR、CORS、API 授權 |
| Nginx 反向代理 | 路徑混淆（path traversal via alias）|
| Swagger/OpenAPI | 完整 API 端點清單，一一測授權 |

---

## 速查表

```bash
# Header 指紋
curl -I http://TARGET
curl -sk https://TARGET -I

# 技術棧識別
whatweb http://TARGET
echo http://TARGET | httpx -title -tech-detect -status-code

# API 文件
curl http://TARGET/swagger.json | jq .
curl http://TARGET/openapi.json | jq .

# 基礎探測
curl http://TARGET/robots.txt
curl http://TARGET/sitemap.xml
curl -X OPTIONS http://TARGET -I

# CORS 測試
curl -H "Origin: https://evil.com" -I http://TARGET/api/
```

---

## 關聯筆記

- [[35-Web列舉|第 35 章 - Web 列舉]]
- [[36-Web請求分析|第 36 章 - Web 請求分析]]
- [[35A-應用程式探索與CMS列舉|第 35A 章 - 應用程式探索與 CMS 列舉]]
- [[04-Volume-4-Web-Index|Vol.4 - Web Information Gathering and Attacks]]
