# 第 36 章 - Web 請求分析

## 標籤

- #cpts
- #chapter
- #web
- #http
- #requests

## 學習目標

- 能用 Burp Suite / curl 精準分析 HTTP 請求與回應。
- 知道如何識別關鍵參數（身份/控制/資料）並選擇測試策略。
- 理解 Method、Header、Cookie、Body 格式對漏洞的影響。
- 能從請求分析形成具體的漏洞測試假說。

---

## 理論基礎：請求語意分類

```
HTTP 請求 = 方法 + 路徑 + Header + Body
```

| 參數位置 | 類型 | 測試意義 |
|----------|------|----------|
| URL path `/user/123` | 資源識別 | IDOR：換 ID 看其他使用者 |
| Query `?page=2` | 控制/資料 | SQLi / LFI / Open Redirect |
| Header `Authorization:` | 身份 | Token 偽造 / JWT 攻擊 |
| Cookie `session=xxx` | 身份/狀態 | Session 劫持 / 操控 |
| POST body `role=user` | 資料/控制 | 質量賦值 / 權限繞過 |
| JSON `{"admin":false}` | 資料/控制 | 改 admin:true 試試 |

---

## 方法一：curl 分析請求

```bash
# 基本 GET 請求
curl -v http://TARGET/api/user/123
# -v → verbose，顯示完整請求和回應 header

# 帶 Cookie
curl -b "session=abc123" http://TARGET/profile
# -b → 設定 Cookie（-b "名稱=值"）

# 帶 Authorization Header（Bearer Token）
curl -H "Authorization: Bearer eyJhbGci..." http://TARGET/api/admin
# -H → 設定自訂 header

# POST 請求（form data）
curl -X POST http://TARGET/login \
  -d "username=admin&password=test123" \
  -v
# -X POST → HTTP 方法
# -d → POST body（x-www-form-urlencoded 格式）

# POST 請求（JSON）
curl -X POST http://TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test123"}' \
  -v
# -H "Content-Type: application/json" → 設定內容類型
# -d '{"json":"data"}' → JSON body

# 追蹤重定向
curl -L http://TARGET/login
# -L → follow redirect（追蹤 301/302）

# 忽略 TLS 錯誤
curl -k https://TARGET/api/
# -k → insecure（忽略憑證驗證）

# 儲存 Cookie 並重用
curl -c cookies.txt http://TARGET/login -d "user=admin&pass=test"
# -c cookies.txt → 儲存伺服器設定的 Cookie 到檔案
curl -b cookies.txt http://TARGET/profile
# -b cookies.txt → 從檔案讀取 Cookie 並發送
```

---

## 方法二：Burp Suite 工作流程

```
1. 設定 Proxy：瀏覽器 → HTTP Proxy → 127.0.0.1:8080
2. 瀏覽目標功能（登入/編輯/刪除）
3. Proxy → HTTP history → 找關鍵請求
4. 右鍵 → Send to Repeater（重複測試用）
5. 在 Repeater 修改參數 → 觀察回應差異

# Burp Repeater 核心操作
# 改參數值 → Send → 看 Response
# 改 Cookie → 測 session 固定或越權
# 改 role/admin 欄位 → 測質量賦值
# 改資源 ID → 測 IDOR
```

---

## 方法三：識別關鍵請求

```bash
# 用 curl 比對不同角色的回應差異
# 以一般使用者身份請求
curl -b "session=USER_SESSION" http://TARGET/api/users -v

# 以管理員身份請求
curl -b "session=ADMIN_SESSION" http://TARGET/api/users -v

# 比對兩個回應的差異：
# 1. 狀態碼（200 vs 403）
# 2. 回應內容（不同資料集）
# 3. 回應大小（不同數量）

# 測試 IDOR（換資源 ID）
curl -b "session=USER_SESSION" http://TARGET/api/user/123  # 自己的
curl -b "session=USER_SESSION" http://TARGET/api/user/124  # 別人的
# 若都回 200 且有資料 → IDOR

# 測試 HTTP Method 差異
curl -X GET http://TARGET/api/user/123
curl -X PUT http://TARGET/api/user/123 -d '{"email":"new@evil.com"}'
curl -X DELETE http://TARGET/api/user/123
# 注意：PUT/DELETE 可能需要 CSRF token 或特定 header
```

---

## 方法四：分析回應訊號

```bash
# 觀察 Set-Cookie（分析 Session 特性）
curl -I http://TARGET/login
# Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Lax
# HttpOnly → JS 無法讀取（防 XSS 竊 Cookie）
# Secure   → 只在 HTTPS 傳送
# SameSite=Strict/Lax → CSRF 保護
# 若缺少這些屬性 → 可能有安全風險

# 分析 CORS
curl -H "Origin: https://evil.com" http://TARGET/api/data -I
# 若回應有：
# Access-Control-Allow-Origin: https://evil.com → 可跨域讀取（看是否帶 cookie）
# Access-Control-Allow-Credentials: true → 跨域可帶身份（高危）
# Access-Control-Allow-Origin: * + Credentials: true → 瀏覽器會拒絕，但值得記錄

# 分析 Cache-Control
# Cache-Control: private → 不應被 proxy 快取
# Cache-Control: no-store → 不快取（含敏感資料）
# 若敏感 API 缺少 Cache-Control → 可能被中間代理快取

# 觀察錯誤回應差異（帳號列舉）
curl -d "user=admin&pass=wrong" http://TARGET/login
# "Invalid password" → 帳號存在但密碼錯（帳號列舉）
# "User not found"   → 帳號不存在
# 應該都回一樣的訊息（"Invalid credentials"）
```

---

## 參數測試決策流程

```
發現一個參數
    ↓
判斷參數類型
    ├─ 資源 ID（/user/123）→ 測 IDOR（換 ID）
    ├─ 控制參數（?page=2）→ SQLi / LFI / 路徑穿越
    ├─ 顯示內容（?name=John）→ XSS / SSTI
    ├─ 身份相關（token/role/admin）→ 質量賦值 / 越權
    └─ URL 跳轉（?redirect=）→ Open Redirect
    ↓
最小化改動驗證
    └─ 只改這一個參數，觀察回應差異
```

---

## 速查表

```bash
# 完整 verbose 請求
curl -v http://TARGET/api/endpoint

# 帶 Cookie
curl -b "session=TOKEN" http://TARGET/api/

# POST JSON
curl -X POST http://TARGET/api/ -H "Content-Type: application/json" -d '{"key":"value"}' -v

# 儲存 + 重用 Cookie
curl -c cookies.txt -d "user=a&pass=b" http://TARGET/login
curl -b cookies.txt http://TARGET/profile

# CORS 測試
curl -H "Origin: https://evil.com" http://TARGET/api/ -I

# 追蹤重定向
curl -L -v http://TARGET/redirect?url=http://evil.com

# Burp：選中請求 → Send to Repeater → 修改 → Send
```

---

## 關聯筆記

- [[35-Web列舉|第 35 章 - Web 列舉]]
- [[37-身分驗證攻擊|第 37 章 - 身分驗證攻擊]]
- [[38-SQL注入|第 38 章 - SQL 注入]]
- [[04-Volume-4-Web-Index|Vol.4 - Web Information Gathering and Attacks]]
