# 第 73B 章 - 有憑證 AD 列舉（Windows）

## 標籤

- #cpts
- #chapter
- #active-directory
- #enumeration
- #powerview
- #sharphound
- #bloodhound
- #snaffler

## 學習目標

- 用 ActiveDirectory PowerShell 模組列舉網域、使用者、群組、信任。
- 用 PowerView 做更深層的屬性查詢（巢狀成員、SPN、管理員存取測試）。
- 用 SharpView（.NET 版 PowerView）在受限環境中替代 PowerShell 工具。
- 用 Snaffler 自動掃描共用資料夾中的敏感檔案。
- 用 SharpHound + BloodHound 視覺化 ACL 攻擊路徑。

---

## 理論基礎

```text
Windows 端列舉的優勢：
  → 可直接使用 RSAT（AD PowerShell 模組）—— 無需上傳工具
  → 行為融入正常管理操作，相對隱蔽
  → PowerView 提供比 cmdlet 更細緻的屬性查詢
  → BloodHound 圖形化呈現 ACL 攻擊路徑，效率遠高於手動

取得 Windows 主機列舉位置的途徑：
  → 客戶提供的內部攻擊主機
  → 密碼噴灑/漏洞利用後拿到的域工作站
  → SYSTEM 權限的域機器（電腦帳號等同低權域帳號）
```

---

## 工具一：ActiveDirectory PowerShell 模組

### 理論

```text
AD PowerShell 模組（RSAT）包含 147 個 cmdlet。
需要先確認是否載入，否則需 Import-Module 匯入。
適合在安裝了 RSAT 的 Windows 主機上直接使用。
```

```powershell
# 確認已載入的模組列表
Get-Module
# ModuleType / Version / Name / ExportedCommands
# 若看不到 ActiveDirectory → 需手動匯入

# 匯入 AD 模組
Import-Module ActiveDirectory

# 確認匯入成功（Version 1.0.1.0 即為 AD 模組）
Get-Module
```

### 網域基本資訊

```powershell
Get-ADDomain
# 關鍵輸出欄位：
# DomainSID         → 網域 SID（RID cycling 需用）
# ChildDomains      → 子網域列表（信任攻擊目標）
# DomainMode        → 功能等級（Windows2016Domain 等）
# PDCEmulator       → 主 DC FQDN
# Forest            → 所屬森林名稱
# ReplicaDirectoryServers → 所有 DC 列表
```

### 使用者列舉（SPN 篩選 → Kerberoast 候選）

```powershell
# 篩選有 SPN 的帳號（Kerberoasting 攻擊前置）
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
# -Filter {ServicePrincipalName -ne "$null"} → LDAP filter 語法
# -Properties ServicePrincipalName           → 額外顯示 SPN 屬性
# 輸出：samaccountname / SID / SPN 內容（如 MSSQLSvc/DEV-SQL:1433）
```

### 信任關係列舉

```powershell
Get-ADTrust -Filter *
# -Filter * → 列出所有信任關係
# 關鍵輸出欄位：
# Direction       → BiDirectional / Inbound / Outbound
# IntraForest     → True = 森林內子網域信任 / False = 跨森林信任
# ForestTransitive → True = 跨森林可傳遞（重要攻擊面）
# Target          → 信任目標的網域名稱
# TrustType       → Uplevel（現代 AD）

# 範例解讀：
# LOGISTICS.INLANEFREIGHT.LOCAL → 同森林子網域，雙向
# FREIGHTLOGISTICS.LOCAL        → 跨森林，ForestTransitive=True → 可嘗試跨林攻擊
```

### 群組列舉

```powershell
# 列出所有群組名稱
Get-ADGroup -Filter * | Select-Object name
# 快速掃描重要群組名稱

# 查詢特定群組詳情
Get-ADGroup -Identity "Backup Operators"
# GroupCategory / GroupScope / SID

# 查詢群組成員
Get-ADGroupMember -Identity "Backup Operators"
# 輸出：distinguishedName / samaccountname / SID
# Backup Operators 成員 → 可備份 SAM 資料庫 → 可能導致 DA 提權
```

---

## 工具二：PowerView

### 理論

```text
PowerView 是 PowerSploit 套件的 AD 列舉模組（已棄用但仍有效）。
BC-Security 維護的 Empire 4 包含更新版本。
優勢：
  → 比 AD 模組更細緻的 LDAP 查詢
  → 支援巢狀群組遞迴成員查詢
  → 可測試本機管理員存取（Test-AdminAccess）
  → 可列出 SPN 帳號（Kerberoasting）
  → Find-DomainUserLocation 追蹤使用者登入位置
```

```powershell
# 載入 PowerView
cd C:\Tools
Import-Module .\PowerView.ps1
```

### 使用者詳細資訊查詢

```powershell
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local `
  | Select-Object -Property name,samaccountname,description,memberof,`
    whencreated,pwdlastset,lastlogontimestamp,accountexpires,`
    admincount,userprincipalname,serviceprincipalname,useraccountcontrol
# -Identity mmorgan     → 指定使用者（或用 -Filter）
# -Domain               → 指定網域（跨信任查詢時使用）
# 關鍵欄位：
# admincount: 1         → 曾是或現為高權帳號（AdminSDHolder 保護）
# memberof              → 所屬群組（巢狀列出）
# useraccountcontrol    → DONT_REQ_PREAUTH = ASREPRoastable
# pwdlastset            → 密碼最後設定時間（舊密碼 = 噴灑優先）
```

### 遞迴群組成員查詢（巢狀成員解析）

```powershell
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
# -Recurse → 遞迴解析巢狀群組
# 若 Secadmins 是 Domain Admins 的成員，-Recurse 會列出 Secadmins 的所有成員
# 輸出欄位：GroupName / MemberName / MemberDistinguishedName / MemberSID
# 用途：找出透過巢狀繼承 DA 權限的帳號
```

### 信任對應

```powershell
Get-DomainTrustMapping
# 列出所有可見的域信任（比 Get-ADTrust 更完整，包含子域視角）
# 輸出：SourceName / TargetName / TrustDirection / TrustAttributes
# WITHIN_FOREST   → 同森林內部信任
# FOREST_TRANSITIVE → 跨森林可傳遞信任
```

### 測試本機管理員存取

```powershell
Test-AdminAccess -ComputerName ACADEMY-EA-MS01
# 輸出：ComputerName / IsAdmin
# IsAdmin: True → 當前帳號是目標機的本機管理員
# → 可用 psexec / wmiexec / smbexec 取得 shell

# 批次測試（掃整個網段）
Get-DomainComputer | Select-Object dnshostname `
  | ForEach-Object { Test-AdminAccess -ComputerName $_.dnshostname }
# 找出所有可橫向移動的目標
```

### 尋找有 SPN 的使用者（Kerberoasting 候選）

```powershell
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
# -SPN → 篩選有 SPN 的帳號
# 常見 SPN 類型：
# MSSQLSvc/... → SQL Server 服務帳號
# adfsconnect/ → ADFS 帳號
# backupjob/   → 備份帳號
# 這些帳號可請求 TGS → 離線破解服務帳號密碼
```

### 其他常用函式

```powershell
# 列舉網域控制器
Get-DomainController
# 傳回所有 DC 的 IP / FQDN / OS 版本

# 尋找有趣的 ACL（修改權限設在非內建物件上）
Find-InterestingDomainAcl
# 用於發現 ACL 濫用路徑（如 GenericWrite / WriteDACL）

# 尋找使用者登入位置（追蹤特定帳號在哪台機器上）
Find-DomainUserLocation -UserName "svc_qualys"
# 用途：找到高權帳號登入的主機 → 橫向移動目標

# 尋找可存取的共用資料夾
Find-DomainShare
# 列出網域所有機器上可讀的共用資料夾

# 取得網域原則
Get-DomainPolicy
# 輸出 SystemAccess（密碼原則）和 KerberosPolicy（票證有效期）
```

---

## 工具三：SharpView（.NET 版 PowerView）

### 理論

```text
SharpView 是 PowerView 的 C# .NET 移植版。
適用場景：
  → 客戶環境限制 PowerShell 執行（AMSI / CLM / 語言模式限制）
  → 需要 .exe 形式的執行檔（LoLBins 情境）
語法與 PowerView 幾乎完全相同。
```

```powershell
# 查詢函式說明
.\SharpView.exe Get-DomainUser -Help
# 輸出所有可用參數（-Identity / -SPN / -AdminCount 等）

# 查詢特定使用者
.\SharpView.exe Get-DomainUser -Identity forend
# 輸出欄位與 PowerView 相同：
# samaccountname / memberof / pwdlastset / useraccountcontrol / badpwdcount

# 列出有 SPN 的帳號
.\SharpView.exe Get-DomainUser -SPN

# 遞迴群組成員
.\SharpView.exe Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

---

## 工具四：Snaffler（共用資料夾敏感檔案掃描）

### 理論

```text
Snaffler 自動化掃描域內所有可讀共用資料夾，尋找高價值檔案。
執行條件：需在已加域主機或有域帳號的情境下執行。
輸出顏色標記：
  Red   → 高優先（.key / .sqldump / .mdf / .keychain / .keypair）
  Black → 次優先（.kdb / .ppk / .kwallet / .psafe3 / .tblk）
  Green → 可存取的共用資料夾
```

```powershell
# 執行 Snaffler（標準模式）
.\Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
# -s → 將結果同時輸出到主控台
# -d inlanefreight.local → 目標網域（用於取得主機列表）
# -o snaffler.log        → 輸出到記錄檔（供後續分析）
# -v data                → 詳細度 = data（只顯示有價值的結果，過濾噪訊）

# 輸出解讀：
# [Share] {Green}(\\DC01\Department Shares)     → 可存取的共用
# [File]  {Red}<...>(\\DC01\IT\Infosec\key.key) → 高優先檔案
# 路徑格式：\\主機\共用\目錄\檔名

# 尋找高價值副檔名（Snaffler 自動涵蓋）：
# .key / .ppk / .keychain / .keypair → SSH / 加密金鑰
# .kdb / .kwallet / .psafe3          → 密碼管理器資料庫
# .sqldump / .mdf                    → 資料庫傾印 / SQL 資料庫
# web.config / *.bat / *.ps1         → 硬編碼憑證常見位置
```

---

## 工具五：BloodHound + SharpHound

### 理論

```text
BloodHound = 圖形化 AD 攻擊路徑分析工具（使用 Neo4j 圖形資料庫）
SharpHound = BloodHound 的資料收集器（.exe / .ps1）

SharpHound 收集的資料類型（-c All）：
  Group         → 群組成員資格（含巢狀）
  LocalAdmin    → 本機管理員關係
  GPOLocalGroup → GPO 設定的本機群組
  Session       → 使用者會話（登入哪台機器）
  LoggedOn      → 已登入使用者
  Trusts        → 信任關係
  ACL           → 物件存取控制清單（GenericWrite / WriteDACL 等）
  Container     → OU 結構
  ObjectProps   → 物件屬性（SPN / admincount 等）
  SPNTargets    → Kerberoasting 候選
```

```powershell
# 執行 SharpHound（收集所有資料）
.\SharpHound.exe -c All --zipfilename ILFREIGHT
# -c All        → 收集所有類別資料
# --zipfilename → 輸出壓縮檔名（自動加時間戳）
# 完成後產生：<timestamp>_ILFREIGHT.zip

# 其他常用選項
.\SharpHound.exe -c All --stealth
# --stealth → 隱蔽模式（優先使用 DCOnly，減少對工作站的查詢）

.\SharpHound.exe -c All -d FREIGHTLOGISTICS.LOCAL
# -d → 指定不同網域（跨信任收集）

.\SharpHound.exe -c All --searchforest
# --searchforest → 收集整個森林中所有可見網域
```

### BloodHound 操作流程

```text
1. 啟動 BloodHound GUI（MS01 上輸入 bloodhound）
2. 使用 neo4j 憑證登入（預設：neo4j / neo4j）
3. 點擊右側 "Upload Data" → 選擇 SharpHound 產生的 .zip
4. 等待所有 .json 上傳至 100%

常用內建查詢（Analysis 分頁）：
  Find Computers with Unsupported Operating Systems
  → 找出執行 Win7 / Server 2008 等過時 OS 的主機
  → 可能受 MS08-067 / EternalBlue 等舊漏洞影響

  Find Computers where Domain Users are Local Admin
  → 整個 Domain Users 群組有本機管理員權限
  → 任何帳號都可橫向移動到這些主機

  Shortest Paths to Domain Admins
  → 從當前帳號到 Domain Admins 的最短 ACL 路徑
  → 是識別 ACL 濫用路徑的核心查詢

  Find AS-REP Roastable Users
  → 無需預認證的帳號 → 可直接請求 AS-REP 做離線破解

  Find Kerberoastable Users with High Value Targets
  → SPN 帳號中擁有高權限者

自訂 Cypher 查詢（Raw Query 框）：
  # 找出所有可達 Domain Admin 的路徑
  MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
  RETURN p
  
  # 參考資源：https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
```

---

## 判斷邏輯

```
在 Windows 主機上有憑證
├── 先確認工具限制
│   ├── PowerShell 正常 → 用 AD 模組 / PowerView
│   └── PowerShell 受限 → 用 SharpView.exe
├── AD 模組快速掃描
│   ├── Get-ADDomain → 網域基本資訊 + 子域
│   ├── Get-ADTrust  → 信任關係（跨域攻擊面）
│   ├── Get-ADUser -Filter {SPN -ne null} → Kerberoast 候選
│   └── Get-ADGroupMember "Backup Operators" → 高權群組成員
├── PowerView 深度查詢
│   ├── Get-DomainGroupMember -Recurse → 解析巢狀群組
│   ├── Test-AdminAccess → 找可橫向移動的主機
│   ├── Find-DomainUserLocation → 追蹤高權帳號登入位置
│   └── Get-DomainUser -SPN → Kerberoast 列表
├── Snaffler → 掃共用資料夾敏感檔案
│   └── Red 標記檔案 → 優先下載分析
└── SharpHound + BloodHound → 視覺化 ACL 路徑
    ├── Shortest Paths to Domain Admins → 最快提權路徑
    ├── Find Local Admins → 橫向移動目標
    └── 自訂 Cypher → 精確查詢特定路徑
```

---

## 速查表

```powershell
# AD 模組
Import-Module ActiveDirectory
Get-ADDomain
Get-ADTrust -Filter *
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
Get-ADGroupMember -Identity "Backup Operators"

# PowerView
Import-Module .\PowerView.ps1
Get-DomainUser -Identity USER -Domain DOMAIN.LOCAL | Select-Object name,admincount,useraccountcontrol,memberof
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainTrustMapping
Test-AdminAccess -ComputerName TARGET_HOST
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

# SharpView（受限環境）
.\SharpView.exe Get-DomainUser -Identity USER
.\SharpView.exe Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Snaffler
.\Snaffler.exe -s -d DOMAIN.LOCAL -o snaffler.log -v data

# SharpHound
.\SharpHound.exe -c All --zipfilename OUTPUT
```

---

## 關聯筆記

- [[73-有憑證AD列舉|第 73 章 - 有憑證 AD 列舉（Linux）]]
- [[73A-密碼噴灑|第 73A 章 - 密碼噴灑]]
- [[75-Kerberos攻擊|第 75 章 - Kerberos 攻擊（Kerberoasting / ASREPRoasting）]]
- [[77-ADACL濫用|第 77 章 - AD ACL 濫用]]
- [[09-Volume-9-Active-Directory-Index|Vol.9 - Active Directory]]
