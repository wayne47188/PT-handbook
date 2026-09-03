# 第 78E 章 - AD 強化與稽核

## 標籤

- #cpts
- #chapter
- #active-directory
- #hardening
- #audit
- #defense

## 學習目標

- 掌握 AD 強化的三大面向：人員、流程、技術，及其對應的 ATT&CK 控制措施。
- 理解 Protected Users 群組的保護機制與限制。
- 使用 AD Explorer、PingCastle、Group3r、ADRecon 進行 AD 稽核與報告產出。

---

## 理論基礎

```text
AD 強化核心原則：
  → 基準安全態勢 > 購買 EDR/SIEM 等額外工具
  → 只有先有文件化、日誌記錄、主機追蹤 → 額外工具才有效
  → 三大面向：人員（People）、流程（Process）、技術（Technology）

稽核目的：
  → 提供客戶修復問題所需的工具與資料
  → 讓報告更具說服力 → 獲得修復資金與管理層支持
```

---

## 一、文件化與稽核基礎

```text
每年（最好每季）必須稽核的項目：
  → OU、電腦、使用者、群組的命名慣例
  → DNS、網路、DHCP 設定
  → 所有 GPO 及其套用的物件
  → FSMO 角色的指派
  → 完整且最新的應用程式清單
  → 所有企業主機及其位置清單
  → 與其他 domain 或外部實體的所有信任關係
  → 擁有較高權限的使用者清單
```

---

## 二、人員面向強化

```text
人員是最薄弱的環節 → 即使環境再堅固，人員行為仍可造成漏洞

主要措施：
  → 強密碼原則 + 密碼篩選器（禁止 welcome/password/月份/公司名等常見詞）
  → 使用企業級密碼管理器
  → 定期輪換服務帳號密碼
  → 禁止使用者工作站上的本機管理員存取（除非有業務需求）
  → 停用預設 RID-500 本機 admin → 建立新帳號並受 LAPS 管理
  → 實施分層管理模型（管理帳號不用於日常工作）
  → 清理特權群組（DA/EA 成員越少越好）
  → 將帳號放入 Protected Users 群組（高風險帳號）
  → 為管理帳號停用 Kerberos 委派
```

### Protected Users 群組

```text
Protected Users 群組：
  → 最早出現於 Windows Server 2012 R2
  → 加入此群組的帳號受到額外 Kerberos/NTLM 限制

保護效果（DC 和裝置層級）：
  → 無法被委派（constrained 或 unconstrained）
  → CredSSP 不快取明文憑證（即使 GPO 允許）
  → Windows Digest 不快取明文密碼
  → 無法使用 NTLM 驗證
  → 無法使用 DES 或 RC4 金鑰（強制 AES）
  → TGT 取得後不快取長期金鑰或明文憑證
  → TGT 不可續訂超過 4 小時 TTL

注意：Protected Users 可能造成無法預見的驗證問題 → 必須分階段測試後再大規模部署
```

```powershell
# 查看 Protected Users 群組成員
Get-ADGroup -Identity "Protected Users" -Properties Name,Description,Members
# 輸出：
# Description  : Members of this group are afforded additional protections...
# Members      : {CN=sqlprod,..., CN=sqldev,...}
# SID          : S-1-5-21-...-525    ← 固定 RID 525
```

---

## 三、流程面向強化

```text
政策與程序項目：
  → 適當的 AD 資產管理政策與程序
  → AD 主機稽核、資產標籤、定期資產盤點（防止主機遺失）
  → 存取控制原則（帳號佈建/取消佈建）+ MFA 機制
  → 佈建和汰除主機的流程（基準強化指南、黃金映像檔）
  → AD 清理政策：
      → 前員工帳號移除或停用？
      → 移除過時記錄的流程？
      → 汰除舊作業系統/服務的流程（如遷移 O365 時正確解除安裝 Exchange）
  → 使用者、群組、主機的稽核排程
```

---

## 四、技術面向強化

```text
定期技術檢查項目：
  → 定期執行 BloodHound / PingCastle / Grouper → 識別設定錯誤
  → 確認管理員未在 AD 帳號描述欄位儲存密碼
  → 檢查 SYSVOL 腳本是否含有密碼或敏感資料
  → 盡量用 gMSA（群組管理服務帳號）取代一般服務帳號 → 降低 Kerberoasting 風險
  → 停用非約束性委派（Unconstrained Delegation）
  → 強化跳板機（Jump Host）→ 防止直接存取 DC
  → ms-DS-MachineAccountQuota 設為 0 → 禁止使用者新增機器帳號（防 noPac / RBCD）
  → 停用列印多工緩衝處理器服務（防 Printer Bug / SpoolSample 等攻擊）
  → 停用 DC 的 NTLM 驗證
  → 啟用 Extended Protection for Authentication（憑證服務相關）
  → 啟用 SMB 簽署（SMB Signing）+ LDAP 簽署（LDAP Signing）
  → 設定 RestrictNullSessAccess = 1 → 防止空會話列舉（null session enumeration）
  → 每季（至少每年）進行滲透測試/AD 安全評估
  → 測試備份有效性 + 演練災難復原計畫
```

---

## 五、按 TTP 分類的防護措施（ATT&CK 對照）

```text
┌────────────────────────┬──────────────┬────────────────────────────────────────────────────────────────┐
│ TTP                    │ MITRE 標籤   │ 防護重點                                                       │
├────────────────────────┼──────────────┼────────────────────────────────────────────────────────────────┤
│ External Recon         │ T1589        │ 清理文件元資料；職缺公告不透露技術細節                           │
│ Internal Recon         │ T1595        │ 監控異常封包爆量；NIDS；Windows 防火牆不回應 ICMP               │
│ Poisoning（LLMNR/NBT） │ T1557        │ 啟用 SMB 簽署；流量加密；停用 LLMNR/NBT-NS                     │
│ Password Spraying      │ T1110/003    │ 監控 Event ID 4624/4648；強密碼原則；帳號鎖定；MFA              │
│ Credentialed Enum      │ TA0006       │ 監控異常 AD 查詢行為；網路分段；Honeypot 帳號                   │
│ LOTL                   │ N/A          │ 建立正常行為基準；AppLocker；監控 PowerShell 殼層啟動           │
│ Kerberoasting          │ T1558/003    │ 強制 AES 加密；gMSA 取代服務帳號；強密碼；稽核過多群組成員     │
└────────────────────────┴──────────────┴────────────────────────────────────────────────────────────────┘
```

---

## 六、AD 稽核工具

### AD Explorer（快照與比較）

```text
AD Explorer（Sysinternals Suite）：
  → 進階 AD 檢視器和編輯器
  → 功能：瀏覽 AD 物件、檢視屬性、編輯權限、執行複雜搜尋
  → 快照功能：儲存 AD 資料庫快照 → 離線檢視 → 前後比較

使用場景：
  → 滲透測試後期：對 AD 快照以供離線分析
  → 比較評估前後的 AD 狀態（物件、屬性、安全權限變更）

快照操作：
  → 工具載入時輸入有效 domain 帳號登入
  → 瀏覽確認後 → File → Create Snapshot → 輸入快照名稱
  → 可將快照移至離線環境分析
```

### PingCastle（風險評估報告）

```text
PingCastle：
  → 評估 AD 環境安全態勢，產生風險報告
  → 使用 CMMI（能力成熟度模型整合）框架評分
  → 產生 HTML 報告 + 網域地圖
  → 涵蓋：漏洞易受性、共用資料夾、信任關係、委派、使用者/電腦狀態

注意：若啟動失敗 → 將系統日期調整為 2023-07-31 之前（試用版限制）

互動模式功能選項：
  1. healthcheck → 整體風險評估報告（預設）
  2. conso       → 整合多份報告
  3. carto       → 建立所有互連 domain 的地圖
  4. scanner     → 特定安全檢查（工作站、SMB、Zerologon 等）
  5. export      → 匯出使用者或電腦清單
  6. advanced    → 進階選項
```

```cmd
REM 呼叫 PingCastle（CMD 中執行）
PingCastle.exe

REM 查看說明
PingCastle.exe --help

REM 直接執行 healthcheck（非互動）
PingCastle.exe --server ACADEMY-EA-DC01

REM Scanner 選項（可在互動模式中選 4）
REM aclcheck / antivirus / laps_bitlocker / nullsession / smb / zerologon / spooler 等
```

```text
PingCastle Scanner 子選項（稽核用）：
  1-aclcheck        → 授權相關（Everyone/Authenticated Users/Domain Users 的 ACL）
  2-antivirus       → 防毒軟體狀態
  3-computerversion → 作業系統版本
  5-laps_bitlocker  → LAPS/BitLocker 部署狀態
  6-localadmin      → 本機管理員帳號
  7-nullsession     → 空會話存取
  c-smb             → SMB 設定
  e-spooler         → Printer Spooler 服務狀態
  g-zerologon       → Zerologon 漏洞
```

### Group3r（GPO 漏洞）

```text
Group3r：
  → 專門找 AD 群組原則（GPO）中的漏洞
  → 需在已加入 domain 的主機以 domain 使用者執行（不需管理員）
  → 或以 runas /netonly 方式執行

輸出格式（縮排層級）：
  → 第一層（無縮排）：GPO 名稱
  → 第二層（一次縮排）：原則設定
  → 第三層（二次縮排）：發現項目（感興趣的部分 + 原因說明）

用途：
  → 找出其他工具忽略的 GPO 漏洞
  → 提供連結到原則設定的發現方塊 + 定義感興趣部分 + 說明發現原因
```

```cmd
REM 執行 Group3r，輸出到檔案
group3r.exe -f results.log
REM -f results.log → 輸出到檔案（必須指定 -s 或 -f 其中一個）
REM -s             → 輸出到 stdout

REM 查看說明
group3r.exe -h
```

### ADRecon（全面資料蒐集）

```text
ADRecon：
  → 一次性從 AD 蒐集大量資料的全面工具
  → 輸出 HTML 報告 + CSV 資料夾
  → 涵蓋：Domain、Forest、Trusts、Sites、DC、Users、Groups、OUs、GPOs、DNS、Printers、Computers、LAPS、BitLocker 等

使用場景：
  → 非隱匿評估（會產生大量 LDAP 查詢）
  → 確保列舉未遺漏任何微小細節
  → 為客戶提供完整的 AD 資料基準

注意：
  → 需要 Excel 安裝才能自動產生 Excel 報告
  → 需要 GroupPolicy PowerShell 模組才能產生 GPO 報告
  → 可在另一台有 Excel 的主機用 -GenExcel 參數產生 Excel 報告
```

```powershell
# 執行 ADRecon（PowerShell）
.\ADRecon.ps1
# 執行約 11 分鐘 → 在當前目錄建立 ADRecon-Report-<timestamp> 資料夾

# 輸出結構：
# ADRecon-Report-20220328092458\
# ├── CSV-Files\          ← 各類 CSV（Users、Groups、Computers 等）
# ├── GPO-Report.html     ← GPO 視覺化報告
# └── GPO-Report.xml      ← GPO 原始資料

# 若需事後在有 Excel 的主機產生 Excel 報告
.\ADRecon.ps1 -GenExcel C:\Tools\ADRecon-Report-20220328092458
```

---

## 判斷邏輯

```
AD 強化與稽核需求
│
├── 人員強化
│   ├── 強密碼原則 + 密碼篩選器
│   ├── 清理 DA/EA 群組成員
│   ├── Protected Users 群組（高權限帳號）
│   │   └── Get-ADGroup "Protected Users" -Properties Members
│   └── 停用預設 RID-500 → LAPS 管理新 admin 帳號
│
├── 流程強化
│   ├── 帳號佈建/取消佈建政策
│   ├── 前員工帳號清理流程
│   └── 定期稽核排程（每季/每年）
│
├── 技術強化
│   ├── SMB 簽署 + LDAP 簽署
│   ├── ms-DS-MachineAccountQuota = 0
│   ├── 停用 Printer Spooler + 非約束性委派
│   ├── gMSA 取代服務帳號
│   └── RestrictNullSessAccess = 1
│
└── 稽核工具
    ├── AD Explorer → 快照 + 前後比較
    ├── PingCastle  → 風險評分報告（healthcheck）+ scanner
    ├── Group3r     → GPO 漏洞（-f output.log）
    └── ADRecon     → 全面資料蒐集（.\ADRecon.ps1）
```

---

## 速查表

```powershell
# Protected Users 群組查詢
Get-ADGroup -Identity "Protected Users" -Properties Name,Description,Members

# 查詢在 Protected Users 中的帳號
Get-ADGroupMember -Identity "Protected Users" | Select SamAccountName

# ms-DS-MachineAccountQuota 查詢與設定
Get-ADDomain | Select-Object ms-DS-MachineAccountQuota
# 設定為 0（禁止一般使用者新增機器帳號）
Set-ADDomain -Identity inlanefreight.local -Replace @{"ms-DS-MachineAccountQuota" = "0"}
```

```cmd
REM PingCastle
PingCastle.exe
PingCastle.exe --server ACADEMY-EA-DC01

REM Group3r
group3r.exe -f results.log
```

```powershell
# ADRecon
.\ADRecon.ps1
.\ADRecon.ps1 -GenExcel C:\Tools\ADRecon-Report-<timestamp>
```

---

## 關聯筆記

- [[78D-跨樹系攻擊Linux與BloodHound|第 78D 章 - 跨樹系攻擊 Linux 與 BloodHound]]
- [[79-ADCS|第 79 章 - ADCS]]
- [[09-Volume-9-Active-Directory-Index|Vol.9 - Active Directory]]
