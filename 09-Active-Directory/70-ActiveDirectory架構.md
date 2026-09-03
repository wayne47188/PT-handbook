# 第 70 章 - Active Directory 架構

## 標籤

- #cpts
- #chapter
- #active-directory
- #architecture

## 學習目標

- 理解 AD 的核心元件與信任邊界。
- 能區分 Domain、Forest、OU、Trust、DC、GPO 等角色。
- 知道 AD 架構如何影響枚舉、攻擊路徑與權限邏輯。
- 將服務、身分與管理層放回整體網域設計判讀。
- 避免把 AD 當作單一服務而非整體身份平台。

---

## 理論基礎

```text
Active Directory 不是一台主機或一個埠，
而是一套身份、授權、政策與資源管理架構。

AD 的核心元件（由外而內）：

  Forest（森林）
  → AD 最高層邊界，包含一或多個 Domain
  → 同一 Forest 內的 Domain 預設有雙向信任
  → Schema（物件定義）在 Forest 層級共用

  Domain（網域）
  → 管理與身份的基本邊界
  → 包含：使用者、群組、電腦、OU、GPO、DC
  → 跨 Domain 存取需要 Trust

  Domain Controller（DC）
  → 負責認證（Kerberos / NTLM）
  → 存放目錄資料（LDAP）
  → 同步複製至同 Domain 的其他 DC

  OU（Organization Unit）
  → 管理委派的最小單位
  → GPO 綁定在 OU 層級
  → 攻擊者視角：誰能修改這個 OU 的 GPO？

  GPO（Group Policy Object）
  → 設定下發機制（登入腳本、軟體部署、安全性設定）
  → 攻擊者視角：若我能修改某 OU 的 GPO → 影響所有該 OU 內的帳號/主機

  Trust（信任關係）
  → 允許跨 Domain / Forest 身份驗證
  → 單向或雙向，可傳遞或不可傳遞
  → 攻擊者視角：外部 Forest Trust 是橫向移動的潛在路徑

AD 攻擊之所以高價值：
  → 這些元件之間存在可被濫用的控制鏈
  → 取得一個低權帳號 → 可能沿著 OU/GPO/ACL 路徑達到 Domain Admin
  → 攻擊者看的是整條控制鏈，不是單一主機

關鍵協定：
  Kerberos → 預設 AD 認證協定（port 88）
  LDAP     → 目錄查詢（port 389 / 636 LDAPS）
  SMB      → 資源存取、RPC（port 445）
  DNS      → AD 服務探索依賴 DNS（port 53）
  RPC      → 管理介面、複製
```

---

## 核心元件枚舉

```bash
# ===== 確認 Domain 資訊（從任何已加域 Windows 主機）=====
net user /domain            # 列出網域使用者
# /domain → 查詢 DC 而非本機 SAM
net group /domain           # 列出網域群組
net group "Domain Admins" /domain  # 查看 Domain Admins 成員

# ===== DC 定位 =====
nltest /dclist:<domain>     # 列出指定網域的所有 DC
# 範例：nltest /dclist:corp.local
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>
# SRV 記錄 → DNS 中 DC 的服務發現機制

# ===== 網域基礎資訊 =====
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
# PowerShell：取得當前 Domain 物件（Forest / DC / DomainMode 等）

# ===== Forest 與 Trust 查詢 =====
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
# 列出所有 Trust 關係，包含方向與類型

# ===== OU 枚舉（LDAP 查詢）=====
([adsisearcher]"(objectCategory=organizationalUnit)").FindAll() | Select-Object -ExpandProperty Path
# objectCategory=organizationalUnit → 只搜尋 OU 物件

# ===== GPO 枚舉 =====
Get-GPO -All | Select-Object DisplayName, GpoStatus, Id
# Get-GPO → GroupPolicy PowerShell 模組（需要 RSAT 或在 DC 上執行）
# 確認哪些 GPO 存在 → 接著查詢 GPO 的 ACL

# ===== 無憑證時的 LDAP 匿名查詢嘗試 =====
ldapsearch -H ldap://DC_IP -x -b "DC=corp,DC=local" "(objectClass=*)" | head -50
# -H → 目標 DC    -x → 簡單認證（匿名）
# -b → Search Base（從哪個 OU 開始搜）
# 若匿名 LDAP 可查 → 大量 AD 資訊直接可讀
```

---

## 攻擊路徑思維框架

```text
攻擊者視角的 AD 架構優先排序：

1. 誰是 Domain Admin / Enterprise Admin？
   → 這些帳號是最終目標
   → 從任何視角枚舉這些群組的成員

2. 哪些帳號有高權委派？
   → 「AdminTo」「HasSession」「MemberOf」關係
   → BloodHound 用圖化方式顯示

3. 哪些主機有高權 Session？
   → 管理員在哪台機器登入了？
   → 若我控制了那台機器，可以 dump 快取憑證

4. OU/GPO 控制誰？
   → 若我能修改某 OU 的 GPO
   → 可以把惡意腳本下發到該 OU 的所有主機

5. Trust 指向哪裡？
   → 若有 External Trust，是否可利用？
   → SID History 攻擊（跨 Forest Trust）

BloodHound 的本質：
  → 把以上所有關係圖化，讓攻擊者能看到最短路徑
  → 「從 userX 到 Domain Admin 需要幾步」
  → python3 bloodhound.py -u <user> -p <pass> -d <domain> -c all --zip
  #  -c all → 收集 Users / Groups / Computers / ACLs / Sessions / Trusts
  #  --zip  → 壓縮成單一 .zip 上傳 BloodHound GUI
```

---

## 決策流程

```
進入 AD 環境（取得任何網域帳號）
    ↓
確認基礎架構
  Domain 名稱、Forest 邊界、DC IP
  net user /domain / nltest /dclist
    ↓
枚舉高價值群組
  Domain Admins / Enterprise Admins / Backup Operators
  net group "Domain Admins" /domain
    ↓
執行 BloodHound 收集（全面關係圖）
  python3 bloodhound.py -c all → 取得 ACL / Session / Trust 地圖
    ↓
分析攻擊路徑
  ShortestPath to Domain Admins
  Kerberoastable 帳號（SPN 存在）
  AS-REP Roastable 帳號（不需預認證）
  ACL 可控制的高權物件
    ↓
選擇最短可行路徑 → 最小化驗證 → 記錄 finding
```

---

## 速查表

```bash
# 網域基礎確認
net user /domain                           # 網域使用者
net group "Domain Admins" /domain          # DA 成員
nltest /dclist:<domain>                    # DC 清單

# BloodHound 蒐集（最快取得完整 AD 地圖）
python3 bloodhound.py -u <user> -p <pass> -d <domain> -c all --zip
# -c all → 收集所有類型關係   --zip → 壓縮上傳

# LDAP 匿名測試
ldapsearch -H ldap://<DC_IP> -x -b "DC=corp,DC=local" "(objectClass=*)" | head -20

# PowerShell Trust 查詢
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

# 架構層次速記
# Forest → Domain → DC → OU → GPO → 控制鏈
# Trust → 跨 Domain/Forest 的身份路徑
```

---

## 常見錯誤與排查

- 把 AD 等同於 LDAP 或 Kerberos → AD 是架構，LDAP/Kerberos/SMB 是它用的協定。
- 不看 OU/GPO，只看帳號群組 → GPO 委派常是橫向與提升的關鍵路徑。
- 忽略 Trust 對橫向與提升的意義 → 跨 Forest Trust 常被低估，但可能有 SID History 濫用。
- 只盯 DC，忽略管理委派結構 → 攻擊者看的是整條控制鏈，不只是 DC。

---

## 關聯筆記

- [[71-AD驗證|第 71 章 - AD 驗證]]
- [[72-無憑證AD列舉|第 72 章 - 無憑證 AD 列舉]]
- [[73-有憑證AD列舉|第 73 章 - 有憑證 AD 列舉]]
- [[75-Kerberos攻擊|第 75 章 - Kerberos 攻擊]]
- [[09-Volume-9-Active-Directory-Index|Vol.9 - Active Directory Enumeration and Attacks]]
