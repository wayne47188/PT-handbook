# 第 49 章 - SNMP

## 標籤

- #cpts
- #chapter
- #snmp
- #udp
- #services

## 學習目標

- 理解 SNMP community string 與版本差異的安全影響。
- 能用 onesixtyone 暴力破解 community string。
- 能用 snmpwalk / snmpbulkwalk 列舉系統資訊、介面、路由與帳號。
- 能從 OID 資訊推導主機角色與網段拓撲。

---

## 理論基礎

```text
SNMP（Simple Network Management Protocol）：
  用於網路設備監控與管理（路由器、交換機、伺服器、印表機）
  Port: 161/udp（read/write）、162/udp（trap，設備主動通知管理站）

版本差異：
  SNMPv1  → community string 明文，無認證
  SNMPv2c → community string 明文，效能改善（bulk query）
  SNMPv3  → 有認證與加密，較安全

Community String（v1/v2c 的「密碼」）：
  read-only：public（常見預設值）
  read-write：private（改這個可寫入設備設定）

OID 重要路徑：
  1.3.6.1.2.1.1        → System（主機名、描述、聯絡資訊）
  1.3.6.1.2.1.2        → Interfaces（網路介面、IP）
  1.3.6.1.2.1.4.34     → IP 位址表
  1.3.6.1.2.1.6.13     → TCP 連線表（哪些 port 正在監聽）
  1.3.6.1.4.1.77.1.2.25 → Windows 本機使用者帳號（UserAccounts MIB）
  1.3.6.1.2.1.25.4.2   → 執行中的程序
  1.3.6.1.2.1.25.6.3   → 已安裝的軟體
```

---

## 方法一：服務發現

```bash
# UDP 掃描 SNMP（nmap 需 -sU）
nmap -sU -p 161 -sV TARGET_IP
# -sU → UDP 掃描（SNMP 主要用 UDP）
# -sV → 版本偵測

# 全範圍 UDP 掃描找 SNMP（較慢）
nmap -sU --open -p 161 SUBNET/24
# --open → 只顯示開放埠

# NSE 腳本
nmap -sU --script snmp-info,snmp-interfaces,snmp-sysdescr -p 161 TARGET_IP
# snmp-info       → 系統基本資訊
# snmp-interfaces → 網路介面列表
# snmp-sysdescr   → 系統描述字串
```

---

## 方法二：Community String 枚舉

```bash
# onesixtyone：快速暴力破解 community string
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt TARGET_IP
# -c → community string 字典（SecLists 有專用列表）
# 成功時輸出：TARGET_IP [community_string] system description...

# 常見字典
# /usr/share/seclists/Discovery/SNMP/snmp.txt
# /usr/share/wordlists/metasploit/snmp_default_pass.txt

# 手動試常見 community
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.1
# 若回傳資料 → public community 有效

snmpwalk -v2c -c private TARGET_IP 1.3.6.1.2.1.1
# 試 private（read-write community）

# 試多個目標（網段掃描）
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt \
  -i targets.txt
# -i → 目標 IP 列表檔案
```

---

## 方法三：snmpwalk 系統資訊列舉

```bash
# 列舉所有 OID（完整資訊，輸出可能很多）
snmpwalk -v2c -c COMMUNITY TARGET_IP
# -v2c → 使用 SNMPv2c
# -c   → community string

# 只看系統基本資訊（OID 1.3.6.1.2.1.1）
snmpwalk -v2c -c COMMUNITY TARGET_IP 1.3.6.1.2.1.1
# 回傳：sysDescr（OS 版本）、sysName（主機名）、sysContact（聯絡人）

# 網路介面與 IP
snmpwalk -v2c -c COMMUNITY TARGET_IP 1.3.6.1.2.1.2
# 回傳介面名稱、狀態、速度

snmpwalk -v2c -c COMMUNITY TARGET_IP 1.3.6.1.2.1.4.34
# IP 位址表（找到額外網段/介面 IP）

# 執行中的程序
snmpwalk -v2c -c COMMUNITY TARGET_IP 1.3.6.1.2.1.25.4.2
# 回傳所有執行中程序名稱與命令列參數（可能包含密碼！）

# 已安裝軟體
snmpwalk -v2c -c COMMUNITY TARGET_IP 1.3.6.1.2.1.25.6.3
# 回傳安裝的軟體清單（找版本 → 對應 CVE）

# Windows 本機帳號
snmpwalk -v2c -c COMMUNITY TARGET_IP 1.3.6.1.4.1.77.1.2.25
# 回傳本機使用者帳號名稱
```

---

## 方法四：snmpbulkwalk（更快速）

```bash
# snmpbulkwalk 使用 GETBULK（v2c 特性），比 snmpwalk 更快
snmpbulkwalk -v2c -c COMMUNITY -Cn0 -Cr10 TARGET_IP 1.3.6.1.2.1
# -Cn0  → 非重複次數設 0
# -Cr10 → 每次 bulk 請求取 10 個 OID

# 實用 MIB 轉換（顯示可讀名稱而非 OID 數字）
snmpwalk -v2c -c COMMUNITY -m ALL TARGET_IP
# -m ALL → 載入所有 MIB 定義（需要安裝 snmp-mibs-downloader）
# 先執行：sudo apt install snmp-mibs-downloader
```

---

## 方法五：snmpset（寫入測試，若有 read-write community）

```bash
# 若 private community 有效且有寫入權限
# 修改系統聯絡資訊（低影響驗證）
snmpset -v2c -c private TARGET_IP \
  1.3.6.1.2.1.1.4.0 s "test@test.com"
# 1.3.6.1.2.1.1.4.0 → sysContact OID
# s → 字串類型
# 若成功 → read-write 權限確認（可進一步測試設備設定修改）
```

---

## 決策流程

```
nmap -sU -p 161 確認 SNMP 服務
    ↓
onesixtyone + community 字典 → 找有效 community
    ↓
snmpwalk -v2c -c COMMUNITY → 列舉系統資訊
    ↓
重點 OID：
  1.3.6.1.2.1.1     → 主機名/OS/聯絡人
  1.3.6.1.2.1.4.34  → IP/網段（找內網拓撲）
  1.3.6.1.2.1.25.4.2 → 執行程序（找密碼）
  1.3.6.1.4.1.77... → Windows 帳號（找使用者）
    ↓
有 private community？
  → snmpset 測試寫入能力
```

---

## 速查表

```bash
# 服務掃描
nmap -sU -p 161 -sV TARGET_IP

# Community 枚舉
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt TARGET_IP

# 完整資訊列舉
snmpwalk -v2c -c public TARGET_IP

# 系統資訊
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.1

# 程序清單（找密碼）
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.25.4.2

# Windows 帳號
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.4.1.77.1.2.25

# IP/介面資訊
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.4.34
```

---

## 關聯筆記

- [[19-UDP掃描深度解析|第 19 章 - UDP 掃描深度解析]]
- [[05-Volume-5-Common-Services-Index|Vol.5 - Attacking Common Services]]
