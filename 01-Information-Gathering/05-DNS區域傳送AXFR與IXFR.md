# 第 5 章 - DNS 區域傳送（AXFR／IXFR）

## 標籤

- #cpts
- #chapter
- #dns
- #zonetransfer

## 學習目標

- 理解 AXFR 與 IXFR 在 DNS 管理中的原始用途。
- 掌握 Zone Transfer 的基本流程與權威伺服器角色。
- 辨識錯誤配置如何造成整個 Zone 外洩。
- 使用 `dig`、`host` 與常見工具驗證是否存在可行的 Zone Transfer。
- 正確整理結果、縮小誤判，並理解防禦與授權風險。

---

## 理論基礎

```text
Zone Transfer 的原始用途：
  主要 NS（Primary）→ 次要 NS（Secondary）之間同步 Zone 資料

  AXFR（Authoritative Transfer）→ 完整傳輸：把整個 Zone 一次給出
  IXFR（Incremental Transfer）→ 增量傳輸：只傳和上次序號相比的差異

真正的問題：
  設計上 Zone Transfer 只應給授權的次要 NS
  若 ACL 沒有正確設定 → 任何來源都能 AXFR
  一次 AXFR 可能取得：子網域、內部命名規則、郵件架構、SRV 記錄等

為何重要：
  成功 AXFR → 直接得到整個 Zone 的主機名稱清單
  比暴力列舉更完整、更準確、噪音更低
  是「高優先、低成本、不可依賴」的技術
    高優先 → 若成功，情報價值極高
    低成本 → 一個命令
    不可依賴 → 大多數現代環境已正確封鎖

Zone Transfer 使用 TCP/53（不是 UDP）
  → 某些環境允許 UDP/53 但封鎖 TCP/53 上的 AXFR
```

---

## 方法一：dig AXFR（最常用）

```bash
# Step 1：先找所有權威名稱伺服器
dig ns example.com +short
# +short → 只輸出 NS 主機名清單
# 輸出：ns1.example.com、ns2.example.com
# 重要：每台 NS 都要分別測試，不要只試一台

# Step 2：對每台 NS 嘗試 AXFR
dig axfr example.com @ns1.example.com
# axfr    → 請求完整區域傳送（AXFR 類型）
# @ns1.example.com → 直接向這台權威 NS 發出請求
# 成功輸出：大量 DNS 記錄（A、AAAA、CNAME、MX、TXT、SRV 等）
# 失敗輸出：Transfer failed（REFUSED 或無回應）

dig axfr example.com @ns2.example.com
# 換另一台 NS 試 → 可能不同 NS 的 ACL 設定不一樣

# 用 TCP 強制（AXFR 本就走 TCP，某些 dig 版本需要明確指定）
dig axfr example.com @ns1.example.com +tcp
# +tcp → 強制 TCP 連線（AXFR 預設就用 TCP，但明確加上無害）

# 確認失敗原因（看 status）
dig axfr example.com @ns1.example.com | head -5
# status: REFUSED  → ACL 封鎖（正確配置）
# Transfer failed  → 連線被切斷或逾時（可能是防火牆擋 TCP/53）
# status: SERVFAIL → NS 本身問題（不代表允許或拒絕 AXFR）
```

---

## 方法二：host -l（替代工具）

```bash
# 用 host 嘗試 Zone Transfer
host -l example.com ns1.example.com
# -l → list（列出 Zone 下所有記錄）
# example.com → 要查詢的 Zone
# ns1.example.com → 直接向這台 NS 查詢

# 成功：輸出所有主機名稱列表
# 失敗：Host example.com not found: 5(REFUSED)
```

---

## 方法三：nmap NSE（自動化驗證）

```bash
# Nmap 的 dns-zone-transfer 腳本自動嘗試 AXFR
nmap --script dns-zone-transfer -p 53 ns1.example.com
# --script dns-zone-transfer → 執行 Zone Transfer 測試腳本
# -p 53 → 指定 Port 53（DNS）
# 腳本自動嘗試 AXFR，回傳成功取得的記錄
```

---

## 方法四：整理 AXFR 結果

```bash
# AXFR 成功後，儲存完整輸出
dig axfr example.com @ns1.example.com > /tmp/zone_example.txt

# 取出所有 A record（主機 → IP）
grep " A " /tmp/zone_example.txt
# 格式：hostname.example.com. TTL IN A 1.2.3.4

# 取出所有主機名（不含 IP）
grep " A " /tmp/zone_example.txt | awk '{print $1}'
# awk '{print $1}' → 取第一欄（主機名稱）

# 取出高價值記錄類型
grep " A "   /tmp/zone_example.txt   # 主機 IP
grep " CNAME " /tmp/zone_example.txt # 別名（可能指向第三方）
grep " MX "  /tmp/zone_example.txt   # 郵件伺服器
grep " SRV " /tmp/zone_example.txt   # 服務記錄（AD/VoIP/Kerberos）
grep " TXT " /tmp/zone_example.txt   # 驗證記錄與第三方整合

# 把主機名清單交給 dnsx 解析驗證
grep " A " /tmp/zone_example.txt | awk '{print $1}' | \
  sed 's/\.$//g' > /tmp/hostnames.txt
# sed 's/\.$//g' → 移除末尾的點（FQDN 格式清理）

dnsx -l /tmp/hostnames.txt -a -resp -silent
# -l → 從清單讀取主機名
# -a → 查 A record
# -resp → 顯示解析到的 IP
# 確認哪些主機仍可解析（剔除殘留/歷史記錄）
```

---

## 決策流程

```
進入 DNS 偵察
    ↓
先找所有 Auth NS：dig ns DOMAIN +short
    ↓
對每台 NS 嘗試 AXFR：dig axfr DOMAIN @NS_IP
  成功取得記錄？
    是 → 儲存原始輸出 → 整理 A/CNAME/SRV 記錄 → dnsx 驗證存活
    否 REFUSED → 正確配置，繼續一般 DNS 列舉（第 9 章）
    否 超時 → 可能防火牆封 TCP/53；換 NS 再試
    ↓
AXFR 失敗（所有 NS 皆失敗）：
  → 切換到子網域列舉（Subfinder/Amass/dnsx）
  → CT Logs 補充（crt.sh）
  → 一般 DNS Enumeration 方法（第 9 章）
```

---

## 速查表

```bash
# Step 1：找所有 Auth NS
dig ns example.com +short

# Step 2：逐台嘗試 AXFR
dig axfr example.com @ns1.example.com
dig axfr example.com @ns2.example.com

# 用 host 嘗試
host -l example.com ns1.example.com

# Nmap NSE
nmap --script dns-zone-transfer -p 53 ns1.example.com

# 整理 AXFR 結果
grep " A " zone.txt | awk '{print $1}' | sed 's/\.$//g' > hostnames.txt
dnsx -l hostnames.txt -a -resp -silent
```

---

## 常見錯誤與排查

- 只測一台 NS 就放棄 → 每台 NS 的 ACL 設定可能不同，要逐一測試。
- 把 `Transfer failed` 和 `REFUSED` 混為一談 → REFUSED 是 ACL 拒絕，連線失敗可能是 TCP/53 被防火牆封鎖。
- AXFR 成功後不驗證記錄是否仍活躍 → Zone 中可能含有殘留/歷史記錄，要用 dnsx 確認可解析性。
- 忽略 SRV 記錄 → SRV 常揭露 AD、Kerberos、VoIP 等內部服務命名規則。
- 沒保存原始輸出 → 考試/報告時要保留原始 AXFR 輸出作為證據。

---

## 關聯筆記

- [[04-DNS架構與解析流程|第 4 章 - DNS 架構與解析流程]]
- [[06-DNS記錄深度解析|第 6 章 - DNS Record 深度解析]]
- [[09-DNS列舉方法論|第 9 章 - DNS 列舉方法論]]
- [[15-dnsx|第 15 章 - dnsx]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
