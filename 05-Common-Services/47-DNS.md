# 第 47 章 - DNS

## 標籤

- #cpts
- #chapter
- #dns
- #services

## 學習目標

- 從服務攻擊面角度評估 DNS：Zone Transfer、開放遞迴、版本洩漏。
- 能用 dig / nmap 驗證各類 DNS 風險。
- 理解遞迴解析器與權威伺服器的角色差異。
- 能區分資訊洩漏型與可濫用型 DNS 問題。

---

## 理論基礎

```text
DNS 服務角色：
  遞迴解析器 → 代替客戶端遞迴查詢，回傳最終結果
  權威伺服器 → 儲存並回應特定 Zone 的正式記錄

攻擊面：
  1. Zone Transfer（AXFR）→ 一次取得整個 Zone 的所有記錄
  2. Open Resolver     → 對任何來源提供遞迴服務 → 可用於 DDoS 放大
  3. 版本洩漏          → CHAOS class 查詢取得 BIND 版本
  4. Dynamic DNS Update → 若 ACL 設定不當，可惡意新增/修改記錄

DNS 回應 flags 判讀：
  AA（Authoritative Answer）→ 回應來自授權伺服器
  RA（Recursion Available） → 伺服器提供遞迴服務
  TC（Truncated）           → 訊息超過 UDP 限制，需改用 TCP
```

---

## 方法一：服務發現

```bash
# 掃描 DNS 服務
nmap -sU -sV -p 53 TARGET_IP
# -sU → UDP 掃描（DNS 主要用 UDP）
# -sV → 版本偵測

# TCP 53（Zone Transfer 需要 TCP）
nmap -sV -p 53 TARGET_IP

# NSE 腳本快速檢查
nmap --script dns-recursion,dns-zone-transfer \
  --script-args dns-zone-transfer.domain=TARGET_DOMAIN \
  -p 53 TARGET_IP
# dns-recursion      → 測試是否為 Open Resolver
# dns-zone-transfer  → 嘗試 AXFR Zone Transfer
```

---

## 方法二：Zone Transfer（AXFR）

```bash
# 先找目標的 NS 記錄（名稱伺服器）
dig NS TARGET_DOMAIN
# 例如回傳：ns1.target.com、ns2.target.com

# 對每個 NS 嘗試 AXFR
dig axfr TARGET_DOMAIN @ns1.TARGET_DOMAIN
# axfr → 全量區域傳送（All Zone File Records）
# @ns1... → 指定查詢的 DNS 伺服器
# 若成功 → 回傳整個 Zone 所有記錄（A、MX、CNAME、TXT...）

# 若 nslookup（Windows 友好）
nslookup -type=axfr TARGET_DOMAIN ns1.TARGET_DOMAIN

# 確認 AXFR 是否成功
dig axfr TARGET_DOMAIN @TARGET_IP | grep -v "^;"
# 去掉註解行，只看實際 DNS 記錄
# 若輸出很多行 → AXFR 成立 → 所有子域名、內部主機全部洩漏

# 自動列出所有 A 記錄（從 AXFR 結果）
dig axfr TARGET_DOMAIN @TARGET_IP | grep " A " | awk '{print $1, $5}'
```

---

## 方法三：版本資訊洩漏

```bash
# CHAOS class 查詢（BIND 版本字串）
dig version.bind chaos txt @TARGET_IP
# chaos → 特殊 DNS class，用於管理查詢
# txt   → TXT 記錄類型
# 若回傳 "9.11.3-1ubuntu1.13-Ubuntu" → 洩漏 BIND 版本
# 可用版本對應已知 CVE

# 也可查 hostname.bind
dig hostname.bind chaos txt @TARGET_IP
# 回傳 DNS 伺服器的 hostname

# id.server（另一個版本查詢方式）
dig id.server chaos txt @TARGET_IP
```

---

## 方法四：Open Resolver 測試

```bash
# 測試目標 DNS 是否對外提供遞迴服務
dig google.com @TARGET_IP
# 若回應 status: NOERROR 且含 A 記錄 → Open Resolver
# flags 中有 ra（recursion available）→ 確認

# 區分：
# 對自身 Zone 的遞迴 = 正常（RA 旗標存在但限制來源）
# 對任意外部 Domain 的遞迴 = Open Resolver（問題）

# nmap 腳本驗證
nmap --script dns-recursion -p 53 TARGET_IP
```

---

## 方法五：子域名暴力枚舉

```bash
# 若 AXFR 失敗，改用字典枚舉
# gobuster DNS 模式
gobuster dns \
  -d TARGET_DOMAIN \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 20
# -d → 目標 Domain
# -w → 子域名字典
# -t 20 → 20 執行緒

# dnsenum（組合多種 DNS 枚舉）
dnsenum --dnsserver TARGET_IP \
  --enum -p 0 -s 0 \
  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  TARGET_DOMAIN
# --enum → 全面列舉
# -p 0   → 不做反向查詢（節省時間）
# -s 0   → 不用搜尋引擎

# fierce（舊工具但仍常用）
fierce --domain TARGET_DOMAIN --dns-servers TARGET_IP
```

---

## 決策流程

```
nmap -p 53 確認 DNS 服務
    ↓
dig NS → 找名稱伺服器
    ↓
dig axfr @每個 NS → AXFR 成功？
  → 是：整個 Zone 洩漏 → 列所有子域名、內部主機
  → 否：gobuster dns 枚舉子域名
    ↓
dig version.bind chaos txt → 版本洩漏？
    ↓
dig google.com @TARGET → Open Resolver？
```

---

## 速查表

```bash
# NS 查詢
dig NS TARGET_DOMAIN

# Zone Transfer
dig axfr TARGET_DOMAIN @NS_IP

# 版本洩漏
dig version.bind chaos txt @TARGET_IP

# Open Resolver 測試
dig google.com @TARGET_IP

# 子域名枚舉
gobuster dns -d TARGET_DOMAIN \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# NSE 腳本
nmap --script dns-recursion,dns-zone-transfer -p 53 TARGET_IP
```

---

## 關聯筆記

- [[05-DNS區域傳送AXFR與IXFR|第 5 章 - DNS 區域傳送（AXFR／IXFR）]]
- [[05-Volume-5-Common-Services-Index|Vol.5 - Attacking Common Services]]
