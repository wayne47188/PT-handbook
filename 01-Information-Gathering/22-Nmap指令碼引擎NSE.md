# 第 22 章 - Nmap 指令碼引擎（NSE）

## 標籤

- #cpts
- #chapter
- #nmap
- #nse

## 學習目標

- 理解 NSE 的定位、分類與風險差異。
- 熟悉 `-sC`、`--script`、`--script-args` 的基本使用方式。
- 知道 default、safe、discovery、auth、brute、vuln、intrusive 等腳本分類含義。
- 能閱讀 `--script-help` 與原始腳本說明，避免誤用。
- 避免把 NSE 輸出直接當成已驗證漏洞。

---

## 理論基礎

```text
NSE 定位：Nmap 的腳本執行框架

功能：對已發現服務做進一步的應用層互動
  - 協定特定資訊蒐集（SMB / HTTP / DNS / SNMP 等）
  - 配置驗證（是否支援匿名存取、弱加密）
  - 服務版本補充識別
  - 特定弱點指紋檢查（不等於已驗證漏洞）

腳本分類（重要！風險不同）：
  safe       → 幾乎不改變目標狀態，低風險
  default    → 預設集（-sC），主要是 safe + 部分 discovery
  discovery  → 主動蒐集更多資訊（目錄、主機名稱等）
  auth       → 測試認證（匿名存取、預設帳密）
  brute      → 暴力破解認證（高互動、留大量日誌）
  vuln       → 漏洞指紋偵測（不是已驗證漏洞）
  intrusive  → 高風險，可能造成服務不穩或觸發告警
  exploit    → 主動利用（幾乎不在 recon 階段使用）

關鍵原則：
  使用前必須理解腳本做了什麼
  brute/intrusive/exploit 需要明確授權才能使用
  vuln 類結果是線索，不是最終漏洞證明
  -sC（預設腳本）方便但不等於無害，仍應了解其行為
```

---

## 基本使用

```bash
# 執行預設腳本集合
nmap -sC 192.168.1.1
# -sC → 等同 --script=default，執行標記為 default 的腳本集合
# 包含許多 safe 腳本：http-title, ssh-auth-methods, smb-os-discovery 等
# 注意：-sC 不等於完全安全；仍需了解在特定環境的行為

# 明確指定腳本分類（更可控）
nmap --script safe 192.168.1.1
nmap --script "default and safe" 192.168.1.1
# 可用布林邏輯組合分類：and / or / not

# 對特定服務執行特定腳本
nmap --script smb-os-discovery -p 445 192.168.1.1
# smb-os-discovery → 從 SMB 協定取得 OS 版本、電腦名稱、網域
# 比 OS detection (-O) 更可信（SMB 自報資訊）

nmap --script http-title -p 80,443 192.168.1.1
# http-title → 抓取 HTTP 頁面標題
# 比 httpx -title 更適合嵌入 Nmap 掃描流程中

nmap --script ssl-cert -p 443 192.168.1.1
# ssl-cert → 提取 TLS/SSL 憑證資訊（CN, SAN, 有效期）
# 適合：識別服務名稱、CDN、發現相關主機名稱

# 傳遞腳本參數
nmap --script http-brute --script-args http-brute.path=/login -p 80 192.168.1.1
# --script-args → 傳遞 key=value 參數給腳本
# 執行前必須用 --script-help 確認參數意義
```

---

## 查看腳本說明（必做）

```bash
# 查看腳本說明（執行前一定要看）
nmap --script-help smb-os-discovery
# 顯示：腳本功能描述、分類、參數說明、輸出範例
# 看清楚：這個腳本做什麼？有沒有寫入/修改動作？需要什麼條件？

nmap --script-help "http-*"
# 列出所有 http 相關腳本的說明（* 萬用字元）

# 搜尋腳本（在 /usr/share/nmap/scripts/ 目錄）
ls /usr/share/nmap/scripts/ | grep smb
# 列出所有 smb 相關腳本

# 查看腳本原始碼（確認行為）
cat /usr/share/nmap/scripts/smb-os-discovery.nse | head -30
# 讀 description 和 categories 欄位最快速
```

---

## 常用腳本整理

```bash
# ── Web 相關 ──
nmap --script http-title -p 80,443 <IP>            # 頁面標題
nmap --script http-headers -p 80,443 <IP>          # HTTP 回應標頭
nmap --script http-methods -p 80,443 <IP>          # 允許的 HTTP 方法
nmap --script http-robots.txt -p 80 <IP>           # robots.txt 內容
nmap --script http-auth-finder -p 80,443 <IP>      # 偵測認證類型

# ── SMB / Windows 相關 ──
nmap --script smb-os-discovery -p 445 <IP>         # OS 版本與主機資訊
nmap --script smb-security-mode -p 445 <IP>        # SMB 安全設定
nmap --script smb-enum-shares -p 445 <IP>          # 列舉共享資料夾
nmap --script smb2-security-mode -p 445 <IP>       # SMBv2 安全模式

# ── SSH 相關 ──
nmap --script ssh-auth-methods -p 22 <IP>          # 支援的認證方法
nmap --script ssh-hostkey -p 22 <IP>               # SSH host key 資訊

# ── TLS / 憑證 ──
nmap --script ssl-cert -p 443 <IP>                 # TLS 憑證資訊
nmap --script ssl-enum-ciphers -p 443 <IP>         # 支援的加密套件
nmap --script tls-alpn -p 443 <IP>                 # TLS ALPN 協定

# ── DNS 相關 ──
nmap --script dns-zone-transfer -p 53 <IP>         # DNS Zone Transfer
nmap --script dns-brute --script-args dns-brute.domain=example.com -p 53 <IP>

# ── SNMP 相關 ──
nmap --script snmp-info -p 161 -sU <IP>            # SNMP 基本資訊
nmap --script snmp-sysdescr -p 161 -sU <IP>        # 系統描述
```

---

## NSE 輸出解讀

```text
NSE 輸出分三類：

1. 觀測性資料（最可靠）：
   - 憑證 CN/SAN 名稱
   - SMB OS 版本（系統自報）
   - SSH 支援的認證方法
   → 可直接記錄為觀測事實

2. 推測性資料（需謹慎）：
   - 疑似某配置（例如疑似允許匿名存取）
   - 技術指紋（疑似使用某框架版本）
   → 標記為「需進一步驗證」

3. 需二次驗證的發現（不可直接報告為漏洞）：
   - vuln 類腳本輸出
   - 「VULNERABLE」標記（多數是版本比對，非實際利用驗證）
   → 必須用其他方法確認再寫入報告

常見誤判：
  http-shellshock 顯示 VULNERABLE → 需要手動驗證 CGI 實際行為
  vuln 腳本通常用版本範圍比對，backport 補丁讓結果假陽性
```

---

## 決策流程

```
已知服務類型（來自 -sV 結果）
    ↓
選擇對應 NSE 腳本類別
  Web (80/443/8080) → http-title / http-headers / ssl-cert
  SMB (445)         → smb-os-discovery / smb-security-mode
  SSH (22)          → ssh-auth-methods / ssh-hostkey
  DNS (53)          → dns-zone-transfer
  SNMP (161/udp)    → snmp-info / snmp-sysdescr
    ↓
執行前：nmap --script-help <腳本名稱>
確認：這個腳本做什麼？風險等級？參數需求？
    ↓
執行腳本（在授權範圍內）
    ↓
結果分類
  觀測性 → 直接記錄
  推測性 → 標記需驗證
  vuln 發現 → 手動驗證後才能報告
```

---

## 速查表

```bash
# 基本 NSE
nmap -sC 192.168.1.1                                        # 預設腳本
nmap --script safe 192.168.1.1                              # 只跑 safe 類
nmap --script smb-os-discovery -p 445 192.168.1.1           # 指定腳本
nmap --script-help smb-os-discovery                         # 查腳本說明
nmap --script <name> --script-args key=val 192.168.1.1      # 傳參數

# 常用組合
nmap -sV -sC -p 22,80,443,445 192.168.1.1                  # 服務版本+預設腳本
nmap --script ssl-cert,ssl-enum-ciphers -p 443 192.168.1.1 # TLS 完整檢查
nmap --script "smb*" -p 445 192.168.1.1                    # 所有 smb 腳本
```

---

## 常見錯誤與排查

- 不看腳本說明就直接執行 → `--script-help` 是最低門檻，尤其 brute/intrusive 類。
- 把 `-sC` 當成安全無害的預設 → default 集包含主動互動腳本，某些環境仍會留日誌。
- 把 `vuln` 腳本輸出直接寫進最終報告 → 多數是版本比對，backport 導致假陽性很常見。
- 用單一腳本輸出取代協定層人工驗證 → NSE 是起點，不是終點。

---

## 關聯筆記

- [[20-Nmap服務與版本偵測|第 20 章 - Nmap 服務與版本偵測]]
- [[21-Nmap作業系統偵測|第 21 章 - Nmap 作業系統偵測]]
- [[23-Nmap輸出證據與自動化|第 23 章 - Nmap 輸出證據與自動化]]
- [[01-Volume-1-Information-Gathering-Index|Vol.1 - Information Gathering]]
